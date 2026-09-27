"""Phase 5: the Nuclei wall-clock cap + -mhe + uuid names, and the httpx budget.

A 21.5h field run sat at 31% because process.wait() had no timeout. The cap is
a watchdog that docker-kills the named container and keeps the partial JSONL.
"""
from __future__ import annotations

import threading
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.nuclei_helpers import build_nuclei_command
from recon.main_recon_modules import vuln_scan


def _cmd(**kw):
    return build_nuclei_command(
        targets_file="/tmp/redamon/t.txt", output_file="/tmp/redamon/o.jsonl",
        docker_image="projectdiscovery/nuclei:latest", **kw)


class TestBuildNucleiCommand:
    def test_container_name_becomes_docker_run_name(self):
        cmd = _cmd(container_name="redamon-nuclei-detection-abc123")
        assert "--name" in cmd
        assert cmd[cmd.index("--name") + 1] == "redamon-nuclei-detection-abc123"
        # The name flag sits on `docker run`, before the image.
        assert cmd.index("--name") < cmd.index("projectdiscovery/nuclei:latest")

    def test_no_name_means_no_flag(self):
        assert "--name" not in _cmd()

    def test_max_host_error_becomes_mhe(self):
        cmd = _cmd(max_host_error=30)
        assert "-mhe" in cmd and cmd[cmd.index("-mhe") + 1] == "30"

    def test_mhe_zero_is_omitted(self):
        assert "-mhe" not in _cmd(max_host_error=0)

    def test_two_passes_in_the_same_second_get_different_names(self):
        import uuid
        a = f"redamon-nuclei-detection-{uuid.uuid4().hex[:12]}"
        b = f"redamon-nuclei-dast-{uuid.uuid4().hex[:12]}"
        assert a != b


class _FakeProc:
    """A Popen whose stdout blocks until the watchdog 'kills' it."""

    def __init__(self, lines, killed_event):
        self._lines = iter(lines)
        self._killed = killed_event
        self.returncode = 0

    @property
    def stdout(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._lines)
        except StopIteration:
            # After the scripted lines, block until the watchdog fires.
            if self._killed.wait(timeout=5):
                self.returncode = 137
                raise StopIteration
            raise StopIteration

    def wait(self):
        return self.returncode


class TestRuntimeWatchdog:
    def test_the_cap_kills_the_container_and_records_truncation(self, tmp_path, monkeypatch):
        killed = threading.Event()
        out = tmp_path / "o.jsonl"
        out.write_text('{"template-id":"x","matched-at":"https://a.test","info":{"severity":"low"}}\n')

        def fake_kill(name):
            assert name == "redamon-nuclei-detection-xyz"
            killed.set()

        monkeypatch.setattr(vuln_scan, "_nuclei_kill_container", fake_kill)
        proc = _FakeProc(["[INF] running"], killed)
        monkeypatch.setattr(vuln_scan.subprocess, "Popen", lambda *a, **k: proc)

        findings, fps, dur, rc = vuln_scan._execute_nuclei_pass(
            ["docker", "run"], str(out), label="DETECTION",
            runtime_cap=0.2, container_name="redamon-nuclei-detection-xyz")

        assert killed.is_set()
        # The partial JSONL on disk is still parsed.
        assert len(findings) == 1
        report = cb.coverage_report()
        assert report.nuclei_truncated is True
        assert "nuclei" in report.degraded_sources

    def test_a_pass_that_finishes_early_does_not_truncate(self, tmp_path, monkeypatch):
        killed = threading.Event()
        out = tmp_path / "o.jsonl"
        out.write_text("")
        monkeypatch.setattr(vuln_scan, "_nuclei_kill_container",
                            lambda name: killed.set())

        class _Quick:
            returncode = 0
            stdout = iter(["[INF] done"])
            def wait(self): return 0
        monkeypatch.setattr(vuln_scan.subprocess, "Popen", lambda *a, **k: _Quick())

        vuln_scan._execute_nuclei_pass(["docker", "run"], str(out), label="DETECTION",
                                       runtime_cap=3600, container_name="redamon-nuclei-x")
        assert not killed.is_set()
        assert cb.coverage_report().nuclei_truncated is False


class TestStatsWatchdog:
    def test_warns_once_when_errors_dominate_with_no_matches(self, monkeypatch):
        t = {"v": 0.0}
        monkeypatch.setattr(vuln_scan.time, "monotonic", lambda: t["v"])
        state = {"since": None, "warned": False}
        line = '{"requests":"1000","errors":"900","matched":"0","duration":"0:05:00"}'
        printed = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a))))
        vuln_scan._nuclei_watch_stats(line, "DETECTION", state)   # first bad sample
        t["v"] = 601                                               # 10 min later
        vuln_scan._nuclei_watch_stats(line, "DETECTION", state)
        vuln_scan._nuclei_watch_stats(line, "DETECTION", state)   # would warn again
        warns = [p for p in printed if "erroring" in p]
        assert len(warns) == 1 and "NUCLEI_MAX_RUNTIME" in warns[0]

    def test_a_healthy_scan_never_warns(self, monkeypatch):
        t = {"v": 0.0}
        monkeypatch.setattr(vuln_scan.time, "monotonic", lambda: t["v"])
        state = {"since": None, "warned": False}
        printed = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a))))
        vuln_scan._nuclei_watch_stats('{"requests":"1000","errors":"10","matched":"3"}',
                                      "DETECTION", state)
        t["v"] = 700
        vuln_scan._nuclei_watch_stats('{"requests":"2000","errors":"20","matched":"3"}',
                                      "DETECTION", state)
        assert [p for p in printed if "erroring" in p] == []

    def test_a_transient_error_burst_that_clears_resets(self, monkeypatch):
        t = {"v": 0.0}
        monkeypatch.setattr(vuln_scan.time, "monotonic", lambda: t["v"])
        state = {"since": None, "warned": False}
        vuln_scan._nuclei_watch_stats('{"requests":"1000","errors":"900","matched":"0"}', "D", state)
        assert state["since"] == 0.0
        t["v"] = 100
        vuln_scan._nuclei_watch_stats('{"requests":"2000","errors":"901","matched":"5"}', "D", state)
        assert state["since"] is None  # matches appeared, the streak reset


class TestHttpxBudget:
    """ceil(urls/threads) * (timeout*(retries+1)) + 60 (after hakrawler_job_budget)."""

    def test_the_formula(self):
        from recon.main_recon_modules.http_probe import httpx_budget
        # 1,000 URLs, 50 threads, 10s timeout, 2 retries: 20 waves * 30s + 60.
        assert httpx_budget(1000, 50, 10, 2) == 20 * 30 + 60

    def test_far_below_the_old_formula(self):
        from recon.main_recon_modules.http_probe import httpx_budget
        old = 1000 * 10  # len(urls) * HTTPX_TIMEOUT, ~2.8h: it never fired
        assert httpx_budget(1000, 50, 10, 2) < old / 10

    def test_rounds_waves_up_and_guards_zero_threads(self):
        from recon.main_recon_modules.http_probe import httpx_budget
        assert httpx_budget(51, 50, 10, 0) == 2 * 10 + 60
        assert httpx_budget(5, 0, 10, 0) == 5 * 10 + 60
        assert httpx_budget(0, 50, 10, 2) == 60
