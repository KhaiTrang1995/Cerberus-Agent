"""Regression: a timed-out Nuclei template update left the updater running.

The 600 s timeout only killed the docker CLI; the `nuclei -ut` container kept
rewriting the nuclei-templates volume while the scan read it, so templates
loaded half-written, failed, and their findings were pruned. The updater now
runs under a unique name and is killed on timeout, and since a killed update
can still leave the volume half-written, Nuclei is skipped for the run (its
findings kept by the caller) instead of scanning with it.

`docker` is a fake.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import docker_helpers  # noqa: E402


def _docker(monkeypatch, *, volume_exists=True, update_times_out=False):
    commands = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        if cmd[:3] == ["docker", "volume", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0 if volume_exists else 1, "", "")
        if cmd[:3] == ["docker", "volume", "create"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "alpine" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "5", "")
        if "-ut" in cmd:
            if update_times_out:
                raise subprocess.TimeoutExpired(cmd, 600)
            return subprocess.CompletedProcess(cmd, 0, "already up to date", "")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(docker_helpers.subprocess, "run", fake_run)
    return commands


def _updater_name(commands):
    (update,) = [c for c in commands if "-ut" in c]
    return update[update.index("--name") + 1]


class TestRegressionTemplateUpdateTimeout:
    def test_regression_template_update_timeout_left_updater_running(self, monkeypatch):
        commands = _docker(monkeypatch, update_times_out=True)
        ok = docker_helpers.ensure_templates_volume("projectdiscovery/nuclei:latest",
                                                    auto_update=True)
        assert ok is False
        name = _updater_name(commands)
        assert name.startswith("redamon-nuclei-update-")
        assert ["docker", "kill", name] in commands

    def test_a_first_download_that_times_out_is_stopped_too(self, monkeypatch):
        commands = _docker(monkeypatch, volume_exists=False, update_times_out=True)
        assert docker_helpers.ensure_templates_volume("img", auto_update=False) is False
        assert ["docker", "kill", _updater_name(commands)] in commands

    def test_each_update_has_its_own_name(self, monkeypatch):
        first = _docker(monkeypatch)
        docker_helpers.ensure_templates_volume("img", auto_update=True)
        second = _docker(monkeypatch)
        docker_helpers.ensure_templates_volume("img", auto_update=True)
        assert _updater_name(first) != _updater_name(second)

    def test_a_healthy_update_kills_nothing_and_scans(self, monkeypatch):
        commands = _docker(monkeypatch)
        assert docker_helpers.ensure_templates_volume("img", auto_update=True) is True
        assert not any(c[:2] == ["docker", "kill"] for c in commands)
