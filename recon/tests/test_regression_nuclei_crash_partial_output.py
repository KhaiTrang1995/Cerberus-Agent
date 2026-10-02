"""Regression: a Nuclei crash that had written some output counted as a full run.

The gate was `returncode != 0 and not parsed_lines`, so a container killed
(OOM, 137) or failing (1) after writing 3 of 50 findings was a complete scan,
and the prune deleted the 47 findings it never reached. Nuclei exits 0 with or
without matches (no flag the pass uses changes that), so any other exit not
caused by the runtime cap is a cut run. The findings it did write are still
returned for ingest.

The nuclei container is a fake process.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402


def _line(n):
    return ('{"template-id":"tpl-%d","matched-at":"https://a.example/%d",'
            '"host":"https://a.example","info":{"name":"x","severity":"low"}}\n' % (n, n))


class _Proc:
    def __init__(self, rc):
        self.returncode = rc
        self.stdout = iter(["[INF] Templates loaded for current scan: 50\n"])

    def wait(self):
        return self.returncode


def _pass(monkeypatch, tmp_path, rc, lines):
    out = tmp_path / "nuclei_detection.jsonl"
    out.write_text("".join(lines))
    monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: _Proc(rc))
    return vs._execute_nuclei_pass(["docker", "run"], str(out), label="DETECTION")


class TestRegressionNucleiCrashPartialOutput:
    def test_regression_nuclei_oom_after_partial_output_pruned_the_rest(self, monkeypatch,
                                                                        tmp_path):
        findings, _, _, rc = _pass(monkeypatch, tmp_path, 137, [_line(n) for n in range(3)])
        assert rc == 137
        assert len(findings) == 3  # what it wrote is still ingested
        report = cb.coverage_report()
        assert {"nuclei", "vuln_scan"} <= report.degraded_sources
        assert report.nuclei_truncated is False  # a crash, not the runtime cap

    @pytest.mark.parametrize("rc", [1, 2, 125, 139])
    def test_any_failing_exit_with_output_is_a_cut_run(self, monkeypatch, tmp_path, rc):
        _pass(monkeypatch, tmp_path, rc, [_line(0)])
        assert "nuclei" in cb.coverage_report().degraded_sources

    def test_a_clean_exit_with_findings_is_a_clean_scan(self, monkeypatch, tmp_path):
        findings, _, _, _ = _pass(monkeypatch, tmp_path, 0, [_line(n) for n in range(3)])
        assert len(findings) == 3
        assert not cb.coverage_report().degraded

    def test_a_clean_exit_without_findings_is_a_clean_scan(self, monkeypatch, tmp_path):
        _pass(monkeypatch, tmp_path, 0, [])
        assert not cb.coverage_report().degraded
