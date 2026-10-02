"""Regression: a failed port scan silently deleted every nmap NSE finding.

When Naabu failed, timed out or raised, its isolated wrapper returned {}, so
port_scan was never set, nmap was skipped and nothing was recorded; the prune
then read "no nmap_nse finding this run" as "every one is gone". run_nmap_scan's
own "no port_scan data" return did the same. A port scan that ran and found no
open port is still a clean scan, and so is one that had no target at all or
was turned off by configuration.

Every scanner and Neo4j is a fake.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402

IP = "192.0.2.10"

# Everything around the port scan and nmap switched off, so run_ip_recon runs
# only the two phases under test.
IP_SETTINGS = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False, "SHODAN_ENABLED": False,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": False, "NMAP_ENABLED": True,
    "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False, "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "AI_SURFACE_RECON_ENABLED": False,
    "JS_RECON_ENABLED": False, "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROE_ENABLED": False,
}

PORT_SCAN = {"scan_metadata": {}, "by_host": {}, "all_ports": [80], "summary": {},
             "by_ip": {IP: {"ip": IP, "hostnames": [], "ports": [80], "port_details": []}},
             "ip_to_hostnames": {}}


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': [IP],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['port_scan'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", ["port_scan"])
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", False)
        yield rm


def _ip_run(rm, monkeypatch, port_scan, settings=None):
    nmap_calls = []

    def fake_nmap(recon_data, output_file=None, settings=None):
        nmap_calls.append(recon_data.get("port_scan"))
        return recon_data

    monkeypatch.setattr(rm, "run_port_scan_isolated", port_scan)
    monkeypatch.setattr(nmap_scan, "run_nmap_scan", fake_nmap)
    rm.run_ip_recon([IP], dict(IP_SETTINGS, **(settings or {})))
    return nmap_calls


def _boom(*_a, **_k):
    raise RuntimeError("naabu exploded")


class TestRegressionPortScanFailure:
    def test_regression_failed_port_scan_pruned_nse_findings(self, recon_main, monkeypatch):
        nmap_calls = _ip_run(recon_main, monkeypatch, _boom)
        assert nmap_calls == []
        report = cb.coverage_report()
        assert "nmap_nse" in report.degraded_sources
        assert any(g["source"] == "nmap_nse" and "no port scan data" in g["reason"]
                   for g in report.gaps)

    def test_a_timed_out_port_scan_keeps_nse_findings(self, recon_main, monkeypatch):
        # run_port_scan returns without a port_scan section on a timeout, so the
        # isolated wrapper hands back {}.
        _ip_run(recon_main, monkeypatch, lambda *a, **k: {})
        assert "nmap_nse" in cb.coverage_report().degraded_sources

    def test_the_prune_then_leaves_nmap_nse_alone(self, recon_main, monkeypatch):
        prunes = []

        class _Graph:
            def __call__(self, *a, **k):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def verify_connection(self):
                return True

            def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
                prunes.append(list(sources))

        _ip_run(recon_main, monkeypatch, _boom)
        monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(recon_main, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
        monkeypatch.setattr(recon_main, "_COVERAGE_WRITE_FAILED", False)
        recon_main._prune_recon_findings()
        assert prunes and all("nmap_nse" not in sources for sources in prunes)

    def test_a_healthy_port_scan_runs_nmap_and_degrades_nothing(self, recon_main, monkeypatch):
        nmap_calls = _ip_run(recon_main, monkeypatch, lambda *a, **k: dict(PORT_SCAN))
        assert len(nmap_calls) == 1
        assert not cb.coverage_report().degraded

    def test_port_scanning_turned_off_is_not_a_gap(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch, _boom, settings={"NAABU_ENABLED": False})
        assert not cb.coverage_report().degraded

    def test_nmap_turned_off_is_not_a_gap(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch, _boom, settings={"NMAP_ENABLED": False})
        assert not cb.coverage_report().degraded

    def test_a_port_scan_with_no_target_is_not_a_gap(self, recon_main):
        recon_main._note_nmap_without_port_data({"dns": {}}, dict(IP_SETTINGS))
        assert not cb.coverage_report().degraded

    def test_the_domain_pipeline_records_it_too(self, recon_main):
        body = inspect.getsource(recon_main.run_domain_recon)
        block = body[body.index("run_nmap_scan("):]
        block = block[:block.index("GROUP 3.6")]
        assert "_note_nmap_without_port_data(combined_result, _settings)" in block


class TestRunNmapScanWithoutPortData:
    def test_regression_nmap_without_port_scan_section_pruned_nse_findings(self, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
        out = nmap_scan.run_nmap_scan({}, settings={})
        assert "nmap_scan" not in out
        assert "nmap_nse" in cb.coverage_report().degraded_sources

    def test_a_port_scan_that_found_nothing_open_is_a_clean_scan(self, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
        nmap_scan.run_nmap_scan({"port_scan": dict(PORT_SCAN, by_ip={})}, settings={})
        assert not cb.coverage_report().degraded
