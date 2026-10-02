"""Regression: an IP nmap did not finish kept the findings of EVERY source.

nmap recorded an unfinished IP (host timeout, kill, unreadable XML) as a
skipped host, and the run-level prune passed every skipped host as keep_hosts
for every source. So after `--host-timeout` on one IP, Nuclei re-checked that
IP but its stale findings there (matched_ip / url on the IP) survived the
prune, run after run. Only nmap_nse findings may be kept for such an IP; a
host that was unreachable for every tool still keeps every source's findings.

nmap and Neo4j are fakes; these pin what the prune is asked to do.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402

IP_A = "192.0.2.10"
IP_B = "203.0.113.7"
DEAD = "dead.example.com"


def _xml(ip, *, timedout=False):
    port = ('<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
            '<service name="http" product="nginx" version="1.25.0"/></port></ports>')
    t = ' timedout="true"' if timedout else ""
    return ('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93">'
            f'<host{t}><status state="up" reason="syn-ack"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>{"" if timedout else port}</host></nmaprun>')


class _Proc:
    def __init__(self, stdout):
        self.returncode = 0
        self._stdout = stdout

    def communicate(self, timeout=None):
        return self._stdout, ""


def _fake_nmap(cmd, **_kw):
    ip = cmd[-1]
    timed_out = ip == IP_B
    Path(cmd[cmd.index("-oX") + 1]).write_text(_xml(ip, timedout=timed_out))
    return _Proc(f"Skipping host {ip} due to host timeout\n" if timed_out else "")


def _run_nmap(monkeypatch):
    monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
    monkeypatch.setattr(nmap_scan.subprocess, "Popen", _fake_nmap)
    recon = {"port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": [80]}
                                     for ip in (IP_A, IP_B)},
                           "by_host": {}, "ip_to_hostnames": {}}}
    return nmap_scan.run_nmap_scan(recon, settings={"NMAP_PARALLELISM": 2})


@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm


class _Graph:
    def __init__(self):
        self.prunes = []
        self.coverage = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
        self.prunes.append({"sources": list(sources), "keep_hosts": tuple(keep_hosts)})
        return {"pruned": 0, "stale": 0, "revived": 0}

    def update_graph_coverage(self, user_id, project_id, domain, record):
        self.coverage.append(record)
        return 1

    def keep_for(self, source):
        (prune,) = [p for p in self.prunes if source in p["sources"]]
        return prune["keep_hosts"]


@pytest.fixture
def graph(monkeypatch):
    fake = _Graph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


class TestRegressionNmapCoverageScope:
    def test_regression_nmap_unfinished_ip_kept_nuclei_findings(self, recon_main, graph,
                                                                monkeypatch):
        _run_nmap(monkeypatch)
        recon_main._prune_recon_findings()
        assert IP_B in graph.keep_for("nmap_nse")
        # Nuclei (and every other source) re-checked IP_B: its stale findings go.
        for source in set(RECON_FINDING_SOURCES) - {"nmap_nse"}:
            assert IP_B not in graph.keep_for(source), source
        pruned = [s for p in graph.prunes for s in p["sources"]]
        assert sorted(pruned) == sorted(RECON_FINDING_SOURCES)  # each exactly once

    def test_a_host_unreachable_for_every_tool_still_keeps_every_source(self, recon_main, graph,
                                                                         monkeypatch):
        cb.note_degraded("security_checks", hosts=[f"{DEAD}:443"], host_source="security_check")
        _run_nmap(monkeypatch)
        recon_main._prune_recon_findings()
        for source in RECON_FINDING_SOURCES:
            assert DEAD in graph.keep_for(source), source

    def test_an_ip_unreachable_for_every_tool_and_unfinished_by_nmap_stays_global(self):
        cb.note_degraded("nmap", hosts=[IP_B], host_source="nmap_nse", source_only_hosts=True)
        cb.note_degraded("security_checks", hosts=[IP_B], host_source="security_check")
        report = cb.coverage_report()
        assert report.source_hosts == ()
        assert report.keep_hostnames("nuclei") == (IP_B,)

    def test_an_unreachable_ip_port_still_keeps_every_source_on_that_ip(self):
        # HostHealth keys carry the port, nmap's do not: the hostname decides.
        cb.note_degraded("nmap", hosts=[IP_B], host_source="nmap_nse", source_only_hosts=True)
        cb.note_degraded("security_checks", hosts=[f"{IP_B}:443"], host_source="security_check")
        report = cb.coverage_report()
        assert report.keep_hostnames("nuclei") == (IP_B,)
        assert report.keep_hostnames("nmap_nse") == (IP_B,)

    def test_the_coverage_record_still_lists_the_ip(self, recon_main, graph, monkeypatch):
        _run_nmap(monkeypatch)
        assert recon_main._write_coverage_record("example.com") is True
        (record,) = graph.coverage
        assert record["skipped_hosts"] == [IP_B]
        assert '"source":"nmap_nse"' in record["gaps_json"]
        assert "unreachable host(s) skipped" in record["gaps_json"]

    def test_partial_recon_still_sees_the_unreachable_ip(self, monkeypatch):
        out = _run_nmap(monkeypatch)
        assert out["nmap_scan"]["unreachable_hosts"] == [IP_B]

    def test_a_clean_nmap_run_is_still_one_prune_call(self, recon_main, graph, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)

        def healthy(cmd, **_kw):
            Path(cmd[cmd.index("-oX") + 1]).write_text(_xml(cmd[-1]))
            return _Proc("")

        monkeypatch.setattr(nmap_scan.subprocess, "Popen", healthy)
        nmap_scan.run_nmap_scan(
            {"port_scan": {"by_ip": {IP_A: {"ip": IP_A, "hostnames": [], "ports": [80]}},
                           "by_host": {}, "ip_to_hostnames": {}}},
            settings={})
        recon_main._prune_recon_findings()
        assert graph.prunes == [{"sources": list(RECON_FINDING_SOURCES), "keep_hosts": ()}]
