"""nmap coverage, per-IP keys and per-IP service attribution (recon/main_recon_modules/nmap_scan.py).

C2 - an IP nmap did not scan to completion (killed, crashed, host timeout,
     unreadable or missing XML) keeps its previous nmap_nse findings: it is a
     skipped host in the coverage report. A module-level failure keeps every
     nmap_nse finding.
C3 - every services_detected / nse_vulns entry carries the IP it came from.
C4 - two IPs sharing a primary hostname never merge into one by_host entry.

nmap itself is a fake that writes scripted XML to the command's -oX path.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402

IP_A = "192.0.2.10"
IP_B = "192.0.2.11"


def _port_xml(port, product="", version="", script=None):
    svc = f'<service name="http" product="{product}" version="{version}"/>' if product else ""
    scr = f'<script id="{script[0]}" output="{script[1]}"/>' if script else ""
    return (f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
            f'{svc}{scr}</port>')


def _xml(ip, ports=(), *, timedout=False, status="up", host=True):
    if not host:
        body = f'<target specification="{ip}" status="skipped" reason="invalid"/>'
    else:
        t = ' timedout="true"' if timedout else ""
        port_block = f"<ports>{''.join(ports)}</ports>" if not timedout else ""
        body = (f'<host starttime="1" endtime="2"{t}><status state="{status}" reason="syn-ack"/>'
                f'<address addr="{ip}" addrtype="ipv4"/>{port_block}</host>')
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<nmaprun scanner="nmap" version="7.93">{body}</nmaprun>')


class _Proc:
    def __init__(self, spec):
        self.spec = spec
        self.returncode = spec.get("rc", 0)

    def communicate(self, timeout=None):
        if self.spec.get("hang"):
            raise subprocess.TimeoutExpired("nmap", timeout)
        return self.spec.get("stdout", ""), self.spec.get("stderr", "")

    def kill(self):
        pass

    def wait(self, timeout=None):
        return self.returncode


class _FakeNmap:
    """One scripted nmap process per target IP (the command's last argument)."""

    def __init__(self, plan):
        self.plan = plan
        self.commands = []

    def __call__(self, cmd, **_kw):
        self.commands.append(cmd)
        spec = self.plan[cmd[-1]]
        if spec.get("xml") is not None:
            Path(cmd[cmd.index("-oX") + 1]).write_text(spec["xml"])
        return _Proc(spec)


def _recon(ip_ports, hostnames=None, by_host=None):
    hostnames = hostnames or {}
    by_ip = {ip: {"ip": ip, "hostnames": list(hostnames.get(ip, [])), "ports": list(ports)}
             for ip, ports in ip_ports.items()}
    return {"port_scan": {"by_ip": by_ip, "by_host": by_host or {},
                          "ip_to_hostnames": {ip: list(h) for ip, h in hostnames.items()}}}


def _run(monkeypatch, recon, plan):
    fake = _FakeNmap(plan)
    monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
    monkeypatch.setattr(nmap_scan.subprocess, "Popen", fake)
    out = nmap_scan.run_nmap_scan(recon, settings={"NMAP_PARALLELISM": 2})
    return out, fake


HEALTHY_A = {"xml": _xml(IP_A, [_port_xml(80, "nginx", "1.25.0",
                                          ("http-vuln-x", "VULNERABLE: x CVE-2020-0001"))])}
HEALTHY_B = {"xml": _xml(IP_B, [_port_xml(80, "Apache httpd", "2.4.49")])}


class TestPerIpCoverage:
    def test_a_healthy_scan_degrades_nothing(self, monkeypatch):
        out, fake = _run(monkeypatch, _recon({IP_A: [80], IP_B: [80]}),
                         {IP_A: HEALTHY_A, IP_B: HEALTHY_B})
        assert len(fake.commands) == 2
        report = cb.coverage_report()
        assert not report.degraded
        nmap = out["nmap_scan"]
        assert "unreachable_hosts" not in nmap and "degraded" not in nmap
        assert [v["script_id"] for v in nmap["nse_vulns"]] == ["http-vuln-x"]

    def test_a_host_timeout_keeps_that_ips_findings(self, monkeypatch):
        timed_out = {"xml": _xml(IP_B, timedout=True),
                     "stdout": f"Skipping host {IP_B} due to host timeout\n"}
        out, _ = _run(monkeypatch, _recon({IP_A: [80], IP_B: [80]}),
                      {IP_A: HEALTHY_A, IP_B: timed_out})
        report = cb.coverage_report()
        assert report.skipped_hostnames() == (IP_B,)
        assert "nmap_nse" not in report.degraded_sources  # the other IP was re-checked
        assert out["nmap_scan"]["unreachable_hosts"] == [IP_B]

    def test_the_timeout_marker_alone_is_enough(self, monkeypatch):
        # Older nmap omits the timed-out host from the XML; stdout still says so.
        spec = {"xml": _xml(IP_B, [_port_xml(80, "x", "1")]),
                "stdout": f"Skipping host {IP_B} due to host timeout\n"}
        _run(monkeypatch, _recon({IP_B: [80]}), {IP_B: spec})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_a_killed_scan_keeps_that_ips_findings(self, monkeypatch):
        _run(monkeypatch, _recon({IP_A: [80], IP_B: [80]}),
             {IP_A: HEALTHY_A, IP_B: {"hang": True}})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_a_crash_without_xml_keeps_that_ips_findings(self, monkeypatch):
        _run(monkeypatch, _recon({IP_A: [80], IP_B: [80]}),
             {IP_A: HEALTHY_A, IP_B: {"rc": 1, "stderr": "boom"}})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_unreadable_xml_keeps_that_ips_findings(self, monkeypatch):
        _run(monkeypatch, _recon({IP_A: [80], IP_B: [80]}),
             {IP_A: HEALTHY_A, IP_B: {"xml": "<nmaprun><host>"}})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_an_ip_absent_from_the_xml_keeps_its_findings(self, monkeypatch):
        # nmap exits 0 and writes no <host> when it cannot route to a target.
        _run(monkeypatch, _recon({IP_B: [80]}), {IP_B: {"xml": _xml(IP_B, host=False)}})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_a_down_host_keeps_its_findings(self, monkeypatch):
        _run(monkeypatch, _recon({IP_B: [80]}),
             {IP_B: {"xml": _xml(IP_B, [_port_xml(80)], status="down")}})
        assert cb.coverage_report().skipped_hostnames() == (IP_B,)

    def test_a_host_with_every_port_closed_is_a_clean_scan(self, monkeypatch):
        closed = ('<port protocol="tcp" portid="80"><state state="closed" reason="reset"/>'
                  '</port>')
        _run(monkeypatch, _recon({IP_B: [80]}), {IP_B: {"xml": _xml(IP_B, [closed])}})
        assert not cb.coverage_report().degraded

    def test_the_skipped_ip_reaches_the_prune_as_a_kept_host(self, monkeypatch):
        from graph_db.mixins.base_mixin import keep_host_patterns
        import re
        _run(monkeypatch, _recon({IP_B: [80]}), {IP_B: {"hang": True}})
        (pattern,) = keep_host_patterns(cb.coverage_report().skipped_hostnames())
        assert re.match(pattern, IP_B)          # nmap_nse stores the bare ip_address
        assert not re.match(pattern, IP_A)


class TestModuleFailure:
    def test_a_missing_binary_keeps_every_nse_finding(self, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: False)
        nmap_scan.run_nmap_scan(_recon({IP_A: [80]}), settings={})
        assert "nmap_nse" in cb.coverage_report().degraded_sources

    def test_an_exception_mid_scan_keeps_every_nse_finding(self, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)

        def _boom(*a, **k):
            raise RuntimeError("executor broke")

        monkeypatch.setattr(nmap_scan, "ThreadPoolExecutor", _boom)
        out = nmap_scan.run_nmap_scan(_recon({IP_A: [80]}), settings={})
        assert "nmap_scan" not in out
        assert "nmap_nse" in cb.coverage_report().degraded_sources

    def test_disabled_nmap_records_nothing(self, monkeypatch):
        nmap_scan.run_nmap_scan(_recon({IP_A: [80]}), settings={"NMAP_ENABLED": False})
        assert not cb.coverage_report().degraded


class TestSharedHostnameNeverMerges:
    """C4: by_host was keyed by the primary hostname, so two IPs behind one name merged."""

    def _shared(self):
        return _recon(
            {IP_A: [80], IP_B: [80, 443]},
            hostnames={IP_A: ["shared.example.com"], IP_B: ["shared.example.com"]},
            by_host={"shared.example.com": {"host": "shared.example.com", "ip": IP_B,
                                            "ports": [80, 443], "port_details": []}},
        )

    def test_each_ip_keeps_its_own_entry_and_ports(self, monkeypatch):
        plan = {IP_A: {"xml": _xml(IP_A, [_port_xml(80, "nginx", "1.25.0")])},
                IP_B: {"xml": _xml(IP_B, [_port_xml(80, "Apache httpd", "2.4.49"),
                                          _port_xml(443, "Apache httpd", "2.4.49")])}}
        out, _ = _run(monkeypatch, self._shared(), plan)
        by_host = out["nmap_scan"]["by_host"]
        assert len(by_host) == 2
        by_ip = {entry["ip"]: entry for entry in by_host.values()}
        assert [pd["product"] for pd in by_ip[IP_A]["port_details"]] == ["nginx"]
        assert [pd["port"] for pd in by_ip[IP_B]["port_details"]] == [80, 443]
        assert {pd["product"] for pd in by_ip[IP_B]["port_details"]} == {"Apache httpd"}

    def test_the_hostname_key_stays_with_the_ip_the_port_scan_maps_it_to(self, monkeypatch):
        plan = {IP_A: {"xml": _xml(IP_A, [_port_xml(80, "nginx", "1")])},
                IP_B: {"xml": _xml(IP_B, [_port_xml(80, "Apache httpd", "2")])}}
        out, _ = _run(monkeypatch, self._shared(), plan)
        by_host = out["nmap_scan"]["by_host"]
        assert by_host["shared.example.com"]["ip"] == IP_B
        assert by_host[IP_A]["ip"] == IP_A

    def test_unique_hostnames_keep_todays_keys(self, monkeypatch):
        recon = _recon({IP_A: [80], IP_B: [80]},
                       hostnames={IP_A: ["a.example.com"], IP_B: ["b.example.com"]})
        out, _ = _run(monkeypatch, recon, {IP_A: HEALTHY_A, IP_B: HEALTHY_B})
        assert set(out["nmap_scan"]["by_host"]) == {"a.example.com", "b.example.com"}
        assert out["nmap_scan"]["summary"]["hosts_scanned"] == 2


class TestEntriesCarryTheirIp:
    """C3: the graph writer needs the IP of every service and NSE finding."""

    def test_services_and_nse_vulns_carry_the_ip(self, tmp_path):
        path = tmp_path / "o.xml"
        path.write_text(HEALTHY_A["xml"])
        parsed = nmap_scan.parse_nmap_xml(str(path), {IP_A: ["a.example.com"]})
        (svc,) = parsed["services_detected"]
        assert svc["ip"] == IP_A and svc["host"] == "a.example.com"
        (vuln,) = parsed["nse_vulns"]
        assert vuln["ip"] == IP_A and vuln["host"] == IP_A


class TestThePipelineWrapsNmap:
    @pytest.fixture
    def recon_main(self):
        stub = {
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
            'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        }
        with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
            yield rm

    def test_a_crashed_nmap_phase_keeps_its_nse_findings(self, recon_main):
        assert recon_main._PHASE_FINDING_SOURCES["nmap"] == ("nmap_nse",)
        recon_main._note_phase_error("nmap")
        assert "nmap_nse" in cb.coverage_report().degraded_sources

    @pytest.mark.parametrize("func", ["run_ip_recon", "run_domain_recon"])
    def test_both_callers_record_a_crashed_nmap_phase(self, recon_main, func):
        import inspect
        body = inspect.getsource(getattr(recon_main, func))
        block = body[body.index("run_nmap_scan("):]
        block = block[:block.index("GROUP 3.6")]
        assert '_note_phase_error("nmap")' in block
        assert 'phase_errors", {})["nmap"]' in block
