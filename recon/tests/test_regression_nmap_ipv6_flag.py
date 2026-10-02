"""Regression: nmap never added -6, so no IPv6 address was ever scanned.

nmap 7.93 given an IPv6 target without -6 prints "you have to use the -6
option", still exits 0, and lists the target status="skipped". The IP was
then "not scanned to completion" on every run (its NSE findings kept for
ever) and IPv6 services never got a version or an NSE script. An IPv4
command must stay byte-identical.

nmap is a fake that behaves like 7.93 about -6.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402

IP4 = "192.0.2.10"
IP6 = "2001:db8::10"
SETTINGS = {"NMAP_VERSION_DETECTION": True, "NMAP_SCRIPT_SCAN": True,
            "NMAP_TIMING_TEMPLATE": "T3", "NMAP_HOST_TIMEOUT": 300}


class _Proc:
    returncode = 0

    def __init__(self, stdout):
        self._stdout = stdout

    def communicate(self, timeout=None):
        return self._stdout, ""


def _nmap_793(cmd, **_kw):
    """An IPv6 target without -6 is skipped, exit 0, as nmap 7.93 does."""
    target = cmd[-1]
    out = Path(cmd[cmd.index("-oX") + 1])
    if ":" in target and "-6" not in cmd:
        out.write_text('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93">'
                       f'<target specification="{target}" status="skipped" reason="invalid"/>'
                       '</nmaprun>')
        return _Proc("WARNING: ... looks like an IPv6 target specification -- "
                     "you have to use the -6 option.\n")
    addrtype = "ipv6" if ":" in target else "ipv4"
    out.write_text('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93">'
                   '<host><status state="up" reason="syn-ack"/>'
                   f'<address addr="{target}" addrtype="{addrtype}"/>'
                   '<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
                   '<service name="https" product="nginx" version="1.25.0"/></port></ports>'
                   '</host></nmaprun>')
    return _Proc("")


class TestRegressionNmapIpv6Flag:
    def test_regression_nmap_ipv6_target_without_dash_6(self):
        cmd = nmap_scan.build_nmap_command(IP6, "443", "/tmp/o.xml", SETTINGS)
        assert cmd.count("-6") == 1
        assert cmd[-2:] == ["-6", IP6]

    def test_an_ipv4_command_is_byte_identical(self):
        cmd = nmap_scan.build_nmap_command(IP4, "22,443", "/tmp/o.xml", SETTINGS)
        assert cmd == ["nmap", "-sV", "--script", "vuln", "-oX", "/tmp/o.xml", "-p", "22,443",
                       "-T3", "--host-timeout", "300s", IP4]

    def test_an_ipv6_address_is_scanned_and_not_kept_as_unfinished(self, monkeypatch):
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
        monkeypatch.setattr(nmap_scan.subprocess, "Popen", _nmap_793)
        recon = {"port_scan": {"by_ip": {IP6: {"ip": IP6, "hostnames": [], "ports": [443]}},
                               "by_host": {}, "ip_to_hostnames": {}}}
        out = nmap_scan.run_nmap_scan(recon, settings={})
        assert not cb.coverage_report().degraded
        (entry,) = out["nmap_scan"]["by_host"].values()
        assert entry["ip"] == IP6
        assert [pd["product"] for pd in entry["port_details"]] == ["nginx"]
