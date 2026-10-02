"""Regression: a TLS finding on a bare IPv6 address got an unbracketed URL.

run_tls_data_checks built f"https://{host}:{port}". tlsx submits the IP itself
when the IP has no hostname, so an IPv6 target became
"https://2001:db8::1:8443": the graph writer read its host as "2001", matched
no IP, BaseURL, Subdomain or Domain, and the finding was left unlinked. The
host is now bracketed for the URL authority (RFC 3986); IPv4 and hostname URLs
are byte-identical.

Fixture data uses example.test, RFC 5737 and RFC 3849 addresses only.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from recon.helpers.security_checks import run_tls_data_checks  # noqa: E402

_V6 = "2001:db8::1"


def _tlsx(host, ip, port=8443):
    return {"tlsx": {"by_target": {f"{ip}:{port}": {
        "host": host, "scanned_ip": ip, "ip": ip, "port": port, "probe_status": True,
        "subject_cn": "self", "subject_dn": "CN=self", "issuer_dn": "CN=self",
        "san": [], "self_signed": True, "expired": False, "mismatched": False,
        "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
    }}}}


def _self_signed(recon):
    [finding] = [f for f in run_tls_data_checks(recon, {}) if f["type"] == "tls_self_signed"]
    return finding


def test_regression_tls_ipv6_url_unbracketed():
    finding = _self_signed(_tlsx(_V6, _V6))
    assert finding["url"] == f"https://[{_V6}]:8443"
    assert finding["matched_ip"] == _V6 and "hostname" not in finding

    # ...and the writer now reaches the IP node instead of a "2001" Domain.
    from graph_db.mixins.recon.vuln_mixin import VulnMixin

    calls = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            calls.append((query, params))
            res = MagicMock()
            res.single.return_value = {"matched": 1, "linked": 0}
            return res

    writer = VulnMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = _Session()
    stats = writer.update_graph_from_vuln_scan(
        {"domain": "example.test", "vuln_scan": {"security_checks": {"findings": [finding]}}},
        "u1", "p1")
    assert stats["errors"] == []
    links = [p for q, p in calls if "HAS_VULNERABILITY" in q]
    assert [(p.get("address"), p.get("hostname")) for p in links] == [(_V6, None)]


def test_ipv4_and_hostname_urls_are_byte_identical():
    assert _self_signed(_tlsx("192.0.2.10", "192.0.2.10"))["url"] == "https://192.0.2.10:8443"
    assert (_self_signed(_tlsx("mail.example.test", "192.0.2.10", 993))["url"]
            == "https://mail.example.test:993")
