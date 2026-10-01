"""tlsx: no false "hostname mismatch" on an IP shared by several names.

tlsx dials ONE name per IP by default (TLSX_MAX_HOSTNAMES_PER_IP = 1), the
alphabetically first. On a shared IP that pick is arbitrary: an IMAPS/SMTPS
service serves the one cert for the name clients use (mail.<root>), so the cert
"did not name" the alphabetically-first sibling and a medium
tls_hostname_mismatch was raised for a host nobody connects to that way.

A cert naming ANOTHER hostname of the same IP is now not a mismatch. A cert
naming none of the IP's hostnames still is, and IP mode is unchanged.

The second half pins the Certificate node: one cert observed on several
targets used to carry whichever target's verdict tlsx printed last.

Fixture names are under example.test only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import tls_scan  # noqa: E402

# Must pass is_non_routable_ip: the TEST-NET ranges are dropped as targets.
_IP = "192.88.98.10"


def _combined(hostnames, ip=_IP, ports=(993,)):
    return {"port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": list(hostnames),
                                         "ports": list(ports)}}},
            "metadata": {}}


def _row(host, cn, san, *, ip=_IP, tlsx_mismatched=None, fp="AABBCC"):
    row = {
        "host": host, "ip": ip, "port": "993", "probe_status": True,
        "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
        "subject_cn": cn, "subject_dn": f"CN={cn}", "subject_an": san,
        "issuer_cn": "Test CA", "issuer_dn": "CN=Test CA",
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2099-01-01T00:00:00Z",
        "fingerprint_hash": {"sha256": fp},
    }
    if tlsx_mismatched is not None:
        row["mismatched"] = tlsx_mismatched
    return row


def _run(combined, rows):
    """Run the real phase with the docker call mocked; return (combined, argv)."""
    proc = MagicMock()
    proc.communicate.return_value = ("\n".join(json.dumps(r) for r in rows), "")
    proc.returncode = 0
    with patch.object(tls_scan.subprocess, "Popen", return_value=proc) as popen:
        out = tls_scan.run_tlsx_enrichment(combined, {})
    return out, popen.call_args[0][0]


def _mismatch_findings(combined):
    from recon.helpers.security_checks import run_tls_data_checks
    return [f for f in run_tls_data_checks(combined, {"tls_hostname_mismatch": True})
            if f["type"] == "tls_hostname_mismatch"]


# --------------------------------------------------------------------------- #
# The bug path
# --------------------------------------------------------------------------- #
def test_cert_for_a_sibling_name_on_the_same_ip_is_not_a_mismatch():
    combined = _combined(["alpha.example.test", "mail.example.test"])
    # The SNI pick stays deterministic: the alphabetically first name.
    lines, _ = tls_scan._build_tlsx_targets(combined, {})
    assert lines == ["alpha.example.test:993"]

    out, _ = _run(combined, [_row("alpha.example.test", "mail.example.test",
                                  ["mail.example.test"], tlsx_mismatched=True)])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["host"] == "alpha.example.test"
    assert entry["mismatched"] is False
    assert out["tlsx"]["summary"]["mismatched"] == 0
    assert _mismatch_findings(out) == []


def test_wildcard_cert_covering_a_sibling_is_not_a_mismatch():
    combined = _combined(["alpha.example.test", "imap.mail.example.test"])
    out, _ = _run(combined, [_row("alpha.example.test", "*.mail.example.test",
                                  ["*.mail.example.test"])])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is False


# --------------------------------------------------------------------------- #
# Still reported / unchanged
# --------------------------------------------------------------------------- #
def test_cert_naming_none_of_the_ips_hostnames_is_still_a_mismatch():
    combined = _combined(["alpha.example.test", "mail.example.test"])
    out, _ = _run(combined, [_row("alpha.example.test", "other.example.test",
                                  ["other.example.test"])])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is True
    findings = _mismatch_findings(out)
    assert len(findings) == 1 and findings[0]["hostname"] == "alpha.example.test"


def test_single_hostname_ip_with_wrong_cert_is_still_a_mismatch():
    combined = _combined(["alpha.example.test"])
    out, _ = _run(combined, [_row("alpha.example.test", "mail.example.test",
                                  ["mail.example.test"])])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is True


def test_a_name_on_a_different_ip_does_not_excuse_the_mismatch():
    combined = _combined(["alpha.example.test"])
    combined["port_scan"]["by_ip"]["192.88.98.11"] = {
        "ip": "192.88.98.11", "hostnames": ["mail.example.test"], "ports": [25]}
    out, _ = _run(combined, [_row("alpha.example.test", "mail.example.test",
                                  ["mail.example.test"])])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is True


def test_cert_naming_the_submitted_host_is_unchanged():
    combined = _combined(["alpha.example.test", "mail.example.test"])
    out, _ = _run(combined, [_row("alpha.example.test", "alpha.example.test",
                                  ["alpha.example.test"])])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is False
    # tlsx's own flag on a cert that names the host is still trusted, as before.
    out, _ = _run(_combined(["alpha.example.test", "mail.example.test"]),
                  [_row("alpha.example.test", "alpha.example.test",
                        ["alpha.example.test", "mail.example.test"], tlsx_mismatched=True)])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is True


def test_ip_mode_still_never_reports_a_mismatch():
    combined = _combined([])
    out, _ = _run(combined, [_row(_IP, "mail.example.test", ["mail.example.test"],
                                  tlsx_mismatched=True)])
    assert out["tlsx"]["by_target"][f"{_IP}:993"]["mismatched"] is False


def test_mock_ip_hostname_is_no_sibling():
    # run_ip_recon's dashed-IP placeholder never resolves; it must not excuse anything.
    assert tls_scan._hostnames_by_ip(_combined(["192-88-98-10", "alpha.example.test"])) == {
        _IP: {"alpha.example.test"}}


def test_parser_without_ip_hostnames_behaves_as_before():
    row = _row("alpha.example.test", "mail.example.test", ["mail.example.test"])
    bt = tls_scan._parse_tlsx_output(json.dumps(row), {f"alpha.example.test:993": _IP})
    assert bt[f"{_IP}:993"]["mismatched"] is True


# --------------------------------------------------------------------------- #
# Certificate node: deterministic across observation order
# --------------------------------------------------------------------------- #
class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"matched": 1}
        return result


def _writer():
    from graph_db.mixins.recon.tlsx_mixin import TlsxMixin

    class _W(TlsxMixin):
        def __init__(self):
            self.session = _Session()
            self.driver = MagicMock()
            self.driver.session.return_value = self.session
    return _W()


def _cert_entry(ip, host, mismatched, fp="ab" * 32):
    return {"scanned_ip": ip, "host": host, "port": 993, "probe_status": True,
            "fingerprint_sha256": fp, "subject_cn": "mail.example.test",
            "san": ["mail.example.test"], "mismatched": mismatched}


def _cert_writes(writer):
    return [p for q, p in writer.session.calls if "MERGE (c:Certificate" in q]


def test_shared_cert_mismatch_flag_does_not_depend_on_observation_order():
    a = ("192.88.98.10:993", _cert_entry("192.88.98.10", "mail.example.test", False))
    b = ("192.88.98.11:993", _cert_entry("192.88.98.11", "alpha.example.test", True))
    for order in ([a, b], [b, a]):
        w = _writer()
        w.update_graph_from_tlsx({"domain": "example.test",
                                  "tlsx": {"by_target": dict(order)}}, "u1", "p1")
        writes = _cert_writes(w)
        assert len(writes) == 2
        assert all(p["props"]["mismatched"] is True for p in writes), order
        assert all(p["uid"] == "u1" and p["pid"] == "p1" for p in writes)


def test_single_observation_cert_flag_is_written_as_observed():
    for flag in (True, False):
        w = _writer()
        w.update_graph_from_tlsx({"domain": "example.test", "tlsx": {"by_target": {
            "192.88.98.10:993": _cert_entry("192.88.98.10", "mail.example.test", flag)}}},
            "u1", "p1")
        (props,) = [p["props"] for p in _cert_writes(w)]
        assert props["mismatched"] is flag


def test_distinct_certs_keep_their_own_flags():
    w = _writer()
    w.update_graph_from_tlsx({"domain": "example.test", "tlsx": {"by_target": {
        "192.88.98.10:993": _cert_entry("192.88.98.10", "mail.example.test", False, fp="aa" * 32),
        "192.88.98.11:993": _cert_entry("192.88.98.11", "alpha.example.test", True, fp="bb" * 32),
    }}}, "u1", "p1")
    flags = sorted((p["props"]["fingerprint_sha256"], p["props"]["mismatched"])
                   for p in _cert_writes(w))
    assert flags == [("aa" * 32, False), ("bb" * 32, True)]
