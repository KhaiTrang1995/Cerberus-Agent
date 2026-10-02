"""Regression: a real hostname mismatch was hidden when the cert named a sibling.

mail.example.test and www.example.test share one IP, and IMAPS 993 serves a
certificate naming only www. tlsx dials mail (the alphabetically first name),
the cert does not name it, and mail clients DO connect as mail.example.test;
yet the mismatch was cleared because the cert named www, another name on the
same IP. With TLSX_INCLUDE_HTTP_PORTS on, a frontend serving another site's
cert was hidden the same way, and the cleared tlsx entry also replaced httpx's
own verdict for that host:port. The shared Certificate node read
mismatched=false.

The verdict now stands. The entry records which sibling names the cert does
cover, and the finding is reported at "low" with that context. A mismatch
whose cert covers no sibling is unchanged: medium, same text.

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
_MAIL, _WWW = "mail.example.test", "www.example.test"


def _combined(hostnames, ports=(993,)):
    return {"port_scan": {"by_ip": {_IP: {"ip": _IP, "hostnames": list(hostnames),
                                          "ports": list(ports)}}},
            "metadata": {}}


def _row(host, cn, san, *, port=993, fp="AABBCC"):
    return {
        "host": host, "ip": _IP, "port": str(port), "probe_status": True,
        "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
        "subject_cn": cn, "subject_dn": f"CN={cn}", "subject_an": san,
        "issuer_cn": "Test CA", "issuer_dn": "CN=Test CA",
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2099-01-01T00:00:00Z",
        "fingerprint_hash": {"sha256": fp},
    }


def _run(combined, rows, settings=None):
    proc = MagicMock()
    proc.communicate.return_value = ("\n".join(json.dumps(r) for r in rows), "")
    proc.returncode = 0
    with patch.object(tls_scan.subprocess, "Popen", return_value=proc):
        return tls_scan.run_tlsx_enrichment(combined, settings or {})


def _mismatches(combined):
    from recon.helpers.security_checks import run_tls_data_checks
    return [f for f in run_tls_data_checks(combined, {"tls_hostname_mismatch": True})
            if f["type"] == "tls_hostname_mismatch"]


def test_regression_tlsx_sibling_mismatch_hidden():
    combined = _combined([_MAIL, _WWW])
    assert tls_scan._build_tlsx_targets(combined, {})[0] == [f"{_MAIL}:993"]

    out = _run(combined, [_row(_MAIL, _WWW, [_WWW])])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["mismatched"] is True
    assert entry["mismatch_cert_covers_siblings"] == [_WWW]
    assert out["tlsx"]["summary"]["mismatched"] == 1

    [finding] = _mismatches(out)
    assert finding["hostname"] == _MAIL and finding["url"] == f"https://{_MAIL}:993"
    assert finding["severity"] == "low"
    assert finding["name"] == "TLS Certificate Hostname Mismatch"
    assert f"valid for {_WWW} on the same IP" in finding["description"]
    assert "verify which name clients use" in finding["description"]
    assert f"valid_for_same_ip={_WWW}" in finding["evidence"]


def test_regression_tlsx_sibling_mismatch_hidden_wildcard_lists_every_covered_sibling():
    combined = _combined(["alpha.example.test", "imap.mail.example.test",
                          "smtp.mail.example.test"])
    out = _run(combined, [_row("alpha.example.test", "*.mail.example.test",
                               ["*.mail.example.test"])])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["mismatched"] is True
    assert entry["mismatch_cert_covers_siblings"] == ["imap.mail.example.test",
                                                      "smtp.mail.example.test"]


def test_regression_tlsx_sibling_mismatch_hidden_httpx_verdict_on_http_ports():
    # TLSX_INCLUDE_HTTP_PORTS: tlsx's entry for mail:443 replaces httpx's verdict
    # for the same host:port, so clearing it left no finding at all.
    combined = _combined([_MAIL, _WWW], ports=(443,))
    combined["http_probe"] = {"by_url": {
        f"https://{_MAIL}": {"host": _MAIL, "ip": _IP, "tls": {
            "version": "tls13", "certificate": {"subject_cn": _WWW, "san": [_WWW],
                                                "mismatched": True}}},
        f"https://{_WWW}": {"host": _WWW, "ip": _IP, "tls": {
            "version": "tls13", "certificate": {"subject_cn": _WWW, "san": [_WWW],
                                                "mismatched": False}}},
    }}
    out = _run(combined, [_row(_MAIL, _WWW, [_WWW], port=443)],
               {"TLSX_INCLUDE_HTTP_PORTS": True})
    findings = _mismatches(out)
    assert [(f["hostname"], f["port"], f["severity"]) for f in findings] == [(_MAIL, 443, "low")]


def test_regression_tlsx_sibling_mismatch_hidden_certificate_node():
    from graph_db.mixins.recon.tlsx_mixin import TlsxMixin

    out = _run(_combined([_MAIL, _WWW]), [_row(_MAIL, _WWW, [_WWW], fp="ab" * 32)])

    calls = []
    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False

    def run(query, **params):
        calls.append((query, params))
        res = MagicMock()
        res.single.return_value = {"matched": 1}
        return res
    session.run.side_effect = run

    class _W(TlsxMixin):
        driver = MagicMock()
    w = _W()
    w.driver.session.return_value = session
    w.update_graph_from_tlsx({"domain": "example.test", "tlsx": out["tlsx"]}, "u1", "p1")

    [props] = [p["props"] for q, p in calls if "MERGE (c:Certificate" in q]
    assert props["mismatched"] is True
    # The new field is the finding's context; it is not a Certificate property.
    assert "mismatch_cert_covers_siblings" not in props


# --------------------------------------------------------------------------- #
# Unchanged paths
# --------------------------------------------------------------------------- #
def test_mismatch_covering_no_sibling_keeps_its_severity_and_text():
    out = _run(_combined([_MAIL, _WWW]), [_row(_MAIL, "other.example.test",
                                               ["other.example.test"])])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["mismatched"] is True
    assert "mismatch_cert_covers_siblings" not in entry
    [finding] = _mismatches(out)
    assert finding["severity"] == "medium"
    assert finding["description"] == (
        f"The certificate on {_MAIL}:993 does not name the host it was served for.")
    assert finding["evidence"] == (
        "subject_cn=other.example.test san=['other.example.test']")


def test_cert_naming_the_tested_host_carries_no_sibling_field():
    out = _run(_combined([_MAIL, _WWW]), [_row(_MAIL, _MAIL, [_MAIL, _WWW])])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["mismatched"] is False
    assert "mismatch_cert_covers_siblings" not in entry
    assert _mismatches(out) == []


def test_ip_mode_still_never_reports_a_mismatch():
    out = _run(_combined([]), [_row(_IP, _WWW, [_WWW])])
    entry = out["tlsx"]["by_target"][f"{_IP}:993"]
    assert entry["mismatched"] is False
    assert "mismatch_cert_covers_siblings" not in entry
