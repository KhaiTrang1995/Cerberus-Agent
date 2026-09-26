"""
Unit tests for the class-13 WAF blocked-vs-allowed payload differential in
recon.helpers.security_checks._waf_payload_differential().

The probe compares an edge (hostname, through the WAF) response with the origin
(direct IP + real Host header) response for a canonical WAF-signature string. A
finding is produced ONLY when the edge blocks the probe and the origin serves it.
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks

_IP = "10.10.10.10"


def _resp(status):
    r = mock.MagicMock()
    r.status_code = status
    r.text = "x"
    r.headers = {}
    return r


def _patch(side_effect):
    return mock.patch.object(security_checks.requests, "get", side_effect=side_effect)


def test_edge_blocks_origin_serves_is_bypass():
    def fake_get(url, **kw):
        return _resp(200) if _IP in url else _resp(403)   # origin serves, edge blocks
    with _patch(fake_get):
        f = security_checks._waf_payload_differential("shop.test", _IP, timeout=2)
    assert f is not None
    assert f["type"] == "waf_bypass"
    assert f["detection_method"] == "payload_differential"
    assert f["matched_ip"] == _IP
    assert f["severity"] == "high"


def test_both_allow_is_not_a_bypass():
    with _patch(lambda url, **kw: _resp(200)):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_both_block_is_not_a_bypass():
    with _patch(lambda url, **kw: _resp(403)):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_origin_5xx_is_not_allowed():
    # An origin that errors on the probe is not "serving" it -> no bypass claim.
    def fake_get(url, **kw):
        return _resp(500) if _IP in url else _resp(403)
    with _patch(fake_get):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_network_error_is_swallowed():
    with _patch(mock.Mock(side_effect=security_checks.requests.exceptions.RequestException("boom"))):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_block_codes_membership():
    assert security_checks._looks_blocked(403)
    assert security_checks._looks_blocked(406)
    assert not security_checks._looks_blocked(200)
    assert not security_checks._looks_blocked(404)
