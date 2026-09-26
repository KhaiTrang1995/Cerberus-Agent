"""
Unit tests for the class-14 unauthenticated cache-purge check
recon.helpers.security_checks.check_cache_purge_exposed().

A finding requires the method DIFFERENTIAL: a bogus control method refused, PURGE or
BAN accepted (2xx). If the server 2xx's an arbitrary method it is ambiguous -> no claim.
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks

_IP = "10.0.0.5"


def _resp(status):
    r = mock.MagicMock()
    r.status_code = status
    r.text = ""
    r.headers = {}
    return r


def _patch(side_effect):
    return mock.patch.object(security_checks.requests, "request", side_effect=side_effect)


def test_purge_accepted_control_refused_is_finding():
    def fake(method, url, **kw):
        return _resp(200) if method == "PURGE" else _resp(405)
    with _patch(fake):
        f = security_checks.check_cache_purge_exposed(_IP, timeout=2)
    assert f is not None
    assert f["type"] == "cache_purge_exposed"
    assert f["detection_method"] == "method_differential"
    assert "PURGE" in f["name"]


def test_ban_accepted_is_finding():
    def fake(method, url, **kw):
        return _resp(200) if method == "BAN" else _resp(405)
    with _patch(fake):
        f = security_checks.check_cache_purge_exposed(_IP, timeout=2)
    assert f is not None
    assert "BAN" in f["name"]


def test_server_accepts_any_method_is_ambiguous_no_finding():
    # Control method also 2xx -> cannot distinguish a real purge endpoint.
    with _patch(lambda method, url, **kw: _resp(200)):
        assert security_checks.check_cache_purge_exposed(_IP, timeout=2) is None


def test_purge_refused_no_finding():
    with _patch(lambda method, url, **kw: _resp(405)):
        assert security_checks.check_cache_purge_exposed(_IP, timeout=2) is None


def test_network_error_swallowed():
    with _patch(mock.Mock(side_effect=security_checks.requests.exceptions.RequestException("x"))):
        assert security_checks.check_cache_purge_exposed(_IP, timeout=2) is None
