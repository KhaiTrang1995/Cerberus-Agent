"""HostHealth on the custom security checks (recon/helpers/security_checks.py).

A dead host used to be re-contacted by every check category at 10s each: 12
login paths, 7 API paths, 10 rate-limit POSTs. The requests themselves only
RECORD what they saw (any response is life; only a connection failure counts);
the skip is decided once per host at each check_single_* closure, so request
counts inside a closure never change.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers import security_checks as sc


def _resp(status=200, headers=None, text=""):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.content = text.encode()
    r.cookies = []
    r.url = "https://h.example.test/"
    r.history = []
    return r


def _mark_down(host):
    for scheme in ("https", "http"):
        for _ in range(3):
            cb.host_health.record_failure(f"{scheme}://{host}", requests.ConnectionError("x"))


class TestTheRecordingWrappers:
    def test_any_response_is_life_and_never_counts(self):
        with mock.patch.object(sc.requests, "get", return_value=_resp(403)):
            for _ in range(10):
                sc._hh_get("https://waf.example.test/")
        assert cb.host_health.allow("https://waf.example.test/")
        assert cb.host_health.unreachable() == []

    def test_connection_failures_count_and_are_reraised(self):
        with mock.patch.object(sc.requests, "get", side_effect=requests.ConnectionError("x")):
            for _ in range(3):
                with pytest.raises(requests.ConnectionError):
                    sc._hh_get("https://dead.example.test/")
        assert cb.host_health.is_down("https://dead.example.test/")

    def test_a_dead_capture_proxy_never_marks_hosts_down(self):
        with mock.patch.object(sc.requests, "get", side_effect=requests.exceptions.ProxyError("x")):
            for _ in range(10):
                with pytest.raises(requests.exceptions.ProxyError):
                    sc._hh_get("https://live.example.test/")
        assert not cb.host_health.is_down("https://live.example.test/")

    def test_the_wrappers_never_refuse_a_request(self):
        """Gating a leaf would change request counts; only the closure skips."""
        _mark_down("dead.example.test")
        with mock.patch.object(sc.requests, "get", return_value=_resp(200)) as get:
            sc._hh_get("https://dead.example.test/")
        assert get.call_count == 1


class TestThePerHostGate:
    def test_a_host_down_on_both_ports_is_skipped(self):
        _mark_down("dead.example.test")
        assert sc._host_down("dead.example.test") is True

    def test_a_host_that_only_lost_https_is_still_checked(self):
        for _ in range(3):
            cb.host_health.record_failure("https://half.example.test",
                                          requests.ConnectionError("x"))
        assert sc._host_down("half.example.test") is False

    def test_a_skipped_host_sends_no_request(self):
        _mark_down("dead.example.test")
        with mock.patch.object(sc.requests, "get", return_value=_resp(200)) as get:
            out = sc.run_security_headers_checks(
                hostnames=["dead.example.test", "live.example.test"],
                enabled_checks={"missing_referrer_policy": True},
                timeout=1, max_workers=1)
        urls = [c.args[0] for c in get.call_args_list]
        assert urls and all("dead.example.test" not in u for u in urls)
        assert any("live.example.test" in u for u in urls)
        assert isinstance(out, list)

    def test_the_off_switch_never_skips(self, monkeypatch):
        _mark_down("dead.example.test")
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        assert sc._host_down("dead.example.test") is False


class TestWafBypassCallCount:
    def test_check_waf_bypass_keeps_its_two_calls(self, monkeypatch):
        monkeypatch.setattr(sc, "_waf_payload_differential", lambda *a, **k: None)
        with mock.patch.object(sc.requests, "get",
                               side_effect=[_resp(200, text="edge"), _resp(200, text="origin")]) as get:
            sc.check_waf_bypass("www.example.test", "198.51.100.9", timeout=1)
        assert get.call_count == 2


class TestTheResult:
    def _recon(self, hosts):
        return {"domain": "example.test", "dns": {
            "domain": {},
            "subdomains": {h: {"has_records": True, "ips": {"ipv4": [], "ipv6": []}} for h in hosts},
        }}

    def test_a_clean_run_has_no_unreachable_hosts_key(self):
        with mock.patch.object(sc.requests, "get", return_value=_resp(200)):
            out = sc.run_security_checks(self._recon(["a.example.test"]),
                                         {"missing_referrer_policy": True}, timeout=1, max_workers=1)
        assert "unreachable_hosts" not in out["security_checks"]
        assert "degraded" not in out["security_checks"]

    def test_a_dead_host_is_listed_and_kept_by_the_prune(self):
        # The login check alone probes a dozen paths per host: plenty to cross
        # the 3-connection-failure threshold on a dead host.
        with mock.patch.object(sc.requests, "get", side_effect=requests.ConnectionError("x")):
            out = sc.run_security_checks(
                self._recon(["dead.example.test"]),
                {"login_no_https": True, "missing_referrer_policy": True},
                timeout=1, max_workers=1)
        hosts = out["security_checks"].get("unreachable_hosts") or []
        assert any(h.startswith("dead.example.test") for h in hosts)
        report = cb.coverage_report()
        assert "dead.example.test" in report.skipped_hostnames()
        # Host-level only: the source itself still prunes for other hosts.
        assert "security_check" not in report.degraded_sources


class TestSyntheticIpHostFilter:
    """IP-mode dashed-IP placeholders (e.g. 192-88-96-10) must not be probed by
    name or reported as unreachable: they never resolve, and the IP is checked
    directly. Regression for the false 'partial' every IP-mode scan showed."""

    def test_recognises_dashed_ipv4_placeholder(self):
        assert sc._is_synthetic_ip_host("192-88-96-10") is True
        assert sc._is_synthetic_ip_host("10-0-0-1") is True

    def test_recognises_dashed_ipv6_placeholder(self):
        assert sc._is_synthetic_ip_host("2001-db8--1") is True

    def test_real_hostnames_are_not_matched(self):
        assert sc._is_synthetic_ip_host("app.example.test") is False
        assert sc._is_synthetic_ip_host("webserver") is False
        assert sc._is_synthetic_ip_host("10-0-0-1.example.com") is False
        assert sc._is_synthetic_ip_host("") is False

    def test_placeholder_hostnames_are_never_probed_by_name(self):
        # Two IP-mode hosts under dashed placeholder names, both resolving to a
        # real IP. No probe may target a dashed-IP host (only the real IPs).
        from urllib.parse import urlparse
        recon = {"domain": "", "dns": {"domain": {}, "subdomains": {
            "app.example.test": {"has_records": True, "ips": {"ipv4": ["192.88.96.10"], "ipv6": []}},
            "192-88-96-10": {"has_records": True, "ips": {"ipv4": ["192.88.96.10"], "ipv6": []}},
            "192-88-96-20": {"has_records": True, "ips": {"ipv4": ["192.88.96.20"], "ipv6": []}},
        }}}
        with mock.patch.object(sc.requests, "get", return_value=_resp(200)) as get, \
             mock.patch.object(sc.requests, "post", return_value=_resp(200)), \
             mock.patch.object(sc.requests, "request", return_value=_resp(200)):
            sc.run_security_checks(
                recon,
                {"missing_referrer_policy": True, "login_no_https": True},
                timeout=1, max_workers=1)
        hosts = [urlparse(c.args[0]).hostname or "" for c in get.call_args_list if c.args]
        assert "app.example.test" in hosts, "the real hostname should still be probed"
        assert all(not sc._is_synthetic_ip_host(h) for h in hosts), \
            f"a dashed-IP placeholder was probed: {[h for h in hosts if sc._is_synthetic_ip_host(h)]}"
