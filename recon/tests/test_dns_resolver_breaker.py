"""The canary-gated DNS resolver breaker and per-source subdomain breakers.

domain_recon.py, plan Phase 7 (#2 rdns zones, #3 resolver+canary, #5 sources).
A dead resolver used to make every 80x7 subdomain lookup time out three times;
the canary tells a dead resolver from a dead name so only the former stops the run.
"""
from __future__ import annotations

from unittest import mock

import pytest

import dns.resolver

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import domain_recon as dr


@pytest.fixture(autouse=True)
def _reset_resolver():
    dr.resolver_breaker.reset()
    yield
    dr.resolver_breaker.reset()


def _timeout(*a, **k):
    # dnspython requires both kwargs; this is what resolve() raises on timeout.
    raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])


def _answer(text="1.2.3.4"):
    rr = mock.MagicMock()
    rr.to_text.return_value = text
    return [rr]


class TestDnsLookupSingle:
    def test_nxdomain_is_definitive_no_retry(self):
        with mock.patch.object(dr.dns.resolver, "resolve",
                               side_effect=dns.resolver.NXDOMAIN) as res:
            out = dr.dns_lookup_single("nope.test", "A", max_retries=3)
        assert out is None
        assert res.call_count == 1  # not retried

    def test_transient_with_a_live_canary_does_not_open(self):
        dr.resolver_breaker.set_canary("canary.test")

        def side(hostname, rtype, *a, **k):
            if str(hostname) == "canary.test":
                return _answer()          # resolver is alive
            raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])

        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=side):
            out = dr.dns_lookup_single("slow.test", "A", max_retries=2)
        assert out is None
        assert dr.resolver_breaker.is_open() is False

    def test_transient_with_a_dead_canary_opens_the_resolver(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            out = dr.dns_lookup_single("slow.test", "A", max_retries=3)
        assert out is None
        assert dr.resolver_breaker.is_open() is True
        report = cb.coverage_report()
        assert "dns" in report.degraded_sources

    def test_an_open_resolver_short_circuits(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            dr.dns_lookup_single("slow.test", "A", max_retries=3)  # opens it
        with mock.patch.object(dr.dns.resolver, "resolve") as res:
            out = dr.dns_lookup_single("other.test", "A", max_retries=3)
        assert out is None
        res.assert_not_called()

    def test_the_off_switch_never_opens(self, monkeypatch):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            dr.dns_lookup_single("slow.test", "A", max_retries=1)
        assert dr.resolver_breaker.is_open() is False


class TestReverseZoneBreaker:
    def test_a_zone_that_times_out_is_skipped_after_the_threshold(self):
        # Three PTR timeouts on the same /24 open its rdns breaker; the fourth
        # IP in that zone is skipped without a lookup.
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            for i in range(3):
                dr.reverse_dns_lookup(f"203.0.113.{i}", max_retries=1)
        assert cb.is_open("rdns:203.0.113")
        with mock.patch.object(dr.dns.resolver, "resolve") as res:
            out = dr.reverse_dns_lookup("203.0.113.9", max_retries=1)
        assert out is None
        res.assert_not_called()

    def test_a_definitive_no_ptr_keeps_the_zone_healthy(self):
        with mock.patch.object(dr.dns.resolver, "resolve",
                               side_effect=dns.resolver.NXDOMAIN):
            for i in range(5):
                dr.reverse_dns_lookup(f"198.51.100.{i}", max_retries=1)
        assert not cb.is_open("rdns:198.51.100")


class TestVerifyDomainOwnership:
    def test_resolver_down_is_reported_not_no_txt(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            out = dr.verify_domain_ownership("example.test", "tok")
        assert out["verified"] is False
        assert "resolver down" in out["error"].lower()


class TestSourceBreakers:
    def _resp(self, status=200, text=""):
        r = mock.MagicMock()
        r.status_code = status
        r.text = text
        r.json.return_value = []
        return r

    def test_crtsh_pauses_after_repeated_failures(self):
        with mock.patch.object(dr.requests, "Session") as Sess:
            Sess.return_value.get.return_value = self._resp(502)
            for _ in range(3):
                dr.query_crtsh("a.test", settings={"CRTSH_ENABLED": True})
        assert cb.is_open("subsrc:crtsh")
        # Next group: the source is skipped without another HTTP call.
        with mock.patch.object(dr.requests, "Session") as Sess:
            dr.query_crtsh("b.test", settings={"CRTSH_ENABLED": True})
            Sess.return_value.get.assert_not_called()

    def test_hackertarget_429_pauses_after_two_in_a_row(self):
        # A 429 is classified RATE_LIMIT; the breaker pauses the source after two
        # consecutive rate-limits (never on one stray 429).
        with mock.patch.object(dr.requests, "Session") as Sess:
            Sess.return_value.get.return_value = self._resp(429, text="")
            dr.query_hackertarget("a.test", settings={"HACKERTARGET_ENABLED": True})
            assert not cb.is_open("subsrc:hackertarget")  # one strike, still closed
            dr.query_hackertarget("a2.test", settings={"HACKERTARGET_ENABLED": True})
        assert cb.is_open("subsrc:hackertarget")
