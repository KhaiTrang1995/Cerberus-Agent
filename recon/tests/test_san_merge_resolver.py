"""SAN merge resolver caching + resolver-breaker awareness (target_helpers.py, #4).

merge_discovered_hostnames resolves each SAN-derived name to drop internal
pivots. It ran twice per pipeline and the second call re-resolved the first's
names; now a per-run cache means each name is resolved once, and when the shared
DNS resolver is already down the getaddrinfo is skipped entirely.
"""
from __future__ import annotations

from unittest import mock

from recon.helpers import circuit_breaker as cb
from recon.helpers import target_helpers as th
from recon.main_recon_modules import domain_recon as dr


def test_a_name_is_resolved_once_across_calls():
    with mock.patch("socket.getaddrinfo",
                           return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]) as gai:
        assert th._resolves_to_routable("a.example.test") is True
        assert th._resolves_to_routable("a.example.test") is True  # cached
    assert gai.call_count == 1


def test_a_non_routable_name_is_dropped_and_cached():
    with mock.patch("socket.getaddrinfo",
                           return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]) as gai:
        assert th._resolves_to_routable("intranet.example.test") is False
        assert th._resolves_to_routable("intranet.example.test") is False
    assert gai.call_count == 1


def test_a_down_resolver_skips_getaddrinfo():
    dr.resolver_breaker.reset()
    dr.resolver_breaker.set_canary("canary.test")
    # Force the resolver open without any real DNS.
    with mock.patch.object(dr._ResolverBreaker, "_canary_responds", return_value=False):
        dr.resolver_breaker.note_transient()
    assert dr.resolver_breaker.is_open()
    with mock.patch("socket.getaddrinfo") as gai:
        # In scope, unresolved: kept without resolving.
        assert th._resolves_to_routable("late.example.test") is True
        gai.assert_not_called()
    dr.resolver_breaker.reset()
