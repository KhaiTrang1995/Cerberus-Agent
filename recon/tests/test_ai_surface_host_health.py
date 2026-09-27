"""HostHealth gate on AI-surface recon (ai_surface_recon.py).

Phase 4.5 runs after http_probe/security_checks, so a host already found
unreachable is skipped rather than re-probed with a dozen AI paths. AI-surface
findings carry no host field, so the skip is reported at the SOURCE level
(host_field=False): the prune keeps every ai_surface_recon finding.
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import ai_surface_recon as ais


def _settings():
    # Every probe off: _analyze becomes a no-op, so a submitted (live) host
    # needs no network. The gate runs before submit, independent of this.
    return {
        "AI_SURFACE_RECON_ENABLED": True,
        "AI_SURFACE_RECON_CHAT_SHAPE_PROBE_ENABLED": False,
        "AI_SURFACE_RECON_MCP_HANDSHAKE_ENABLED": False,
        "AI_SURFACE_RECON_OPENAPI_DISCOVERY_ENABLED": False,
        "AI_SURFACE_RECON_JULIUS_PROBE_PACK_ENABLED": False,
        "AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED": False,
    }


def _candidates():
    return {
        "https://dead.example.test": {"host_is_ai": True, "endpoints": []},
        "https://live.example.test": {"host_is_ai": True, "endpoints": []},
    }


def _mark_down(host):
    for _ in range(3):
        cb.host_health.record_failure(f"https://{host}", requests.ConnectionError("x"))


def test_a_dead_host_is_skipped_and_reported_at_source_level():
    _mark_down("dead.example.test")
    with mock.patch.object(ais, "_gather_candidates", return_value=_candidates()):
        out = ais.run_ai_surface_recon({"metadata": {}}, settings=_settings())
    payload = out["ai_surface_recon"]
    assert "dead.example.test:443" in payload.get("unreachable_hosts", [])

    report = cb.coverage_report()
    # Source-level: the whole source is kept by the prune (no host field to scope).
    assert "ai_surface_recon" in report.degraded_sources
    # NOT recorded as a host skip (that would build a host-scoped prune regex).
    assert report.skipped_hosts == ()


def test_a_clean_run_keeps_todays_shape():
    with mock.patch.object(ais, "_gather_candidates", return_value=_candidates()):
        out = ais.run_ai_surface_recon({"metadata": {}}, settings=_settings())
    payload = out["ai_surface_recon"]
    assert "unreachable_hosts" not in payload
    assert "degraded" not in payload
    assert cb.coverage_report().degraded is False


def test_the_off_switch_skips_no_host(monkeypatch):
    # Even with a host marked down, is_down() is inert under the off switch, so
    # nothing is skipped and the run keeps today's shape.
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    _mark_down("dead.example.test")
    with mock.patch.object(ais, "_gather_candidates", return_value=_candidates()):
        out = ais.run_ai_surface_recon({"metadata": {}}, settings=_settings())
    assert "unreachable_hosts" not in out["ai_surface_recon"]
    assert cb.coverage_report().degraded is False
