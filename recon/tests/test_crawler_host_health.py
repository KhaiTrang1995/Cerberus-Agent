"""Skip-only HostHealth gates on the Docker crawlers and P3 tools.

hakrawler (#20), FFuf (#21) and the ZAP Ajax Spider (#22) each run per-seed for
minutes; graphql-cop, jsluice verify and kiterunner method detection (P3) run
per endpoint. A seed/endpoint whose host another module already found
unreachable is skipped, so a dead target no longer costs the full per-seed
timeout. The discovered URLs live under source 'resource_enum', so a skip is
reported per host and the prune keeps that host's endpoints.
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.resource_enum import (
    hakrawler_helpers as hk,
    ffuf_helpers as ff,
    zap_ajax_spider_helpers as zap,
    jsluice_helpers as jl,
    kiterunner_helpers as kr,
)


def _mark_down(host):
    for _ in range(3):
        cb.host_health.record_failure(f"https://{host}", requests.ConnectionError("x"))


ALLOWED = {"dead.example.test", "live.example.test"}
SEEDS = ["https://dead.example.test/", "https://live.example.test/"]


class TestHakrawler:
    def test_a_dead_host_seed_is_not_crawled(self):
        _mark_down("dead.example.test")
        crawled = []

        def fake_crawl(url, *a, **k):
            crawled.append(url)
            return (set(), 0, [])

        with mock.patch.object(hk, "_crawl_single_url", side_effect=fake_crawl):
            hk.run_hakrawler_crawler(
                SEEDS, "img", 2, 5, 10, 100, False, True, ALLOWED, [], [], parallelism=1)
        assert crawled == ["https://live.example.test/"]


class TestFFuf:
    def test_a_dead_host_target_is_not_fuzzed(self):
        _mark_down("dead.example.test")
        fuzzed = []

        def fake_fuzz(idx, fuzz_url, *a, **k):
            fuzzed.append(fuzz_url)
            return ([], [])

        with mock.patch.object(ff, "_fuzz_single_target", side_effect=fake_fuzz), \
             mock.patch.object(ff, "_build_fuzz_targets", return_value=list(SEEDS)):
            ff.run_ffuf_discovery(
                SEEDS, "wl", 40, 0, 10, 60, [], [], "0", [], False, 0, False, [], False,
                ALLOWED, parallelism=1)
        assert fuzzed == ["https://live.example.test/"]


class TestZapAjax:
    def test_a_dead_host_seed_is_skipped_and_counted(self):
        _mark_down("dead.example.test")
        crawled = []

        # Patch the executor entry (crawl_seed is a closure); instead assert via
        # the metadata + that no work dir subprocess runs by patching subprocess.
        with mock.patch.object(zap.subprocess, "run") as srun, \
             mock.patch.object(zap, "parse_zap_ajax_export_urls", return_value=[]):
            srun.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            urls, meta = zap.run_zap_ajax_spider(
                SEEDS, "img", ALLOWED, [], [], 100, 60, 5, 10, 1, "firefox-headless",
                1000, 1000, True, True, False, True, True, parallelism=1)
        assert meta.get("seeds_skipped_unreachable") == 1
        assert meta["seed_urls"] == 1


class TestGraphqlCop:
    def test_a_dead_host_endpoint_is_skipped_before_docker(self):
        from recon.graphql_scan import misconfig
        _mark_down("dead.example.test")
        # The skip returns before any docker run; patch subprocess.run to prove
        # it is never reached.
        with mock.patch.object(misconfig.subprocess, "run") as srun:
            out = misconfig.run_graphql_cop(
                "https://dead.example.test/graphql", {}, {"GRAPHQL_COP_ENABLED": True})
        assert out == {"findings": [], "raw": []}
        srun.assert_not_called()


class TestJsluiceVerify:
    def test_dead_host_candidates_are_dropped(self):
        _mark_down("dead.example.test")
        urls = ["https://dead.example.test/a.js", "https://live.example.test/b.js"]
        captured = {}

        def fake_run(cmd, *a, **k):
            # Read the urls file the verifier wrote and record its lines.
            data_idx = cmd.index("-l") + 1
            captured["ran"] = True
            return mock.MagicMock(returncode=1, stdout="", stderr="")

        with mock.patch.object(jl.subprocess, "run", side_effect=fake_run):
            _verified, stats = jl.verify_jsluice_urls(
                urls, "img", 10, 5, 50, [200], exclude_patterns=[])
        assert stats.get("jsluice_skipped_unreachable") == 1
        assert stats["jsluice_verify_candidates"] == 1


class TestKiterunnerMethods:
    def test_dead_host_urls_keep_their_method_without_re_probing(self):
        _mark_down("dead.example.test")
        kr_results = [
            {"url": "https://dead.example.test/api", "method": "GET"},
            {"url": "https://live.example.test/api", "method": "GET"},
        ]
        # Only the live URL should reach the OPTIONS probe (subprocess.run).
        with mock.patch.object(kr.subprocess, "run") as srun, \
             mock.patch.object(kr, "_create_temp_dir") as mktmp:
            srun.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            tmp = mock.MagicMock()
            written = {}

            class _P:
                def __init__(self, name): self.name = name
                def __truediv__(self, other): return _P(f"{self.name}/{other}")
                def __fspath__(self): return self.name
            mktmp.return_value = _P("/tmp/redamon/kr_methods_test")
            with mock.patch("builtins.open", mock.mock_open()) as mo:
                out = kr.detect_kiterunner_methods(
                    kr_results, "httpx", True, "options", ["GET", "POST"], 3, 50, 20)
                writes = "".join(c.args[0] for c in mo().write.call_args_list)
        assert "dead.example.test" not in writes
        assert "live.example.test" in writes
        # The dead host still carries its Kiterunner-found method in the result.
        assert out.get("https://dead.example.test/api") == ["GET"]
