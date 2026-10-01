"""Regression tests for the recon-review findings (99_RECON_FINDINGS.md).

Each class covers one fix. They assert at the seam, not through the whole
pipeline, so a change elsewhere does not silently neuter them.

- a silent crawler zero no longer prunes jsluice secrets  (jsluice feed cut)
- a broken jsluice URL verification records a coverage gap
- JS-discovered hostnames are capped like the certificate paths
- the Uncover merge routes hostnames through the scope gates
- an httpx budget timeout keeps what it already probed
- partial-recon crawlers forward their parallelism settings
- partial DAST rebuilds parameterised URLs from the graph
- the vhost noise filter records what it suppressed
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb


# ---------------------------------------------------------------------------
# #1 silent crawler zero must keep jsluice's previous findings
# ---------------------------------------------------------------------------
class TestJsluiceFeedCut:
    def setup_method(self):
        cb.reset_registry()

    def teardown_method(self):
        cb.reset_registry()

    def _degraded_sources(self):
        return set(cb.coverage_report().degraded_sources)

    def test_a_failed_crawler_cuts_jsluice(self):
        from recon.main_recon_modules.resource_enum import _note_jsluice_feed_cut
        _note_jsluice_feed_cut(["katana"], [], ["https://a.example.com"])
        assert "jsluice" in self._degraded_sources()

    def test_a_crawl_that_returned_nothing_from_live_seeds_cuts_jsluice(self):
        from recon.main_recon_modules.resource_enum import _note_jsluice_feed_cut
        _note_jsluice_feed_cut([], [], ["https://a.example.com"])
        assert "jsluice" in self._degraded_sources()

    def test_a_crawl_that_found_urls_is_not_a_cut(self):
        from recon.main_recon_modules.resource_enum import _note_jsluice_feed_cut
        _note_jsluice_feed_cut([], ["https://a.example.com/app.js"], ["https://a.example.com"])
        assert "jsluice" not in self._degraded_sources()

    def test_crawlers_switched_off_is_not_a_cut(self):
        from recon.main_recon_modules.resource_enum import _note_jsluice_feed_cut
        _note_jsluice_feed_cut([], [], [])
        assert "jsluice" not in self._degraded_sources()


# ---------------------------------------------------------------------------
# #1b Katana reports failure vs a genuine zero
# ---------------------------------------------------------------------------
class TestKatanaFailureFlag:
    def _run(self, returncode, stderr=""):
        from recon.helpers.resource_enum import katana_helpers

        def fake_popen(cmd, *a, **k):
            proc = mock.MagicMock()
            proc.stdout = mock.MagicMock()
            proc.stdout.readline.return_value = ""
            proc.stderr = mock.MagicMock()
            proc.stderr.read.return_value = stderr
            proc.poll.return_value = returncode
            proc.returncode = returncode
            proc.wait.return_value = returncode
            proc.kill.return_value = None
            return proc

        def fake_select(rlist, *a):
            return (rlist, [], [])

        with mock.patch.object(katana_helpers.subprocess, "Popen", side_effect=fake_popen), \
             mock.patch.object(katana_helpers.select, "select", side_effect=fake_select):
            return katana_helpers.run_katana_crawler(
                target_urls=["https://example.com"],
                docker_image="projectdiscovery/katana:latest",
                depth=1, max_urls=10, rate_limit=10, timeout=5,
                js_crawl=False, params_only=False,
                allowed_hosts={"example.com"}, custom_headers=[], exclude_patterns=[],
            )

    def test_clean_zero_is_not_a_failure(self):
        _urls, meta = self._run(returncode=0, stderr="")
        assert meta.get("failed") is False

    def test_nonzero_exit_is_a_failure(self):
        _urls, meta = self._run(returncode=1, stderr="")
        assert meta.get("failed") is True

    def test_stderr_output_is_a_failure(self):
        _urls, meta = self._run(returncode=0, stderr="broker denied the spawn")
        assert meta.get("failed") is True


# ---------------------------------------------------------------------------
# #2 a broken jsluice URL verification records a coverage gap
# ---------------------------------------------------------------------------
class TestJsluiceVerifyGap:
    def setup_method(self):
        cb.reset_registry()

    def teardown_method(self):
        cb.reset_registry()

    def _gap_sources(self):
        return {g["source"] for g in cb.coverage_report().gaps}

    def test_httpx_nonzero_exit_records_a_gap(self):
        from recon.helpers.resource_enum import jsluice_helpers

        proc = mock.MagicMock()
        proc.returncode = 2
        proc.stderr = "boom"
        with mock.patch.object(jsluice_helpers.subprocess, "run", return_value=proc), \
             mock.patch.object(jsluice_helpers, "_create_temp_dir", return_value=Path("/tmp")), \
             mock.patch.object(jsluice_helpers, "_cleanup_temp_dir"), \
             mock.patch("builtins.open", mock.mock_open()):
            verified, _stats = jsluice_helpers.verify_jsluice_urls(
                ["https://a.example.com/x"], "projectdiscovery/httpx:latest",
                threads=1, timeout=5, rate_limit=10, accept_status=[200],
            )
        assert verified == set()
        assert "jsluice:verify" in self._gap_sources()


# ---------------------------------------------------------------------------
# #3 JS-discovered hostnames are capped, like the certificate paths
# ---------------------------------------------------------------------------
class TestJsHostnameCap:
    def test_js_recon_passes_the_tlsx_cap(self):
        src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "js_recon.py").read_text()
        # The merge call must carry the cap; without it the path was unbounded.
        assert "merge_discovered_hostnames(" in src
        assert "TLSX_MAX_INJECTED_HOSTNAMES" in src


# ---------------------------------------------------------------------------
# #8 the vhost noise filter records what it discarded
# ---------------------------------------------------------------------------
class TestVhostNoiseBookkeeping:
    def test_detect_noisy_frontend_still_returns_empty_on_a_catch_all(self):
        from recon.main_recon_modules.vhost_sni_enum import _detect_noisy_frontend
        anomalies = [{"observed_status": 200, "observed_size": 100} for _ in range(12)]
        kept, noisy = _detect_noisy_frontend(anomalies, candidates_count=12)
        assert noisy is True
        assert kept == []

    def test_mixin_writes_the_suppression_count_and_sample(self):
        src = (PROJECT_ROOT / "graph_db" / "mixins" / "recon" / "vhost_sni_mixin.py").read_text()
        assert "vhost_sni_suppressed_as_noise" in src
        assert "vhost_sni_suppressed_sample" in src

    def test_probe_result_contract_carries_the_noise_keys(self):
        # The per-IP result dict gains the two keys, populated when a port fires
        # the noisy-frontend safety net.
        src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "vhost_sni_enum.py").read_text()
        assert '"suppressed_as_noise"' in src
        assert '"suppressed_as_noise_sample"' in src
        assert "suppressed_as_noise.extend(" in src


# ---------------------------------------------------------------------------
# #5 an httpx budget timeout keeps what it already probed
# ---------------------------------------------------------------------------
class TestHttpxTimeoutKeepsResults:
    def test_timeout_is_handled_inside_the_run_not_by_discarding(self):
        import inspect
        from recon.main_recon_modules.http_probe import run_http_probe
        src = inspect.getsource(run_http_probe)
        # The timeout no longer returns recon_data unchanged; it marks timed_out
        # and falls through to the same parse step as a finished run.
        assert "timed_out = True" in src
        assert "_stop_httpx_at_budget" in src
        # The old early-return branch (except TimeoutExpired: ... return recon_data
        # before parsing) is gone.
        assert "downstream phases run on what it found" not in src  # moved to the helper

    def test_stop_helper_notes_the_degraded_source(self):
        import inspect
        from recon.main_recon_modules.http_probe import _stop_httpx_at_budget
        src = inspect.getsource(_stop_httpx_at_budget)
        assert 'note_degraded("http_probe"' in src


# ---------------------------------------------------------------------------
# #7 partial-recon crawlers forward their parallelism settings
# ---------------------------------------------------------------------------
class TestPartialParallelismWiring:
    def test_partial_katana_passes_parallelism_and_concurrency(self):
        src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "web_crawling.py").read_text()
        assert "KATANA_PARALLELISM = settings.get('KATANA_PARALLELISM'" in src
        assert "KATANA_CONCURRENCY = settings.get('KATANA_CONCURRENCY'" in src

    def test_partial_hakrawler_and_gau_pass_their_workers(self):
        src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "web_crawling.py").read_text()
        assert "settings.get('HAKRAWLER_PARALLELISM'" in src
        assert "settings.get('GAU_WORKERS'" in src

    def test_partial_paramspider_and_kiterunner_use_their_settings(self):
        src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "parameter_discovery.py").read_text()
        assert "settings.get('PARAMSPIDER_WORKERS'" in src
        assert "KITERUNNER_PARALLELISM" in src
        assert "ThreadPoolExecutor" in src


# ---------------------------------------------------------------------------
# #10 the Uncover merge routes hostnames through the scope gates
# ---------------------------------------------------------------------------
class TestUncoverMergeGate:
    def test_merge_calls_merge_discovered_hostnames(self):
        src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "uncover_enrich.py").read_text()
        assert "from recon.helpers.target_helpers import merge_discovered_hostnames" in src
        assert "root_domain=domain" in src

    def test_empty_domain_adds_nothing(self):
        from recon.main_recon_modules.uncover_enrich import merge_uncover_into_pipeline
        combined = {"dns": {"subdomains": {}}, "metadata": {}}
        uncover = {"hosts": ["evil.example.com"], "ips": [], "ip_ports": {}}
        # No apex to test against -> fail closed, nothing injected.
        n = merge_uncover_into_pipeline(combined, uncover, "")
        assert n == 0
        assert combined["dns"]["subdomains"] == {}
        # The graph writer reads the payload, so the refused name leaves it too.
        assert uncover["hosts"] == []

    def test_a_name_resolving_to_a_private_address_is_refused(self):
        from recon.main_recon_modules.uncover_enrich import merge_uncover_into_pipeline

        def fake_getaddrinfo(host, *a, **k):
            ip = {"www.example.com": "93.184.216.34", "internal.example.com": "10.0.0.5"}[host]
            return [(2, 1, 6, "", (ip, 0))]

        combined = {"dns": {"subdomains": {}}, "metadata": {}}
        uncover = {"hosts": ["www.example.com", "internal.example.com"], "ips": [], "ip_ports": {}}
        with mock.patch("socket.getaddrinfo", fake_getaddrinfo):
            n = merge_uncover_into_pipeline(combined, uncover, "example.com", settings={})
        assert n == 1
        assert set(combined["dns"]["subdomains"]) == {"www.example.com"}
        assert uncover["hosts"] == ["www.example.com"]


# ---------------------------------------------------------------------------
# #6 partial DAST rebuilds parameterised URLs from the graph
# ---------------------------------------------------------------------------
class TestPartialDastUrlRebuild:
    def test_builder_rebuilds_from_parameters_not_full_url_only(self):
        src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "graph_builders.py").read_text()
        # It now reads query Parameters and urlencodes them, instead of relying
        # only on e.full_url (which resource_enum never writes).
        assert "HAS_PARAMETER]->(p:Parameter)" in src
        assert "urlencode(" in src
        assert "discovered_urls" in src


# ---------------------------------------------------------------------------
# #11 co-hosted vhost names are not scanned as targets in partial recon
# ---------------------------------------------------------------------------
class TestCoHostedVhostFilter:
    def test_scope_drops_a_known_co_hosted_vhost_host(self):
        from recon.partial_recon_modules import graph_builders as gb

        class _Sess:
            def run(self, cypher, **params):
                if "co_hosted_vhost_hosts" in cypher:
                    return [{"co_hosted_vhost_hosts": ["unrelated.co.uk"]}]
                return []

        keep = gb.graph_url_scope(_Sess(), "u", "p", ["example.com"], None)
        # A third-party host the graph knows only as a vhost name is dropped;
        # an ordinary third-party host (an IP, say) is still kept.
        assert keep("unrelated.co.uk") is False
        assert keep("10.0.0.9") is True

    def test_a_failed_lookup_drops_nothing_extra(self):
        from recon.partial_recon_modules import graph_builders as gb

        class _BadSess:
            def run(self, *a, **k):
                raise RuntimeError("neo4j down")

        hosts = gb._co_hosted_vhost_hosts(_BadSess(), "u", "p")
        assert hosts == frozenset()
