"""The run-level finding prune and its coverage guard (recon/main.py).

A degraded run must never delete a finding it did not re-check:
  - a source whose coverage was cut is left out of the prune;
  - every finding on a host the run skipped is kept (keep_hosts);
  - unknown coverage (a failed coverage write, a faulted accumulator) prunes nothing;
  - a Domain batch prunes once, after the loop, and not at all when a group failed;
  - IP mode and a single domain still prune on success.

Neo4j is a fake: these pin what main.py asks the graph to do.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402


@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm


class FakeGraph:
    def __init__(self, matched=1, raise_on_coverage=False, reachable=True):
        self.matched = matched
        self.raise_on_coverage = raise_on_coverage
        self.reachable = reachable
        self.prunes = []
        self.coverage = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return self.reachable

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
        self.prunes.append({"sources": list(sources), "since": since, "keep_hosts": tuple(keep_hosts)})
        return {"pruned": 0, "stale": 0, "revived": 0}

    def update_graph_coverage(self, user_id, project_id, domain, record):
        if self.raise_on_coverage:
            raise RuntimeError("write failed")
        self.coverage.append({"domain": domain, **record})
        return self.matched


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


class TestThePruneGuard:
    def test_a_clean_run_prunes_every_recon_source(self, recon_main, graph):
        recon_main._prune_recon_findings()
        (prune,) = graph.prunes
        assert prune["sources"] == list(RECON_FINDING_SOURCES)
        assert prune["keep_hosts"] == ()

    def test_a_degraded_source_is_left_out(self, recon_main, graph, capsys):
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True,
                         reason="NUCLEI_MAX_RUNTIME reached")
        recon_main._prune_recon_findings()
        (prune,) = graph.prunes
        assert "nuclei" not in prune["sources"]
        assert set(prune["sources"]) == set(RECON_FINDING_SOURCES) - {"nuclei"}
        assert "1 source(s) cut (nuclei)" in capsys.readouterr().out

    def test_skipped_hosts_are_passed_as_keep_hosts(self, recon_main, graph):
        cb.note_degraded("security_checks", hosts=["a.example.com:443", "a.example.com:80",
                                                   "b.example.com:8443"],
                         host_source="security_check")
        recon_main._prune_recon_findings()
        (prune,) = graph.prunes
        assert prune["keep_hosts"] == ("a.example.com", "b.example.com")
        # A host-level cut keeps the source itself in the prune.
        assert "security_check" in prune["sources"]

    def test_a_failed_coverage_write_means_no_prune(self, recon_main, graph, capsys):
        graph.matched = 0  # no Domain node to stamp
        assert recon_main._write_coverage_record("example.com") is False
        recon_main._prune_recon_findings()
        assert graph.prunes == []
        assert "Finding prune skipped" in capsys.readouterr().out

    def test_a_coverage_write_exception_means_no_prune(self, recon_main, graph):
        graph.raise_on_coverage = True
        assert recon_main._write_coverage_record("example.com") is False
        recon_main._prune_recon_findings()
        assert graph.prunes == []

    def test_an_unreachable_graph_blocks_the_prune(self, recon_main, graph):
        graph.reachable = False
        assert recon_main._write_coverage_record("example.com") is False
        graph.reachable = True
        recon_main._prune_recon_findings()
        assert graph.prunes == []

    def test_a_faulted_accumulator_means_no_prune(self, recon_main, graph, monkeypatch):
        monkeypatch.setattr(cb, "_accumulator_broken", True)
        recon_main._prune_recon_findings()
        assert graph.prunes == []

    def test_the_off_switch_never_disables_the_guard(self, recon_main, graph, monkeypatch):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True)
        recon_main._prune_recon_findings()
        assert "nuclei" not in graph.prunes[0]["sources"]

    def test_a_crashed_phase_keeps_all_of_its_sources(self, recon_main, graph):
        recon_main._note_phase_error("vuln_scan")
        recon_main._note_phase_error("graphql_scan")
        recon_main._prune_recon_findings()
        (prune,) = graph.prunes
        for source in ("nuclei", "security_check", "vuln_scan", "graphql_scan", "graphql_cop"):
            assert source not in prune["sources"]
        assert "http_probe" in prune["sources"]

    def test_every_phase_source_is_a_recon_finding_source(self, recon_main):
        for sources in recon_main._PHASE_FINDING_SOURCES.values():
            assert set(sources) <= set(RECON_FINDING_SOURCES)

    def test_no_run_timestamp_means_no_prune(self, recon_main, graph):
        recon_main._RUN_STARTED_AT = None
        recon_main._prune_recon_findings()
        assert graph.prunes == []


class TestTheCoverageRecord:
    def test_a_clean_group_stamps_an_empty_record(self, recon_main, graph):
        assert recon_main._write_coverage_record("example.com") is True
        (record,) = graph.coverage
        assert record["domain"] == "example.com"
        assert record["gaps_json"] == "[]"
        assert record["skipped_hosts"] == [] and record["nuclei_truncated"] is False
        assert record["at"]

    def test_a_group_records_only_what_it_cut(self, recon_main, graph):
        cb.note_degraded("otx_enrich", entries=[{"source": "otx:general", "reason": "r", "skipped": 3}])
        group = cb.group_scope()
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True, reason="cap")
        cb.note_degraded("security_checks", hosts=["a.example.com:443"], host_source="security_check")
        recon_main._write_coverage_record("b.example.com", group)
        (record,) = graph.coverage
        assert '"otx:general"' not in record["gaps_json"]
        assert '"nuclei"' in record["gaps_json"] and '"security_check"' in record["gaps_json"]
        assert record["skipped_hosts"] == ["a.example.com:443"]
        assert record["nuclei_truncated"] is True

    def test_no_graph_means_nothing_to_write_and_no_failure(self, recon_main, graph, monkeypatch):
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", False)
        assert recon_main._write_coverage_record("example.com") is True
        assert graph.coverage == []

    def test_the_writer_is_synchronous_not_the_background_executor(self, recon_main):
        import inspect
        body = inspect.getsource(recon_main._write_coverage_record)
        assert "_graph_update_bg(" not in body


class TestWhereThePruneRuns:
    def test_a_domain_group_no_longer_prunes(self, recon_main):
        import inspect
        body = inspect.getsource(recon_main.run_domain_group)
        assert "_prune_recon_findings()" not in body
        assert "_write_coverage_record(root_domain, coverage_group)" in body

    def test_a_single_domain_prunes_only_on_success(self, recon_main, monkeypatch):
        prune = mock.Mock()
        monkeypatch.setattr(recon_main, "_prune_recon_findings", prune)
        monkeypatch.setattr(recon_main, "_clear_recon_graph", mock.Mock())
        monkeypatch.setattr(recon_main, "_check_roe_time_window", lambda s: (True, ""))
        monkeypatch.setattr(recon_main, "run_domain_group", mock.Mock(return_value=1))
        assert recon_main._run_pipeline() == 1
        prune.assert_not_called()
        recon_main.run_domain_group.return_value = 0
        assert recon_main._run_pipeline() == 0
        prune.assert_called_once_with()

    def test_ip_mode_records_coverage_then_prunes(self, recon_main, monkeypatch):
        calls = []
        monkeypatch.setattr(recon_main, "IP_MODE", True)
        monkeypatch.setattr(recon_main, "TARGET_IPS", ["198.51.100.1"])
        monkeypatch.setattr(recon_main, "_clear_recon_graph", mock.Mock())
        monkeypatch.setattr(recon_main, "run_ip_recon",
                            lambda ips, s: {"domain": "ip-targets.p1"})
        monkeypatch.setattr(recon_main, "_write_coverage_record",
                            lambda d, group=None: calls.append(("record", d)) or True)
        monkeypatch.setattr(recon_main, "_prune_recon_findings",
                            lambda: calls.append(("prune",)))
        assert recon_main._run_pipeline() == 0
        assert calls == [("record", "ip-targets.p1"), ("prune",)]

    def _groups(self, *roots):
        return [{'rootDomain': r, 'prefixes': ['.']} for r in roots]

    def _batch(self, recon_main, monkeypatch, results):
        prune = mock.Mock()
        monkeypatch.setattr(recon_main, "_prune_recon_findings", prune)
        monkeypatch.setattr(recon_main, "run_domain_group", mock.Mock(side_effect=results))
        with mock.patch.object(recon_main, "clear_batch_outputs", return_value=0), \
                mock.patch.object(recon_main, "initialize_batch_canonical"), \
                mock.patch.object(recon_main, "merge_batch_outputs"), \
                mock.patch.object(recon_main, "_seed_batch_root_domains"):
            rc = recon_main.run_domain_batch(self._groups("a.example", "b.example"),
                                             recon_main.datetime.now())
        return rc, prune

    def test_a_batch_prunes_once_after_every_group(self, recon_main, monkeypatch):
        rc, prune = self._batch(recon_main, monkeypatch, [0, 0])
        assert rc == 0
        prune.assert_called_once_with()

    def test_a_failed_group_means_no_prune_for_the_whole_batch(self, recon_main, monkeypatch, capsys):
        rc, prune = self._batch(recon_main, monkeypatch, [0, 1])
        assert rc == 0  # one group succeeded: the run itself did not fail
        prune.assert_not_called()
        assert "Finding prune skipped: b.example did not complete" in capsys.readouterr().out

    def test_a_group_that_raised_counts_as_failed(self, recon_main, monkeypatch):
        rc, prune = self._batch(recon_main, monkeypatch, [RuntimeError("boom"), 0])
        prune.assert_not_called()
