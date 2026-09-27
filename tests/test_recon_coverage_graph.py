"""The graph side of partial-coverage recon runs (hermetic).

- prune_unseen_findings(keep_hosts=...) keeps every finding about a host the
  run skipped, and the host patterns travel as parameters, never in the query;
- update_graph_coverage matches the run's Domain on the tenant triple only.

A fake driver captures what the mixins send; tests/test_recon_coverage_graph_live.py
runs the same queries against a real Neo4j.
"""
import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.base_mixin import BaseMixin, keep_host_patterns  # noqa: E402
from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _Session:
    def __init__(self, calls, row):
        self.calls = calls
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result(self.row)


class _Driver:
    def __init__(self, row):
        self.calls = []
        self.row = row

    def session(self):
        return _Session(self.calls, self.row)


class _Client(BaseMixin, DomainMixin):
    def __init__(self, row):
        self.driver = _Driver(row)


def _prune_query(calls):
    (query, params), = [c for c in calls if "DETACH DELETE d" in c[0]]
    return query, params


class TestKeepHostPatterns(unittest.TestCase):
    def _matches(self, host, value):
        return any(re.fullmatch(p, value) for p in keep_host_patterns([host]))

    def test_every_shape_a_finding_writer_stores(self):
        for value in ("a.example.com", "a.example.com:8443", "https://a.example.com",
                      "https://a.example.com/login?x=1", "http://a.example.com:8080/",
                      "wss://a.example.com/socket", "https://user@a.example.com/",
                      "A.EXAMPLE.COM".lower()):
            with self.subTest(value=value):
                self.assertTrue(self._matches("a.example.com", value))

    def test_never_a_different_host(self):
        for value in ("b.example.com", "xa.example.com", "a.example.com.evil.test",
                      "https://evil.test/?next=a.example.com", "https://a.example.comx/",
                      "sub.a.example.com", ""):
            with self.subTest(value=value):
                self.assertFalse(self._matches("a.example.com", value))

    def test_ip_targets(self):
        self.assertTrue(self._matches("198.51.100.7", "https://198.51.100.7"))
        self.assertTrue(self._matches("198.51.100.7", "198.51.100.7"))
        self.assertFalse(self._matches("198.51.100.7", "198.51.100.70"))
        self.assertTrue(self._matches("::1", "https://[::1]:8443/x"))

    def test_regex_metacharacters_are_escaped(self):
        # A '.' must not match any character.
        self.assertFalse(self._matches("a.example.com", "aXexampleXcom"))

    def test_hostile_names_are_dropped_before_they_reach_a_pattern(self):
        patterns = keep_host_patterns(["ok.example.com", "evil.com'); DROP", "a|b", "x*",
                                       "", None, "[::1]"])
        joined = "".join(patterns)
        self.assertIn(re.escape("ok.example.com"), joined)
        for bad in ("DROP", "a|b", "x*", "evil"):
            self.assertNotIn(bad, joined)

    def test_many_hosts_are_split_into_short_patterns(self):
        hosts = [f"h{i}.example.com" for i in range(250)]
        patterns = keep_host_patterns(hosts)
        self.assertEqual(len(patterns), 3)
        self.assertTrue(any(re.fullmatch(p, "https://h249.example.com/") for p in patterns))


class TestPruneKeepHosts(unittest.TestCase):
    def _prune(self, keep_hosts):
        client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_hosts=keep_hosts)
        return _prune_query(client.driver.calls)

    def test_no_keep_hosts_leaves_the_query_unchanged(self):
        plain_client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        plain_client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00")
        plain_query, plain_params = _prune_query(plain_client.driver.calls)
        query, params = self._prune(())
        self.assertEqual(query, plain_query)
        self.assertEqual(params, plain_params)
        self.assertNotIn("keep_patterns", query)

    def test_hosts_travel_as_parameters_never_in_the_query_text(self):
        query, params = self._prune(["a.example.com", "198.51.100.7"])
        self.assertIn("$keep_patterns", query)
        self.assertNotIn("a.example.com", query)
        self.assertNotIn("198", query)
        self.assertEqual(len(params["keep_patterns"]), 1)
        self.assertTrue(re.fullmatch(params["keep_patterns"][0], "https://a.example.com/x"))

    def test_the_tenant_predicate_and_sources_stay(self):
        query, params = self._prune(["a.example.com"])
        self.assertIn("n.user_id = $uid AND n.project_id = $pid", query)
        self.assertIn("coalesce(n.source, '') IN $sources", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_every_host_field_is_checked(self):
        query, _ = self._prune(["a.example.com"])
        for field in ("host", "hostname", "matched_at", "url", "base_url", "source_url",
                      "endpoint", "matched_ip", "ip_address", "probe_url"):
            self.assertIn(f"toStringOrNull(n.{field})", query)

    def test_the_revive_query_is_unchanged(self):
        client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_hosts=["a.example.com"])
        revive = [q for q, _ in client.driver.calls if "REMOVE n.stale_since" in q]
        self.assertEqual(len(revive), 1)
        self.assertNotIn("keep_patterns", revive[0])


class TestUpdateGraphCoverage(unittest.TestCase):
    RECORD = {"at": "2026-01-01T00:00:00+00:00", "gaps_json": "[]",
              "skipped_hosts": [], "nuclei_truncated": False}

    def test_it_matches_the_tenant_triple_and_sets_the_four_properties(self):
        client = _Client({"n": 1})
        self.assertEqual(client.update_graph_coverage("u1", "p1", "example.com", self.RECORD), 1)
        (query, params), = client.driver.calls
        self.assertIn("MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})", query)
        self.assertNotIn("MERGE", query)
        for prop in ("recon_coverage_at", "recon_coverage_gaps", "recon_skipped_hosts",
                     "recon_nuclei_truncated"):
            self.assertIn(f"d.{prop}", query)
        self.assertEqual((params["name"], params["user_id"], params["project_id"]),
                         ("example.com", "u1", "p1"))

    def test_zero_matched_is_reported_as_zero(self):
        client = _Client({"n": 0})
        self.assertEqual(client.update_graph_coverage("u1", "p1", "example.com", self.RECORD), 0)

    def test_a_missing_gaps_value_is_an_empty_array(self):
        client = _Client({"n": 1})
        client.update_graph_coverage("u1", "p1", "example.com", {"at": self.RECORD["at"]})
        (_, params), = client.driver.calls
        self.assertEqual(params["gaps_json"], "[]")
        self.assertEqual(params["skipped_hosts"], [])
        self.assertIs(params["nuclei_truncated"], False)


if __name__ == "__main__":
    unittest.main()
