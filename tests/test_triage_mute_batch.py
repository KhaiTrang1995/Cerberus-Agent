"""`mute_findings_batch`, the Multi mute write, and the batch-scoped Undo.

These run in the gate with a stubbed driver, so they pin the Cypher that gets
BUILT. What they guard is the part a suggestion cannot be trusted with: the
suggestion is minutes old when the person clicks, so the write itself must
re-check every guard under the node lock, in a deadlock-safe order, without
touching `updated_at`, and stamp the mute as a person's Multi mute.
"""
from __future__ import annotations

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.triage_mixin import (  # noqa: E402
    MAX_MULTI_MUTE_BATCH,
    MULTI_MUTE_CHANNEL,
    TriageMixin,
)

UID, PID = "u1", "p1"
CEILING = {"severity_rank": 1, "tier_rank": 1, "validated": False,
           "malicious": False, "confirmed": False}


class WriteClient(TriageMixin):
    """Records the query run inside `execute_write`, and how it was run."""

    def __init__(self, rows=None):
        self.queries, self.params = [], []
        self.used_execute_write = False
        self.used_plain_run = False
        rows = rows if rows is not None else []

        tx = MagicMock()

        def tx_run(query, **params):
            self.queries.append(query)
            self.params.append(params)
            return iter(rows)

        tx.run = tx_run

        def execute_write(fn):
            self.used_execute_write = True
            return fn(tx)

        def plain_run(query, **params):
            self.used_plain_run = True
            self.queries.append(query)
            self.params.append(params)
            result = MagicMock()
            result.__iter__ = lambda _self: iter(rows)
            return result

        session = MagicMock()
        session.execute_write = execute_write
        session.run = plain_run
        session.__enter__ = lambda _self: session
        session.__exit__ = lambda *_: False
        self.driver = MagicMock()
        self.driver.session.return_value = session

    def mute(self, keys=("k2", "k1"), **kw):
        args = dict(label="Vulnerability", keys=list(keys), seed_key="k1",
                    ceiling=CEILING, exempt_pairs=[["Vulnerability", "k9"]],
                    muted_by=UID, reason="Multi mute mm-0123abcd", batch_id="mm-0123abcd")
        args.update(kw)
        return self.mute_findings_batch(UID, PID, **args)


class TestTheWrite(unittest.TestCase):
    def setUp(self):
        self.c = WriteClient()
        self.c.mute()
        self.q = self.c.queries[-1]
        self.p = self.c.params[-1]

    def test_runs_in_a_retrying_write_transaction(self):
        self.assertTrue(self.c.used_execute_write)
        self.assertFalse(self.c.used_plain_run)

    def test_keys_are_ordered_before_the_lock(self):
        order = self.q.index("ORDER BY key")
        lock = self.q.index("SET n._mute_lock = true")
        self.assertLess(order, lock)
        self.assertEqual(self.p["keys"], ["k1", "k2"])

    def test_the_lock_comes_before_reading_muted(self):
        self.assertLess(self.q.index("SET n._mute_lock = true"), self.q.index("n:Muted AS already"))

    def test_tenant_scoped_and_single_label(self):
        self.assertIn("MATCH (n:Vulnerability)", self.q)
        self.assertIn("n.user_id = $user_id AND n.project_id = $project_id", self.q)
        self.assertEqual((self.p["user_id"], self.p["project_id"]), (UID, PID))

    def test_every_guard_is_re_checked(self):
        for predicate in ("proven", "kept_visible", "$ceiling.severity_rank",
                          "$ceiling.tier_rank", "n.stale_since IS NOT NULL",
                          "'js_file'", "n:Muted AS already", "ChainFinding"):
            self.assertIn(predicate, self.q, predicate)
        self.assertEqual(self.p["ceiling"], CEILING)
        self.assertEqual(self.p["exempt_pairs"], [["Vulnerability", "k9"]])

    def test_the_seed_skips_proof_exemption_and_ceiling_but_not_an_existing_mute(self):
        case = self.q[self.q.index("CASE WHEN already"):self.q.index("AS outcome")]
        self.assertLess(case.index("already"), case.index("is_seed"))
        self.assertLess(case.index("js_file"), case.index("is_seed"))
        for later in ("proven", "kept_visible", "NOT within", "stale"):
            self.assertLess(case.index("is_seed"), case.index(later), later)

    def test_stamped_as_a_persons_multi_mute(self):
        self.assertIn(f"n.muted_channel = '{MULTI_MUTE_CHANNEL}'", self.q)
        self.assertIn("n.muted_token = $batch_id", self.q)
        self.assertIn("n.muted_by = $muted_by", self.q)
        self.assertEqual(self.p["batch_id"], "mm-0123abcd")
        self.assertEqual(self.p["muted_by"], UID)

    def test_never_writes_updated_at(self):
        self.assertNotIn("updated_at", self.q)

    def test_the_write_only_happens_on_a_muted_outcome(self):
        self.assertRegex(self.q, r"FOREACH \(_ IN CASE WHEN outcome = 'muted' THEN \[1\] ELSE \[\] END")


class TestInputs(unittest.TestCase):
    def test_a_label_outside_the_muteable_set_is_refused(self):
        with self.assertRaises(ValueError):
            WriteClient().mute(label="IP")

    def test_keys_are_capped(self):
        c = WriteClient()
        c.mute(keys=[f"k{i:04d}" for i in range(MAX_MULTI_MUTE_BATCH + 50)])
        self.assertEqual(len(c.params[-1]["keys"]), MAX_MULTI_MUTE_BATCH)

    def test_no_keys_is_no_write(self):
        c = WriteClient()
        self.assertEqual(c.mute(keys=[]), {"items": [], "not_found": []})
        self.assertEqual(c.queries, [])

    def test_unmatched_keys_are_reported(self):
        c = WriteClient(rows=[{"key": "k1", "label": "Vulnerability", "node_id": "7",
                               "name": "x", "severity": "low", "outcome": "muted"}])
        out = c.mute(keys=["k1", "k2"])
        self.assertEqual(out["not_found"], ["k2"])
        self.assertEqual(out["items"][0]["outcome"], "muted")


class TestTheCeilingMirror(unittest.TestCase):
    """The Cypher severity rank must agree with `multi_mute.pool.severity_rank`,
    or the write refuses what the suggestion offered (or the reverse)."""

    def test_the_rank_table_matches_the_pool(self):
        try:
            sys.path.insert(0, os.path.join(_REPO, "agentic"))
            from multi_mute import pool
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"multi_mute.pool not importable here: {exc}")
        from graph_db.mixins.recon import triage_mixin
        cypher = triage_mixin._CEILING_SEVERITY_RANK
        for word, rank in pool.SEVERITY_RANK.items():
            if word in ("info", "informational", "none"):
                self.assertIn(f"'{word}'", cypher)
                continue
            branch = re.search(rf"WHEN [^\n]*'{word}'[^\n]*THEN (\d)", cypher)
            self.assertIsNotNone(branch, word)
            self.assertEqual(int(branch.group(1)), rank, word)
        self.assertEqual(pool.UNKNOWN_RANK, 2)
        self.assertRegex(cypher, r"ELSE 2 END")


class TestMalPackageOsvInfoRankedByThePoolsSource(unittest.TestCase):
    """Regression: the write-time ceiling read `n.severity` / `n.source` raw.

    The pool ranks what each label's triage-board query PROJECTS: a
    MalPackageFinding's source is `coalesce(source_tool, 'osv')` and an unset
    severity is the label's default. So an OSV `info` package ranked 2 in the
    pool and 0 at write, and a JS finding with no severity 1 in the pool and 2
    at write. The table the write uses must be the queries' own expressions.
    """

    @staticmethod
    def _projected(query: str, alias: str) -> str:
        m = re.search(rf"((?:coalesce\([^()]*\))|(?:[\w.']+))\s+AS\s+{alias}\b", query)
        assert m, f"no `AS {alias}` in a FINDING_QUERIES entry"
        return re.sub(r"\b[a-z]{1,2}\.", "n.", m.group(1))

    def test_the_write_table_is_the_board_queries_own_projection(self):
        try:
            sys.path.insert(0, os.path.join(_REPO, "agentic"))
            from cypherfix_triage.fact_queries import FINDING_QUERIES
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"fact_queries not importable here: {exc}")
        from graph_db.mixins.recon.triage_mixin import _PROJECTED_SEVERITY_SOURCE
        for entry in FINDING_QUERIES:
            label = entry["label"]
            with self.subTest(label=label):
                self.assertEqual(
                    _PROJECTED_SEVERITY_SOURCE[label],
                    (self._projected(entry["query"], "severity"),
                     self._projected(entry["query"], "source")))

    def test_the_batch_write_ranks_the_labels_projection(self):
        c = WriteClient()
        c.mute(label="MalPackageFinding", keys=["mp-1"])
        q = c.queries[-1]
        self.assertIn("coalesce(n.source_tool, 'osv')", q)
        self.assertIn("coalesce(n.severity, 'high')", q)


class UnmuteClient(TriageMixin):
    def __init__(self):
        self.queries, self.params = [], []

        def run(query, **params):
            self.queries.append(query)
            self.params.append(params)
            result = MagicMock()
            result.__iter__ = lambda _self: iter([])
            return result

        session = MagicMock()
        session.run = run
        session.__enter__ = lambda _self: session
        session.__exit__ = lambda *_: False
        self.driver = MagicMock()
        self.driver.session.return_value = session


class TestUndoIsScopedToTheBatch(unittest.TestCase):
    def test_the_remove_is_gated_on_channel_token_and_person(self):
        c = UnmuteClient()
        c.unmute_findings(UID, PID, ["k1"], only_batch="mm-0123abcd")
        q, p = c.queries[-1], c.params[-1]
        gate = q[q.index("$only_batch IS NOT NULL"):q.index("AS skipped")]
        self.assertIn(f"coalesce(n.muted_channel, '') = '{MULTI_MUTE_CHANNEL}'", gate)
        self.assertIn("n.muted_token = $only_batch", gate)
        self.assertIn("n.muted_by = $user_id", gate)
        self.assertLess(q.index("SET n._mute_lock = true"), q.index("AS skipped"))
        self.assertEqual(p["only_batch"], "mm-0123abcd")

    def test_a_plain_unmute_is_unchanged(self):
        c = UnmuteClient()
        c.unmute_findings(UID, PID, ["k1"])
        self.assertIsNone(c.params[-1]["only_batch"])
        self.assertNotIn("AND n.muted_token = $only_batch\n", c.queries[-1].split("SET n._mute_lock")[0])


class TestTheFourthMutedVia(unittest.TestCase):
    def test_multi_is_its_own_value_before_person(self):
        from graph_db.mixins.recon.triage_mixin import _MUTED_VIA
        self.assertLess(_MUTED_VIA.index("'multi'"), _MUTED_VIA.index("'person'"))
        self.assertLess(_MUTED_VIA.index("'rule'"), _MUTED_VIA.index("'multi'"))

    def test_the_filter_separates_multi_from_person(self):
        person, _ = TriageMixin._muted_filter(muted_via="person")
        multi, _ = TriageMixin._muted_filter(muted_via="multi")
        self.assertIn(f"NOT coalesce(n.muted_channel, '') = '{MULTI_MUTE_CHANNEL}'", person)
        self.assertIn(f"AND coalesce(n.muted_channel, '') = '{MULTI_MUTE_CHANNEL}'", multi)

    def test_facets_count_multi_apart_with_its_batches(self):
        c = UnmuteClient()
        rows = [
            {"label": "Vulnerability", "via": "multi", "rule": "", "token": "mm-0123abcd", "reason": "", "c": 3},
            {"label": "Vulnerability", "via": "person", "rule": "", "token": "", "reason": "", "c": 2},
        ]

        def run(query, **params):
            result = MagicMock()
            result.__iter__ = lambda _self: iter(rows)
            return result

        c.driver.session.return_value.run = run
        facets = c.muted_facets(UID, PID)
        self.assertEqual((facets["by_multi"], facets["by_person"]), (3, 2))
        self.assertEqual(facets["batches"], [{"batch": "mm-0123abcd", "count": 3}])


class TestAMultiMuteIsAPersonsMuteToTheSweepAndThePrune(unittest.TestCase):
    """Multi mute relies on two invariants it does not own: the Mute Rules
    sweep and the prune key "a person's mute" on `muted_by` not starting with
    `rule:`, and a Multi mute keeps the person in `muted_by`. If either side
    started keying on `muted_channel` instead, a bulk mute would be released
    by the next sweep or deleted by the next prune."""

    def test_rule_writes_touch_only_unmuted_or_rule_muted_nodes(self):
        from graph_db.node_filters import cypher
        source = open(cypher.__file__, encoding="utf-8").read()
        for block in re.findall(r'"""(.*?)"""', source, re.S):
            if "REMOVE n:Muted" in block or "SET n:Muted" in block:
                self.assertTrue("STARTS WITH" in block or "NOT n:Muted" in block, block[:300])

    def test_the_prune_keeps_every_non_rule_mute(self):
        from graph_db.mixins import base_mixin
        source = open(base_mixin.__file__, encoding="utf-8").read()
        self.assertIn("(n:Muted AND NOT coalesce(n.muted_by, '') STARTS WITH 'rule:')", source)

    def test_a_multi_mute_keeps_the_person_as_muted_by(self):
        c = WriteClient()
        c.mute(muted_by="")
        self.assertEqual(c.params[-1]["muted_by"], UID)


if __name__ == "__main__":
    unittest.main()
