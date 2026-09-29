"""LIVE-Neo4j proof of the layered Priority Board write paths.

`test_triage_mixin.py` asserts the SHAPE of the Cypher the mixin builds. This
proves Neo4j agrees, against a real database: the layered publish writes the base
and the result and never a decision; a decision given while a run works is
honoured at publish; a still-valid external review survives the next run; a
verdict rescores its finding in the same transaction; Reset removes the
decision; the app/MCP channel rule holds with an absent channel; a finding proven
after the run cannot be talked down; an ambiguous id writes nothing; and a
write that cannot get its node's lock times out as busy instead of stalling.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://redamon-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_triage_scoring_graph_live

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import json
import os
import sys
import threading
import time
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")

if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()

TOP = {"id": "top", "label": "Vulnerability", "source": "nuclei", "severity": "high",
       "name": "Exposed .env", "matcher_status": True, "extracted_results": ["DB_PASSWORD=x"],
       "raw_response": "HTTP/1.1 200 OK\nDate: Tue, 29 Sep 2026 10:00:00 GMT\n\nAPP_KEY=base64",
       "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "host": "h1"}
MID = {"id": "mid", "label": "Vulnerability", "source": "shodan", "severity": "critical",
       "name": "Old banner", "host": "h1"}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveLayersCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin
        from triage_layers_live_support import PUBLISH_COMBINE, layer_row

        run = uuid.uuid4().hex[:8]
        self.uid = f"score-{run}"
        self.pid = f"SCORE_{run}"
        self.other_uid = f"other-{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.combine = PUBLISH_COMBINE
        self.row = layer_row

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            for f in (TOP, MID):
                props = {k: v for k, v in f.items() if k not in ("label",)}
                s.run("CREATE (v:Vulnerability) SET v = $props, v.user_id = $u, v.project_id = $p",
                      props=props, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$u, $o] AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, o=self.other_uid, p=self.pid)
            s.run("MATCH (c:ChainFinding {project_id: $p}) DETACH DELETE c", p=self.pid)
        self.driver.close()

    # -- helpers --------------------------------------------------------------
    def publish(self, *rows):
        return self.client.publish_triage_layers(self.uid, self.pid, list(rows), self.combine,
                                                 guard_updated_at=False)

    def rows(self, **filters):
        return {r["id"]: r for r in self.client.list_triage_findings(self.uid, self.pid, **filters)}

    def props(self, node_id):
        with self.driver.session() as s:
            rec = s.run("MATCH (n:Vulnerability {id: $id, user_id: $u, project_id: $p}) "
                        "RETURN properties(n) AS p", id=node_id, u=self.uid, p=self.pid).single()
        return dict(rec["p"]) if rec else {}

    def mcp_review(self, finding, verdict="doubtful", **extra):
        from cypherfix_triage import evidence
        digest = evidence.bundle_hash(evidence.build_bundle(finding))
        return {"triage_ai_verdict": verdict, "triage_ai_channel": "mcp",
                "triage_ai_by": "rdmn_mcp_0a1b2c3d", "triage_ai_evidence_hash": digest,
                "triage_ai_corrections": json.dumps({"verdict": verdict, "impact_multiplier": 1.0,
                                                     "impact_quote": "", "disputed_facts": []}),
                **extra}

    # -- the publish ----------------------------------------------------------
    def test_the_publish_writes_the_base_and_the_result_and_ranks(self):
        result = self.publish(self.row(TOP), self.row(MID))
        self.assertEqual(result["updated"], 2)
        rows = self.rows()
        ordered = [r["id"] for r in self.client.list_triage_findings(self.uid, self.pid)]
        self.assertEqual(ordered[0], "top")
        top = rows["top"]
        self.assertEqual(top["triage_decided_by"], "rules")
        self.assertEqual(top["triage_priority_score"], top["triage_math_score"])
        self.assertIn('"C"', top["triage_base_factors"])
        self.assertEqual(top["review_state"], "none")
        self.assertEqual(len(self.props("top")["triage_evidence_hash"]), 40)

    def test_the_publish_never_writes_a_decision_and_never_mutes(self):
        self.publish(self.row(TOP))
        p = self.props("top")
        for key in ("triage_source", "triage_verdict_channel", "triage_reason", "triage_confidence"):
            self.assertNotIn(key, p)
        with self.driver.session() as s:
            muted = s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) RETURN v:Muted AS m",
                          u=self.uid).single()["m"]
        self.assertFalse(muted)

    def test_a_decision_given_during_the_run_is_honoured_at_publish(self):
        """The run read 'no decision' minutes ago; the publish reads it again."""
        self.client.set_human_verdict(self.uid, self.pid, "mid", "likely_noise", "checked")
        builtin = {"triage_ai_verdict": "real", "triage_ai_channel": "builtin", "triage_ai_by": ""}
        result = self.publish(self.row(MID, review=builtin))
        self.assertEqual(result["reviews_written"], 0)
        row = self.rows()["mid"]
        self.assertEqual((row["triage_state"], row["triage_decided_by"], row["section"]),
                         ("false_positive", "person", 2))
        self.assertEqual(self.props("mid")["triage_status"], "likely_noise")

    def test_a_valid_external_review_survives_the_next_run(self):
        """B1, for the review an agent wrote: a run is not newer evidence."""
        self.publish(self.row(TOP))
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) SET v += $r",
                  u=self.uid, r=self.mcp_review(TOP))
        builtin = {"triage_ai_verdict": "real", "triage_ai_channel": "builtin", "triage_ai_by": "",
                   "triage_ai_evidence_hash": self.props("top")["triage_evidence_hash"]}
        self.publish(self.row(TOP, run_id="run-2", review=builtin))
        p = self.props("top")
        self.assertEqual((p["triage_ai_channel"], p["triage_ai_verdict"]), ("mcp", "doubtful"))
        row = self.rows()["top"]
        self.assertEqual(row["triage_decided_by"], "review")
        self.assertLess(row["triage_priority_score"], row["triage_math_score"])

    def test_a_rescan_that_only_moves_the_date_keeps_the_review(self):
        self.publish(self.row(TOP))
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) SET v += $r",
                  u=self.uid, r=self.mcp_review(TOP))
        later = dict(TOP, raw_response=TOP["raw_response"].replace("10:00:00", "23:59:59"))
        self.publish(self.row(later, run_id="run-2"))
        self.assertEqual(self.rows()["top"]["review_state"], "current")
        changed = dict(TOP, raw_response="HTTP/1.1 404 Not Found")
        self.publish(self.row(changed, run_id="run-3"))
        row = self.rows()["top"]
        self.assertEqual(row["review_state"], "stale")
        self.assertEqual(row["triage_decided_by"], "rules")

    def test_another_tenants_id_is_never_written(self):
        with self.driver.session() as s:
            s.run("CREATE (v:Vulnerability {id:'victim', user_id:$o, project_id:$p, severity:'high'})",
                  o=self.other_uid, p=self.pid)
        result = self.publish(self.row({"id": "victim", "label": "Vulnerability"}))
        self.assertEqual((result["updated"], result["missing"]), (0, 1))
        with self.driver.session() as s:
            victim = s.run("MATCH (v:Vulnerability {id:'victim'}) RETURN v.triage_priority_score AS s"
                           ).single()
        self.assertIsNone(victim["s"])

    def test_a_node_a_scan_changed_mid_run_is_skipped(self):
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) SET v.updated_at = datetime()",
                  u=self.uid)
        result = self.client.publish_triage_layers(
            self.uid, self.pid, [self.row(TOP, seen="2000-01-01T00:00:00Z")], self.combine)
        self.assertEqual((result["skipped_changed"], result["updated"]), (1, 0))

    def test_the_legacy_shapes_are_retired_on_publish(self):
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) "
                  "SET v.triage_status = 'likely_noise', v.triage_source = 'ai', "
                  "    v.triage_reason = 'the AI said so', v.triage_confidence = 0.9", u=self.uid)
        self.publish(self.row(TOP))
        p = self.props("top")
        self.assertEqual(p["triage_status"], "unreviewed")
        self.assertNotIn("triage_source", p)
        self.assertNotIn("triage_reason", p)
        self.assertEqual(p["triage_ai_why"], "the AI said so")

    # -- the verdict ----------------------------------------------------------
    def test_real_rescores_at_once_and_reset_removes_the_decision(self):
        from cypherfix_triage.layers import combine_props
        self.publish(self.row(MID))
        before = self.rows()["mid"]["triage_priority_score"]
        out = self.client.set_human_verdict(self.uid, self.pid, "mid", "confirmed", "seen it",
                                            combine=combine_props)
        self.assertTrue(out["rescored"])
        self.assertGreater(out["after"]["score"], before)
        row = self.rows()["mid"]
        self.assertEqual(row["triage_decided_by"], "person")
        self.assertEqual(json.loads(row["triage_factors"])["C"]["value"], 1.0)
        p = self.props("mid")
        self.assertIn("triage_verdict_at", p)
        self.assertEqual(str(p["triaged_at"]), str(self.props("mid")["triaged_at"]))

        out = self.client.set_human_verdict(self.uid, self.pid, "mid", "unreviewed",
                                            combine=combine_props)
        p = self.props("mid")
        for key in ("triage_source", "triage_verdict_channel", "triage_verdict_by",
                    "triage_verdict_at", "triage_reason", "triage_confidence"):
            self.assertNotIn(key, p)
        self.assertEqual(p["triage_status"], "unreviewed")
        self.assertEqual(self.rows()["mid"]["triage_priority_score"], before)

    def test_mcp_cannot_touch_a_decision_made_in_the_app_even_with_no_channel(self):
        """C7: every decision before channels existed carries none, and was a click."""
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) "
                  "SET v.triage_status = 'confirmed', v.triage_source = 'human'", u=self.uid)
        for status in ("likely_noise", "unreviewed"):
            out = self.client.set_human_verdict(self.uid, self.pid, "top", status, channel="mcp")
            self.assertEqual(out["reason"], "decided_in_app")
        self.assertEqual(self.props("top")["triage_status"], "confirmed")

    def test_an_id_shared_by_two_labels_is_ambiguous_until_a_label_is_given(self):
        with self.driver.session() as s:
            s.run("CREATE (:Secret {id:'mid', user_id:$u, project_id:$p})", u=self.uid, p=self.pid)
        out = self.client.set_human_verdict(self.uid, self.pid, "mid", "confirmed")
        self.assertEqual((out["reason"], out["labels"]), ("ambiguous", ["Secret", "Vulnerability"]))
        self.assertNotIn("triage_status", self.props("mid"))
        out = self.client.set_human_verdict(self.uid, self.pid, "mid", "confirmed",
                                            label="Vulnerability")
        self.assertTrue(out["updated"])

    def test_a_write_that_cannot_get_the_lock_is_busy_not_stuck(self):
        from graph_db.mixins.recon.triage_mixin import TriageWriteBusy
        session = self.driver.session()
        tx = session.begin_transaction()
        try:
            tx.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) SET v._held = true",
                   u=self.uid).consume()
            started = time.monotonic()
            with self.assertRaises(TriageWriteBusy):
                self.client.set_human_verdict(self.uid, self.pid, "top", "confirmed", timeout=2)
            self.assertLess(time.monotonic() - started, 30)
        finally:
            tx.rollback()
            session.close()

    # -- the reads -------------------------------------------------------------
    def test_filters_facets_detail_and_preflight_run_on_neo4j(self):
        from cypherfix_triage.layers import combine_props
        self.publish(self.row(TOP), self.row(MID))
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) SET v += $r",
                  u=self.uid, r=self.mcp_review(TOP))
        self.client.set_human_verdict(self.uid, self.pid, "mid", "confirmed", combine=combine_props)

        self.assertEqual(set(self.rows(decided_by="person")), {"mid"})
        self.assertEqual(set(self.rows(reviewed_via="mcp")), {"top"})
        self.assertEqual(set(self.rows(review_current="current")), {"top"})
        self.assertEqual(self.client.count_triage_findings(self.uid, self.pid, decided_by="person"), 1)

        facets = self.client.triage_facets(self.uid, self.pid)
        self.assertEqual(facets["total"], 2)
        self.assertEqual(facets["decided_by"]["person"], 1)
        self.assertEqual(facets["reviewed_via"]["mcp"], 1)
        self.assertEqual(facets["decided_via"]["app"], 1)
        self.assertEqual(sum(facets["tiers"].values()), 2)

        detail = self.client.get_triage_detail(self.uid, self.pid, "mid")
        self.assertTrue(detail["found"])
        self.assertEqual(detail["row"]["decided_via"], "app")
        self.assertFalse(detail["row"]["proven_now"])
        self.assertEqual({m["id"] for m in detail["group"]}, {"top", "mid"})
        self.assertEqual(self.client.get_triage_detail(self.uid, self.pid, "nope"), {"found": False})

        pre = self.client.triage_preflight(self.uid, self.pid)
        self.assertEqual((pre["in_scope"], pre["reviews_kept"], pre["external_reviews"]), (2, 1, 1))

    # -- the review -----------------------------------------------------------
    def test_a_finding_proven_after_the_run_cannot_be_talked_down(self):
        """C8: a CONFIRMS edge written after the run, read live in the write."""
        from cypherfix_triage.finding_ops import submit_review
        self.publish(self.row(MID))
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'mid', user_id:$u, project_id:$p}) "
                  "CREATE (:ChainFinding {id:$c, user_id:$u, project_id:$p, "
                  "                       finding_type:'exploit_success'})-[:CONFIRMS]->(v)",
                  u=self.uid, p=self.pid, c=f"cf-{self.pid}")
        digest = self.props("mid")["triage_evidence_hash"]
        with unittest.mock.patch("cypherfix_triage.finding_ops.read_finding_row",
                                 lambda *a, **k: dict(MID, seen_updated_at=None)):
            out = submit_review(self.client, self.uid, self.pid, "mid", None,
                                {"verdict": "doubtful", "evidence_quote": "Finding: Old banner"},
                                digest, "rdmn_mcp_0a1b2c3d")
        self.assertEqual(out["reason"], "proven")
        self.assertNotIn("triage_ai_verdict", self.props("mid"))

    def test_proof_on_the_host_is_not_proof_of_the_finding(self):
        """`triage_proof` records proof on the HOST; a rescore must not read it as T1."""
        from cypherfix_triage.layers import combine_props
        self.publish(self.row(MID))
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id:'mid', user_id:$u, project_id:$p}) "
                  "SET v.triage_proof = 'cf-elsewhere-on-this-host'", u=self.uid, p=self.pid)
        out = self.client.set_human_verdict(self.uid, self.pid, "mid", "confirmed", "seen it",
                                            combine=combine_props)
        self.assertTrue(out["rescored"])
        row = self.rows()["mid"]
        self.assertNotEqual(row["triage_tier_rule"], "proven")
        self.assertNotEqual(row["triage_tier"], "T1")


import unittest.mock  # noqa: E402  (used by the review test above)

if __name__ == "__main__":
    unittest.main()
