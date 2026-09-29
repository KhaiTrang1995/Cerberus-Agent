"""The single-finding ops behind the Priority Board's detail and MCP reviews.

`finding_evidence` is what an external reviewer reads; `submit_review` decides,
under the node's lock, whether that reviewer's review may be written. Every
refusal of plan section 3.12 is pinned here against a fake mixin that runs the
real `decide` and `combine` callbacks the way `write_review` does.

Run: ./agentic/run_tests.sh tests/test_triage_finding_ops.py
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import evidence, finding_ops, score_model as sm  # noqa: E402

ROW = {"id": "v1", "label": "Vulnerability", "source": "nuclei", "name": "Exposed .env",
       "template_id": "env-file",
       "raw_response": "HTTP/1.1 200 OK\nDate: Tue, 29 Sep 2026 10:00:00 GMT\n\n"
                       "<!doctype html><html>Welcome to Example</html>",
       "seen_updated_at": "2026-09-29T10:00:00Z"}
BUNDLE = evidence.build_bundle(ROW)
DIGEST = evidence.bundle_hash(BUNDLE)


def base_props(**extra):
    result = sm.score({**ROW, "matcher_status": True}, sm.ProjectFacts(live_hosts={""}))
    base = sm.BaseLayer.from_result(result)
    props = {
        "triage_run_id": "run-1",
        "triage_base_factors": json.dumps(base.factors),
        "triage_base_tier": base.tier, "triage_base_tier_rule": base.tier_rule,
        "triage_base_state": base.state,
        "triage_tier_inputs": json.dumps(base.inputs.as_dict()),
        "triage_math_score": base.score,
        "triage_evidence_hash": DIGEST,
        "triage_status": "unreviewed",
    }
    props.update(extra)
    return props


class FakeClient:
    """Runs decide/combine exactly where the mixin's transaction would."""
    driver = None

    def __init__(self, props, proven_now=False, updated_at=ROW["seen_updated_at"],
                 found=True, ambiguous=None):
        self.props = props
        self.proven_now = proven_now
        self.updated_at = updated_at
        self.found = found
        self.ambiguous = ambiguous
        self.written = None

    def get_triage_detail(self, user_id, project_id, node_id, label=None):
        if self.ambiguous:
            return {"found": False, "ambiguous": self.ambiguous}
        if not self.found:
            return {"found": False}
        return {"found": True, "row": {"id": node_id, "label": "Vulnerability",
                                       "source": "nuclei", "proven_now": self.proven_now,
                                       **self.props}}

    def write_review(self, user_id, project_id, node_id, decide, combine, label=None):
        outcome = decide(dict(self.props), self.proven_now, self.updated_at, label)
        if outcome.get("refused"):
            return {"written": False, "reason": outcome["refused"], "label": label}
        merged = {**self.props, **outcome["review"]}
        self.written = outcome["review"]
        return {"written": True, "label": label, "final": combine(merged, self.proven_now),
                "dropped": outcome.get("dropped") or []}


def submit(client, item=None, digest=DIGEST, finding=ROW):
    item = item if item is not None else {
        "verdict": "false_positive", "evidence_quote": "Welcome to Example",
        "why": "the homepage", "fix_lever": "nothing to fix"}
    with mock.patch.object(finding_ops, "read_finding_row", lambda *a, **k: finding):
        return finding_ops.submit_review(client, "u1", "p1", "v1", None, item, digest,
                                         "rdmn_mcp_0a1b2c3d")


class TestSubmitReviewRefusals(unittest.TestCase):
    def test_a_person_s_decision_is_never_reviewed_over(self):
        for status in ("confirmed", "likely_noise"):
            client = FakeClient(base_props(triage_status=status, triage_source="human"))
            self.assertEqual(submit(client)["reason"], "decided_by_person")
            self.assertIsNone(client.written)

    def test_a_finding_never_scored_cannot_be_reviewed(self):
        client = FakeClient({"triage_status": "unreviewed"})
        self.assertEqual(submit(client)["reason"], "not_scored")

    def test_a_resolved_finding_cannot_be_reviewed(self):
        client = FakeClient(base_props(triage_base_state="fixed"))
        self.assertEqual(submit(client)["reason"], "not_open")

    def test_a_skipped_source_cannot_be_reviewed(self):
        finding = {**ROW, "source": "osv"}
        client = FakeClient(base_props())
        self.assertEqual(submit(client, finding=finding)["reason"], "source_not_reviewed")

    def test_a_finding_outside_triage_scope_is_named_so(self):
        client = FakeClient(base_props())
        self.assertEqual(submit(client, finding=None)["reason"], "out_of_triage_scope")

    def test_a_stale_evidence_hash_is_refused(self):
        client = FakeClient(base_props())
        self.assertEqual(submit(client, digest="0" * 40)["reason"], "evidence_changed")

    def test_evidence_that_moved_since_the_last_run_is_refused(self):
        client = FakeClient(base_props(triage_evidence_hash="f" * 40))
        self.assertEqual(submit(client)["reason"], "evidence_changed")

    def test_a_scan_that_rewrote_the_node_meanwhile_is_refused(self):
        client = FakeClient(base_props(), updated_at="2026-09-30T00:00:00Z")
        self.assertEqual(submit(client)["reason"], "evidence_changed")

    def test_a_finding_proven_after_the_run_cannot_be_talked_down(self):
        """C8: proof read live in the write transaction."""
        client = FakeClient(base_props(), proven_now=True)
        self.assertEqual(submit(client)["reason"], "proven")

    def test_a_proven_finding_may_still_be_confirmed(self):
        client = FakeClient(base_props(), proven_now=True)
        result = submit(client, {"verdict": "real", "evidence_quote": "Welcome to Example"})
        self.assertTrue(result["written"])

    def test_not_found_and_ambiguous(self):
        self.assertEqual(submit(FakeClient({}, found=False))["reason"], "not_found")
        result = submit(FakeClient({}, ambiguous=["Secret", "Vulnerability"]))
        self.assertEqual((result["reason"], result["labels"]),
                         ("ambiguous", ["Secret", "Vulnerability"]))


class TestSubmitReviewAccepted(unittest.TestCase):
    def test_the_review_is_stamped_as_an_external_agent_s(self):
        client = FakeClient(base_props())
        result = submit(client)
        self.assertTrue(result["written"])
        written = client.written
        self.assertEqual(written["triage_ai_channel"], "mcp")
        self.assertEqual(written["triage_ai_by"], "rdmn_mcp_0a1b2c3d")
        self.assertEqual(written["triage_ai_evidence_hash"], DIGEST)
        self.assertIsNone(written["triage_ai_model"])
        self.assertEqual(result["accepted"]["verdict"], "false_positive")
        self.assertEqual(result["final"]["state"], "false_positive")
        self.assertEqual(result["final"]["decided_by"], "review")
        self.assertIn("external agent", result["final"]["tier_rule"])

    def test_an_invented_quote_is_dropped_and_changes_nothing(self):
        client = FakeClient(base_props())
        result = submit(client, {"verdict": "false_positive",
                                 "evidence_quote": "the server said 404 not found"})
        self.assertTrue(result["written"])
        self.assertEqual(client.written["triage_ai_verdict"], "unclear")
        self.assertTrue(result["dropped"])
        self.assertEqual(result["final"]["decided_by"], "rules")

    def test_a_trufflehog_review_is_flagged_as_not_surviving_a_rescan(self):
        client = FakeClient(base_props())
        finding = {**ROW, "source": "trufflehog", "label": "MultiscannerFinding"}
        client.get_triage_detail = lambda *a, **k: {
            "found": True, "row": {"id": "v1", "label": "MultiscannerFinding",
                                   "source": "trufflehog", **client.props}}
        with mock.patch.object(finding_ops, "read_finding_row", lambda *a, **k: finding):
            bundle = evidence.build_bundle(finding)
            client.props["triage_evidence_hash"] = evidence.bundle_hash(bundle)
            result = finding_ops.submit_review(
                client, "u1", "p1", "v1", None,
                {"verdict": "unclear"}, evidence.bundle_hash(bundle), "rdmn_mcp_0a1b2c3d")
        self.assertFalse(result["review_survives_rescan"])


class TestFindingEvidence(unittest.TestCase):
    def _evidence(self, client, finding=ROW):
        with mock.patch.object(finding_ops, "read_finding_row", lambda *a, **k: finding):
            return finding_ops.finding_evidence(client, "u1", "p1", "v1")

    def test_it_is_the_redacted_bundle_with_its_hash(self):
        secret_row = {**ROW, "extracted_results": ["AKIAIOSFODNN7EXAMPLE"]}
        out = self._evidence(FakeClient(base_props()), secret_row)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out["evidence"])
        self.assertNotIn("Date: Tue", out["evidence"])
        self.assertEqual(out["evidence_hash"], evidence.bundle_hash(out["evidence"]))

    def test_it_says_whether_it_matches_the_last_run_and_is_reviewable(self):
        out = self._evidence(FakeClient(base_props()))
        self.assertTrue(out["matches_last_run"])
        self.assertTrue(out["reviewable"])
        self.assertIsNone(out["not_reviewable_because"])
        self.assertTrue(out["review_survives_rescan"])

    def test_the_contract_names_every_verdict_and_fact(self):
        contract = self._evidence(FakeClient(base_props()))["contract"]
        self.assertEqual(set(contract["verdicts"]), set(sm.REVIEW_VERDICTS))
        self.assertEqual(len(contract["disputable_facts"]), 8)
        self.assertEqual(contract["min_quote_length"], 8)

    def test_a_decided_finding_is_not_reviewable(self):
        out = self._evidence(FakeClient(base_props(triage_status="confirmed",
                                                   triage_source="human")))
        self.assertEqual(out["not_reviewable_because"], "decided_by_person")

    def test_the_current_review_is_reported_with_its_validity(self):
        props = base_props(triage_ai_verdict="doubtful", triage_ai_channel="mcp",
                           triage_ai_by="rdmn_mcp_0a1b2c3d", triage_ai_evidence_hash=DIGEST)
        current = self._evidence(FakeClient(props))["current_review"]
        self.assertEqual((current["verdict"], current["channel"], current["current"]),
                         ("doubtful", "mcp", True))


if __name__ == "__main__":
    unittest.main()
