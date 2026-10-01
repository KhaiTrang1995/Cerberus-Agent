"""_LIVE_PROOF must keep mirroring score_model.is_proven.

A person's verdict and an MCP review re-combine the finding with the proof read
live by `_LIVE_PROOF`. When is_proven stopped counting a validated public
client key (an AIza Maps key, a Stripe publishable key) as proof, the Cypher
twin had to stop too, or every such write lifted the key back to T1 "proven".

graph_db cannot import the agent's model, so the list is duplicated; these
tests pin the copies equal and the Cypher shape that uses it.

Run: python -m pytest tests/test_fix_triage_proof_mirror.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (_REPO, os.path.join(_REPO, "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

from graph_db.mixins.recon import triage_mixin  # noqa: E402
from cypherfix_triage import score_model as sm  # noqa: E402


class TestLiveProofMirrorsIsProven(unittest.TestCase):
    def test_the_public_key_lists_are_the_same(self):
        self.assertEqual(set(triage_mixin._PUBLIC_CLIENT_KEY_TYPES),
                         set(sm.PUBLIC_CLIENT_KEY_TYPES))

    def test_the_validated_arm_excludes_public_client_keys(self):
        proof = " ".join(triage_mixin._LIVE_PROOF.split())
        arm = re.search(r"\(toLower\(coalesce\(n\.validation_status, ''\)\) = 'validated'"
                        r" AND NONE\(name IN \[n\.secret_type, n\.key_type, n\.detector_name\]"
                        r" WHERE toLower\(coalesce\(name, ''\)\) IN \[(.*?)\]\)\)", proof)
        self.assertIsNotNone(arm, proof)
        listed = set(re.findall(r"'([^']+)'", arm.group(1)))
        self.assertEqual(listed, set(sm.PUBLIC_CLIENT_KEY_TYPES))

    def test_no_bare_validated_arm_is_left(self):
        # The old unconditional arm would still prove every validated public key.
        proof = " ".join(triage_mixin._LIVE_PROOF.split())
        self.assertNotIn("OR toLower(coalesce(n.validation_status, '')) = 'validated' OR", proof)

    def test_is_proven_agrees_for_each_name_property(self):
        facts = sm.ProjectFacts()
        for name in sorted(sm.PUBLIC_CLIENT_KEY_TYPES):
            for field in ("secret_type", "detector_name"):
                with self.subTest(name=name, field=field):
                    row = {"id": "x", "validation_status": "validated", field: name.upper()}
                    self.assertFalse(sm.is_proven(row, facts))
        self.assertTrue(sm.is_proven(
            {"id": "x", "validation_status": "validated", "secret_type": "Stripe Secret Key"},
            facts))


if __name__ == "__main__":
    unittest.main()
