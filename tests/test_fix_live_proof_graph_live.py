"""LIVE-Neo4j: a person's verdict cannot lift a validated public client key to T1.

`_LIVE_PROOF` (triage_mixin) is read inside every verdict, review and publish
transaction. Its validated arm now carries a `NONE(...)` list predicate that
excludes public-by-design keys, mirroring score_model.is_proven. A Cypher
Neo4j rejects would fail EVERY single-finding triage write, and a predicate
that drifted from the model would put an AIza Maps key back at T1 "proven" on
the next "Real" click. The unit tests only read the query text; this runs it.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_live_proof_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic"), os.path.join(_REPO, "tests")):
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

#: A Google browser key a validator reached the Geocoding API with, and a
#: Stripe SECRET key validated the same way: the contrast that proves the
#: proof arm still proves real credentials.
SECRETS = {
    "gcp": {"secret_type": "GCP API Key", "key_type": "cloud"},
    "stripe": {"secret_type": "Stripe Secret Key", "key_type": "payment"},
}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveProofPublicKeyCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"lproof-{run}"
        self.pid = f"LPROOF_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            for sid, props in SECRETS.items():
                s.run(
                    """
                    CREATE (x:Secret {id: $id, user_id: $u, project_id: $p,
                                      source: 'js_recon', severity: 'critical',
                                      validation_status: 'validated',
                                      base_url: 'https://app.lproof.test',
                                      updated_at: datetime()})
                    SET x += $props
                    """, id=sid, u=self.uid, p=self.pid, props=props)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
        self.driver.close()

    def _publish_base(self):
        """Score the rows exactly as a run reads them, and publish the base layer."""
        from cypherfix_triage.fact_queries import FINDING_QUERIES, normalise_finding_row
        from triage_layers_live_support import PUBLISH_COMBINE, layer_row

        query = next(q for q in FINDING_QUERIES if q["name"] == "secrets")["query"]
        with self.driver.session() as s:
            findings = [normalise_finding_row(dict(r))
                        for r in s.run(query, userId=self.uid, projectId=self.pid)]
        self.assertEqual({f["id"] for f in findings}, set(SECRETS))
        out = self.client.publish_triage_layers(
            self.uid, self.pid, [layer_row(f) for f in findings], PUBLISH_COMBINE,
            guard_updated_at=False)
        self.assertFalse(out.get("errors"), out)

    def _tier(self, sid):
        with self.driver.session() as s:
            return s.run("MATCH (x:Secret {id: $id, user_id: $u, project_id: $p}) "
                         "RETURN x.triage_tier AS tier",
                         id=sid, u=self.uid, p=self.pid).single()["tier"]

    def test_real_on_a_validated_public_key_writes_and_stays_below_t1(self):
        from cypherfix_triage.layers import combine_props

        self._publish_base()
        out = self.client.set_human_verdict(self.uid, self.pid, "gcp", "confirmed",
                                            combine=combine_props)
        self.assertTrue(out.get("updated"), out)
        self.assertNotEqual(self._tier("gcp"), "T1")

    def test_real_on_a_validated_secret_key_is_still_proven(self):
        from cypherfix_triage.layers import combine_props

        self._publish_base()
        out = self.client.set_human_verdict(self.uid, self.pid, "stripe", "confirmed",
                                            combine=combine_props)
        self.assertTrue(out.get("updated"), out)
        self.assertEqual(self._tier("stripe"), "T1")


if __name__ == "__main__":
    unittest.main()
