"""LIVE-Neo4j: the GVM prune keeps a failed target's findings and prunes the rest.

A GVM target that failed this run was not re-checked, so the run passes it to
prune_unseen_findings as keep_hosts. GVM findings carry their host only as
`target_ip` / `target_hostname`, which _KEEP_HOST_FIELDS gained for this; the
match itself is a regex over those properties in Cypher, which the unit tests
never execute.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_gvm_prune_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
import time
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

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

#: (finding id, target_ip, target_hostname) from a PREVIOUS run.
PREVIOUS = [
    ("failed-ip", "10.79.0.1", None),           # this run's target 10.79.0.1 failed
    ("failed-host", None, "mail.gvmprune.test"),  # so did this hostname target
    ("scanned", "10.79.0.2", None),             # scanned clean: the finding is gone
]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveGvmPruneCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"gvmpr-{run}"
        self.pid = f"GVMPR_{run}"
        with self.client.driver.session() as s:
            for vid, ip, host in PREVIOUS:
                s.run(
                    """
                    CREATE (v:Vulnerability {id: $id, user_id: $u, project_id: $p, source: 'gvm',
                                             updated_at: datetime() - duration('PT1H')})
                    SET v.target_ip = $ip, v.target_hostname = $host
                    """, id=vid, ip=ip, host=host, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)

    def _ids(self):
        with self.client.driver.session() as s:
            return {r["id"] for r in s.run(
                "MATCH (v:Vulnerability {user_id: $u, project_id: $p}) RETURN v.id AS id",
                u=self.uid, p=self.pid)}

    def test_failed_targets_keep_their_findings_and_a_scanned_one_is_pruned(self):
        from graph_db.mixins.base_mixin import run_timestamp

        since = run_timestamp()
        time.sleep(0.05)
        self.client.prune_unseen_findings(self.uid, self.pid, ["gvm"], since,
                                          keep_hosts=["10.79.0.1", "mail.gvmprune.test"])
        self.assertEqual(self._ids(), {"failed-ip", "failed-host"})


if __name__ == "__main__":
    unittest.main()
