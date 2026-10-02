"""LIVE-Neo4j: port/service security-check findings are one per IP, each on its IP.

redis_no_auth, database_exposed, admin_port_exposed and smtp_open_relay report
the host only as `ip`, with no url, hostname or matched_ip. Keyed on those
alone every IP's finding of a type hashed to ONE Vulnerability with no
relationship. The writer now keys them on ip:port and links them from their IP
node; this proves the MERGE and the link against a real database.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_port_findings_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
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

IPS = ("10.77.0.1", "10.77.0.2")


def _redis(ip):
    return {"type": "redis_no_auth", "severity": "critical",
            "name": "Redis Without Authentication", "ip": ip, "port": 6379,
            "service": "redis", "evidence": "PING answered +PONG without AUTH"}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LivePortFindingsCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"portf-{run}"
        self.pid = f"PORTF_{run}"
        with self.client.driver.session() as s:
            for ip in IPS:
                s.run("CREATE (:IP {address: $a, user_id: $u, project_id: $p})",
                      a=ip, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)

    def test_each_ip_gets_its_own_finding_linked_from_it(self):
        recon = {"vuln_scan": {"security_checks": {"findings": [_redis(ip) for ip in IPS]}}}
        stats = self.client.update_graph_from_vuln_scan(recon, self.uid, self.pid)
        self.assertFalse(stats.get("errors"), stats)
        with self.client.driver.session() as s:
            rows = [dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {user_id: $u, project_id: $p, type: 'redis_no_auth'})
                OPTIONAL MATCH (i:IP {user_id: $u, project_id: $p})-[:HAS_VULNERABILITY]->(v)
                RETURN v.id AS id, v.matched_ip AS matched_ip, collect(i.address) AS from_ips
                """, u=self.uid, p=self.pid)]
        self.assertEqual(len(rows), 2, rows)
        self.assertEqual(len({r["id"] for r in rows}), 2, rows)
        for row in rows:
            self.assertEqual(row["from_ips"], [row["matched_ip"]], row)
        self.assertEqual({r["matched_ip"] for r in rows}, set(IPS))


if __name__ == "__main__":
    unittest.main()
