"""LIVE-Neo4j: an open port only nmap confirmed becomes one linked Port node.

nmap probes every IP with the union of all IPs' ports, so it can confirm a
port the port scan missed. merge_nmap_into_port_scan lists those under
nmap_scan.new_open_ports, and update_graph_from_nmap now creates the Port
(source "nmap"), its IP -[:HAS_PORT]-> link and its Service. Before, the
writer only MATCHed existing ports and the confirmed port was lost. A second
ingest of the same run must not duplicate anything.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_nmap_ports_graph_live.py -v

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

IP = "10.78.0.1"
PORT = 8443


def _nmap_scan():
    detail = {"port": PORT, "protocol": "tcp", "state": "open", "service": "https-alt",
              "product": "nginx", "version": "1.18.0", "cpe": ""}
    return {
        "by_host": {IP: {"ip": IP, "hostnames": [], "ports": [PORT], "port_details": [detail]}},
        "services_detected": [{"product": "nginx", "version": "1.18.0", "port": PORT,
                               "host": IP, "ip": IP, "cpe": ""}],
        "nse_vulns": [],
        "new_open_ports": [{"ip": IP, "port": PORT, "protocol": "tcp", "service": "https-alt"}],
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveNmapPortsCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"nmapp-{run}"
        self.pid = f"NMAPP_{run}"
        with self.client.driver.session() as s:
            s.run("CREATE (:IP {address: $a, user_id: $u, project_id: $p})",
                  a=IP, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)

    def test_a_confirmed_port_is_one_linked_port_with_its_service(self):
        for _ in range(2):  # a re-ingest must converge, not duplicate
            stats = self.client.update_graph_from_nmap({"nmap_scan": _nmap_scan()},
                                                       self.uid, self.pid)
            self.assertFalse(stats.get("errors"), stats)
        with self.client.driver.session() as s:
            rows = [dict(r) for r in s.run(
                """
                MATCH (p:Port {number: $port, ip_address: $ip, user_id: $u, project_id: $p})
                OPTIONAL MATCH (i:IP {user_id: $u, project_id: $p})-[:HAS_PORT]->(p)
                OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(svc:Service {user_id: $u, project_id: $p})
                RETURN p.source AS source, p.state AS state, p.product AS product,
                       collect(DISTINCT i.address) AS ips, collect(DISTINCT svc.name) AS services
                """, port=PORT, ip=IP, u=self.uid, p=self.pid)]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["source"], "nmap")
        self.assertEqual(row["state"], "open")
        self.assertEqual(row["ips"], [IP])
        self.assertEqual(row["services"], ["https-alt"])
        self.assertEqual(row["product"], "nginx")


if __name__ == "__main__":
    unittest.main()
