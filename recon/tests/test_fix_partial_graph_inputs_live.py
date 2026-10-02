"""LIVE-Neo4j: partial recon reads technologies and open ports back from the graph.

Partial Nuclei rebuilds the full pipeline's http_probe "technologies" strings
from the graph (_URL_TECHNOLOGIES: a 0..1-hop USES_TECHNOLOGY path filtered on
the edge's detected_by), and the partial security checks load each IP's open
ports (graph_open_ports). The unit tests feed both from fake sessions; here the
graph is written by the REAL httpx writer and read back by the real queries.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-recon python -m pytest tests/test_fix_partial_graph_inputs_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
import unittest
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

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

URL = "https://www.pgi.test"
IP = "10.80.0.1"
TECHNOLOGIES = ["Nginx:1.18.0", "PHP"]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LivePartialGraphInputsCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"pgi-{run}"
        self.pid = f"PGI_{run}"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)

    def test_url_technologies_round_trip_from_the_httpx_writer(self):
        from recon.partial_recon_modules.graph_builders import _graph_url_technologies

        recon = {"http_probe": {"by_url": {URL: {
            "url": URL, "host": "www.pgi.test", "status_code": 200,
            "content_type": "text/html", "technologies": TECHNOLOGIES,
        }}}}
        stats = self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        self.assertFalse(stats.get("errors"), stats)
        with self.client.driver.session() as s:
            got = _graph_url_technologies(s, self.uid, self.pid)
        self.assertEqual(list(got), [URL])
        self.assertEqual(sorted(got[URL]), sorted(TECHNOLOGIES))

    def test_graph_open_ports_returns_the_open_ports_written(self):
        from recon.partial_recon_modules.graph_builders import graph_open_ports

        with self.client.driver.session() as s:
            for number, state in ((6379, "open"), (22, "open"), (25, "closed")):
                s.run("CREATE (:Port {number: $n, protocol: 'tcp', state: $st, ip_address: $ip, "
                      "user_id: $u, project_id: $p})",
                      n=number, st=state, ip=IP, u=self.uid, p=self.pid)
        self.assertEqual(graph_open_ports([IP], self.uid, self.pid), {IP: [22, 6379]})


if __name__ == "__main__":
    unittest.main()
