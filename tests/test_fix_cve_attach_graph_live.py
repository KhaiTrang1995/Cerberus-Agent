"""LIVE-Neo4j: a CVE lands on its own product and version, not on lookalikes.

The CVE-to-Technology link (vuln_mixin.update_graph_from_vuln_scan) matched
the product as a SUBSTRING, then fell back to ignoring the version, so php
CVEs landed on phpMyAdmin and one OpenSSH version's CVEs on every other. The
fix matches the name with a regex (`toLower(t.name) =~ $tech_name_regex`) and
the fallback version with another. Both regexes are built in Python and run
by Neo4j's JAVA regex engine; the unit tests evaluate them in Python only.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_cve_attach_graph_live.py -v

Everything it creates is scoped to a throwaway tenant, plus two CVE reference
nodes with a throwaway id; all are deleted in tearDown.
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

#: (name, version) as the writers store them: nmap names carry "/version".
TECHNOLOGIES = [
    ("PHP/7.4.3", "7.4.3"),
    ("phpMyAdmin", "7.4.3"),       # same version: substring + version matched it
    ("PHP", "8.1.2"),
    ("PHP/8.1.2", "8.1.2"),
    ("OpenSSH/8.2p1", "8.2p1"),    # 8.2 in nmap's spelling: the fallback keeps it
    ("OpenSSH/9.6p1", "9.6p1"),    # another version: the fallback used to take it
]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveCveAttachCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"cveat-{run}"
        self.pid = f"CVEAT_{run}"
        self.php_cve = f"CVE-1999-{int(run, 16) % 100000:05d}1"
        self.ssh_cve = f"CVE-1999-{int(run, 16) % 100000:05d}2"
        with self.client.driver.session() as s:
            for name, version in TECHNOLOGIES:
                s.run("CREATE (:Technology {name: $n, version: $v, user_id: $u, project_id: $p})",
                      n=name, v=version, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
            s.run("MATCH (c:CVE) WHERE c.id IN [$a, $b] DETACH DELETE c",
                  a=self.php_cve, b=self.ssh_cve)

    def _ingest(self, tech_key, product, version, cve_id):
        recon = {
            "vuln_scan": {"scan_metadata": {"scanner": "live-test"}},
            "technology_cves": {"by_technology": {tech_key: {
                "product": product, "version": version,
                "cves": [{"id": cve_id, "cvss": 9.8, "severity": "CRITICAL"}],
            }}},
        }
        self.client.update_graph_from_vuln_scan(recon, self.uid, self.pid)

    def _linked(self, cve_id):
        with self.client.driver.session() as s:
            return {r["name"] for r in s.run(
                "MATCH (t:Technology {user_id: $u, project_id: $p})-[:HAS_KNOWN_CVE]->"
                "(:CVE {id: $c}) RETURN t.name AS name",
                u=self.uid, p=self.pid, c=cve_id)}

    def test_a_php_cve_lands_only_on_php_of_that_version(self):
        self._ingest("PHP:7.4.3", "php", "7.4.3", self.php_cve)
        self.assertEqual(self._linked(self.php_cve), {"PHP/7.4.3"})

    def test_the_version_fallback_keeps_the_spelling_and_drops_other_versions(self):
        self._ingest("OpenSSH:8.2", "openssh", "8.2", self.ssh_cve)
        self.assertEqual(self._linked(self.ssh_cve), {"OpenSSH/8.2p1"})


if __name__ == "__main__":
    unittest.main()
