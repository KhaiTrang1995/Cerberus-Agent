"""Live: MCP mute_findings / unmute_findings end to end, over the real server.

What only the running stack can show, one flow:

  - a mute by Node ID sent as a JSON NUMBER (what query_graph returns) lands,
    and search_muted_findings lists it as the agent's (`mutedVia: mcp`, this
    token's prefix);
  - unmute_findings then clears the provenance from the node
    (`muted_channel` / `muted_token`), and KEEPS the Mute Rules exemption it
    wrote, the row that stops a rule from hiding the finding again.

The finding is a synthetic Vulnerability this test creates in the project and
deletes afterwards, with its exemption. Never a real finding.

Skipped unless every prerequisite is set:
  MCP_MUTE_LIVE_TOKEN    a token with triage:mute and triage:read (the
                         deployment's MCP_SERVER_TOKEN usually lacks triage:mute)
  MCP_MUTE_LIVE_PROJECT  a project the token's owner owns
  MCP_MUTE_LIVE_URL      default http://webapp:3000/api/mcp-server
  NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD, DATABASE_URL

To run it on the stack's network:
  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://redamon-neo4j:7687 -e NEO4J_USER \\
    -e NEO4J_PASSWORD -e DATABASE_URL -e MCP_MUTE_LIVE_TOKEN -e MCP_MUTE_LIVE_PROJECT \\
    --entrypoint python redamon-agent -m pytest -m live tests/test_mcp_mute_live.py
"""

import json
import os
import unittest
import uuid

_URL = os.getenv("MCP_MUTE_LIVE_URL", "http://webapp:3000/api/mcp-server")
_TOKEN = os.getenv("MCP_MUTE_LIVE_TOKEN", "")
_PROJECT = os.getenv("MCP_MUTE_LIVE_PROJECT", "")
_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
_DATABASE_URL = os.getenv("DATABASE_URL", "")


def _missing():
    for name, value in (("MCP_MUTE_LIVE_TOKEN", _TOKEN), ("MCP_MUTE_LIVE_PROJECT", _PROJECT),
                        ("NEO4J_PASSWORD", _NEO4J_PASSWORD), ("DATABASE_URL", _DATABASE_URL)):
        if not value:
            return f"{name} not set"
    try:
        import httpx  # noqa: F401
        import neo4j  # noqa: F401
        import psycopg  # noqa: F401
    except ImportError as e:
        return f"{e.name} not importable"
    return None


class McpMuteLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = _missing()
        if reason:
            raise unittest.SkipTest(reason)
        import httpx
        import neo4j
        import psycopg
        try:
            cls.driver = neo4j.GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD))
            cls.driver.verify_connectivity()
            cls.pg = psycopg.connect(_DATABASE_URL, autocommit=True)
            cls.http = httpx.Client(timeout=120)
            cls.http.post(_URL, json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                          headers=cls._headers())
        except Exception as e:  # noqa: BLE001 - any unreachable service is a skip
            raise unittest.SkipTest(f"stack unreachable: {e}")
        row = cls.pg.execute("select user_id from projects where id = %s", (_PROJECT,)).fetchone()
        if not row:
            raise unittest.SkipTest(f"project {_PROJECT} not found")
        cls.owner = row[0]
        cls.prefix = _TOKEN[:17]

    @classmethod
    def tearDownClass(cls):
        for name in ("http", "pg", "driver"):
            if hasattr(cls, name):
                getattr(cls, name).close()

    @staticmethod
    def _headers():
        return {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {_TOKEN}"}

    def call(self, tool, args):
        resp = self.http.post(_URL, headers=self._headers(), json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        raw = resp.text
        data = next((json.loads(l[6:]) for l in raw.splitlines() if l.startswith("data: ")), None) \
            or json.loads(raw)
        result = data["result"]
        text = "\n".join(c.get("text", "") for c in result.get("content", []))
        self.assertFalse(result.get("isError"), f"{tool}: {text[:300]}")
        return json.loads(text)

    def node(self, key):
        with self.driver.session() as s:
            return s.run(
                "MATCH (n:Vulnerability {id: $key, project_id: $pid}) "
                "RETURN n:Muted AS muted, n.muted_channel AS channel, n.muted_token AS token",
                key=key, pid=_PROJECT).single()

    def setUp(self):
        self.key = f"mcp-mute-live-{uuid.uuid4().hex[:12]}"
        with self.driver.session() as s:
            self.gid = s.run(
                "CREATE (n:Vulnerability {id: $key, user_id: $uid, project_id: $pid, name: $key, "
                "severity: 'info', source: 'mcp_mute_live'}) RETURN id(n) AS gid",
                key=self.key, uid=self.owner, pid=_PROJECT).single()["gid"]
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        with self.driver.session() as s:
            s.run("MATCH (n:Vulnerability {id: $key, project_id: $pid}) DETACH DELETE n",
                  key=self.key, pid=_PROJECT)
        self.pg.execute("delete from node_filter_exemptions where project_id = %s and node_key = %s",
                        (_PROJECT, self.key))

    def test_a_node_id_mute_is_listed_as_mcp_and_its_unmute_clears_provenance_and_keeps_the_exemption(self):
        muted = self.call("mute_findings", {
            "projectId": _PROJECT, "nodeIds": [self.gid], "reason": "live test: synthetic finding"})
        self.assertEqual([m["findingId"] for m in muted["muted"]], [self.key])

        listed = self.call("search_muted_findings", {
            "projectId": _PROJECT, "mutedVia": "mcp", "search": self.key})
        rows = [r for r in listed["findings"] if r.get("id") == self.key]
        self.assertEqual(len(rows), 1, listed)
        self.assertEqual(rows[0]["mutedVia"], "mcp")
        self.assertEqual(rows[0]["mutedByToken"], self.prefix)

        unmuted = self.call("unmute_findings", {"projectId": _PROJECT, "nodeIds": [self.gid]})
        self.assertEqual([u["findingId"] for u in unmuted["unmuted"]], [self.key])

        node = self.node(self.key)
        self.assertEqual((node["muted"], node["channel"], node["token"]), (False, None, None))
        exemptions = self.pg.execute(
            "select label from node_filter_exemptions where project_id = %s and node_key = %s",
            (_PROJECT, self.key)).fetchall()
        self.assertEqual(exemptions, [("Vulnerability",)])


if __name__ == "__main__":
    unittest.main()
