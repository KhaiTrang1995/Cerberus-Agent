"""LIVE-Neo4j proof of Multi mute's graph side.

The unit tests pin the Cypher's shape against a stub driver. This runs it:

- the write-time ceiling ranks every severity exactly as the Python pool does,
  so the write never refuses what the suggestion offered, or lets through what
  it left out;
- the batch write refuses every guarded node on a real graph, and never moves
  `updated_at`;
- the Undo reverts its own batch only;
- the pool query runs for every label, returns a MalPackageFinding with no
  Package parent, and never another tenant's finding;
- a full 2,000-row pool is suggested on without stalling the event loop.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://redamon-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_multi_mute_graph_live.py -v

Everything it creates lives under two throwaway users, is synthetic
(example.com), and is deleted in tearDown.
"""

import asyncio
import os
import sys
import time
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (_REPO, os.path.join(_REPO, "agentic")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

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

BATCH_A = "mm-0000000a"
BATCH_B = "mm-0000000b"
FIXED = "2026-09-20T10:00:00Z"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveMultiMuteCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"mmlive-{run}"
        self.uid2 = f"mmlive2-{run}"
        self.pid = f"MMLIVE_{run}"
        self.pid2 = f"MMLIVE2_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$u, $u2] DETACH DELETE n",
                  u=self.uid, u2=self.uid2)
        self.driver.close()

    # --- helpers -------------------------------------------------------------

    def node(self, label, key, uid=None, pid=None, **props):
        key_prop = "finding_id" if label == "MalPackageFinding" else "id"
        with self.driver.session() as s:
            s.run(f"CREATE (n:{label}) SET n = $props, n.updated_at = datetime($fixed)",
                  props={key_prop: key, "user_id": uid or self.uid,
                         "project_id": pid or self.pid, **props},
                  fixed=FIXED)

    def props(self, label, key):
        with self.driver.session() as s:
            rec = s.run(f"MATCH (n:{label}) WHERE n.user_id = $u AND n.project_id = $p "
                        "AND (n.id = $k OR n.finding_id = $k) "
                        "RETURN n:Muted AS muted, properties(n) AS props",
                        u=self.uid, p=self.pid, k=key).single()
        return dict(rec["props"], _muted=rec["muted"]) if rec else None

    def batch(self, label, keys, ceiling, seed="", exempt=(), batch_id=BATCH_A, muted_by=None):
        out = self.client.mute_findings_batch(
            self.uid, self.pid, label, list(keys), seed_key=seed, ceiling=ceiling,
            exempt_pairs=[list(p) for p in exempt], muted_by=muted_by or self.uid,
            reason=f"Multi mute {batch_id} · test", batch_id=batch_id)
        return {i["key"]: i["outcome"] for i in out["items"]}

    @staticmethod
    def ceiling(rank, tier=None, validated=False, malicious=False, confirmed=False):
        return {"severity_rank": rank, "tier_rank": tier, "validated": validated,
                "malicious": malicious, "confirmed": confirmed}

    # --- strategy row 1 ------------------------------------------------------

    def test_the_write_ceiling_ranks_every_severity_as_the_python_pool_does(self):
        """Exact agreement, per case: muted at the Python rank, above it one lower."""
        from multi_mute import pool, queries
        from multi_mute.kind import resolve_kind

        cases = [
            ("Vulnerability", {"severity": "critical", "source": "nuclei"}),
            ("Vulnerability", {"severity": " High ", "source": "nuclei"}),
            ("Vulnerability", {"severity": "moderate", "source": "nuclei"}),
            ("Vulnerability", {"severity": "low", "source": "nuclei"}),
            ("Vulnerability", {"severity": "informational", "source": "nuclei"}),
            ("Vulnerability", {"severity": "none", "source": "nuclei"}),
            ("Vulnerability", {"severity": "9.8", "source": "nuclei"}),
            ("Vulnerability", {"severity": "7.0", "source": "nuclei"}),
            ("Vulnerability", {"severity": "4", "source": "nuclei"}),
            ("Vulnerability", {"severity": "0.5", "source": "nuclei"}),
            ("Vulnerability", {"severity": "0", "source": "nuclei"}),
            ("Vulnerability", {"severity": "95", "source": "nuclei"}),
            ("Vulnerability", {"severity": 7.5, "source": "nuclei"}),
            ("Vulnerability", {"severity": "7.5 (High)", "source": "nuclei"}),
            ("Vulnerability", {"severity": "n/a", "source": "nuclei"}),
            ("Vulnerability", {"source": "nuclei"}),
            ("Vulnerability", {"severity": "info", "source": "osv"}),
            ("Vulnerability", {"severity": "INFO", "source": " OSV "}),
            ("MalPackageFinding", {"severity": "info", "source_tool": "osv"}),
            ("MalPackageFinding", {"severity": "info"}),
            ("MalPackageFinding", {"severity": "info", "source_tool": "guarddog"}),
            ("MalPackageFinding", {"severity": "high", "source_tool": "osv"}),
            ("Secret", {"severity": "info", "source": "js_recon"}),
            # No severity at all: each label's board query supplies its own
            # default (JS low, packages high, ...), which the pool ranks.
            ("JsReconFinding", {"finding_type": "secret"}),
            ("MalPackageFinding", {"source_tool": "osv"}),
            ("Secret", {"source": "js_recon"}),
            ("MultiscannerFinding", {"source": "trufflehog"}),
            ("GithubSecret", {"secret_type": "aws"}),
            ("GithubSensitiveFile", {"secret_type": "env"}),
        ]
        mismatches = []
        for i, (label, props) in enumerate(cases):
            key = f"sev-{i}"
            self.node(label, key, name=f"case {i}", **props)
            located = queries.locate_seed(self.driver, self.uid, self.pid, key)
            kind = resolve_kind(label, located["props"])
            row = queries.read_seed(self.driver, self.uid, self.pid, key, kind)
            rank = pool.severity_rank(row)

            at_rank = self.batch(label, [key], self.ceiling(rank))
            self.client.unmute_findings(self.uid, self.pid, [key], only_batch=BATCH_A)
            below = self.batch(label, [key], self.ceiling(rank - 1))
            self.client.unmute_findings(self.uid, self.pid, [key], only_batch=BATCH_A)
            if at_rank.get(key) != "muted" or below.get(key) != "above_seed":
                mismatches.append((label, props, rank, at_rank.get(key), below.get(key)))
        self.assertEqual(mismatches, [], "Cypher and Python rank these differently")

    # --- strategy row 4 ------------------------------------------------------

    def test_the_pool_reads_every_label_and_never_another_tenant(self):
        from multi_mute import POOL_LABELS, pool, queries
        from multi_mute.kind import resolve_kind

        base = {
            "Vulnerability": {"source": "nuclei", "severity": "low", "template_id": "t1",
                              "raw_response": "HTTP/1.1 200 OK\r\nServer: nginx\r\n"},
            "JsReconFinding": {"finding_type": "secret", "severity": "low", "evidence": "x"},
            "Secret": {"source": "js_recon", "severity": "low", "secret_type": "aws"},
            "MultiscannerFinding": {"source": "trufflehog", "severity": "low",
                                    "detector_name": "AWS"},
            "GithubSecret": {"severity": "low", "secret_type": "aws", "repository": "acme/app"},
            "GithubSensitiveFile": {"severity": "low", "secret_type": "env", "path": ".env"},
            "MalPackageFinding": {"severity": "low", "source_tool": "osv", "title": "evil"},
        }
        problems = []
        for label in POOL_LABELS:
            props = base[label]
            self.node(label, f"{label}-seed", name="seed", **props)
            self.node(label, f"{label}-mine", name="mine", **props)
            self.node(label, f"{label}-other-project", pid=self.pid2, name="leak", **props)
            self.node(label, f"{label}-other-user", uid=self.uid2, name="leak", **props)
            try:
                located = queries.locate_seed(self.driver, self.uid, self.pid, f"{label}-seed")
                kind = resolve_kind(label, located["props"])
                seed = queries.read_seed(self.driver, self.uid, self.pid, f"{label}-seed", kind)
                rows = queries.read_pool(self.driver, self.uid, self.pid, kind, seed,
                                         pool.severity_rank(seed))
                counts = queries.read_counts(self.driver, self.uid, self.pid, kind)
            except Exception as exc:  # noqa: BLE001
                problems.append(f"{label}: {exc.__class__.__name__}: {exc}")
                continue
            keys = {r["key"] for r in rows}
            if f"{label}-mine" not in keys:
                problems.append(f"{label}: own candidate missing from {sorted(keys)}")
            if keys & {f"{label}-other-project", f"{label}-other-user"}:
                problems.append(f"{label}: another tenant's finding leaked")
            if counts["live"] != 2:
                problems.append(f"{label}: live count {counts['live']} != 2")
        self.assertEqual(problems, [])

    # --- strategy row 2 ------------------------------------------------------

    def test_the_batch_write_refuses_every_guarded_node(self):
        vuln = {"source": "nuclei", "severity": "low"}
        self.node("Vulnerability", "v-ok", **vuln)
        self.node("Vulnerability", "v-proven", triage_status="confirmed", **vuln)
        self.node("Vulnerability", "v-chain", **vuln)
        self.node("Vulnerability", "v-exempt", **vuln)
        self.node("Vulnerability", "v-stale", stale_since="2026-09-01T00:00:00Z", **vuln)
        self.node("Vulnerability", "v-above", source="nuclei", severity="high")
        self.node("Vulnerability", "v-validated", validation_status="validated", **vuln)
        self.node("Vulnerability", "v-already", **vuln)
        self.node("Vulnerability", "v-seed", source="nuclei", severity="critical",
                  triage_status="confirmed")
        self.node("JsReconFinding", "j-file", finding_type="js_file", severity="low")
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id: 'v-chain', user_id: $u, project_id: $p}) "
                  "CREATE (:ChainFinding {id: 'cf', user_id: $u, project_id: $p})-[:CONFIRMS]->(v)",
                  u=self.uid, p=self.pid)
        self.client.mute_finding(self.uid, self.pid, "v-already", muted_by="alice")

        outcomes = self.batch(
            "Vulnerability",
            ["v-ok", "v-proven", "v-chain", "v-exempt", "v-stale", "v-above",
             "v-validated", "v-already", "v-seed", "v-gone"],
            self.ceiling(1), seed="v-seed", exempt=[("Vulnerability", "v-exempt")])
        js = self.batch("JsReconFinding", ["j-file"], self.ceiling(4))

        self.assertEqual(outcomes, {
            "v-ok": "muted", "v-proven": "proven", "v-chain": "proven",
            "v-exempt": "kept_visible", "v-stale": "stale", "v-above": "above_seed",
            "v-validated": "above_seed", "v-already": "already_muted", "v-seed": "muted",
        })
        self.assertEqual(js, {"j-file": "not_muteable"})
        for key in ("v-ok", "v-seed"):
            p = self.props("Vulnerability", key)
            self.assertTrue(p["_muted"])
            self.assertEqual((p["muted_channel"], p["muted_token"], p["muted_by"]),
                             ("multi", BATCH_A, self.uid))
        self.assertEqual(self.props("Vulnerability", "v-already")["muted_by"], "alice")
        with self.driver.session() as s:
            moved = s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p "
                          "AND n.updated_at IS NOT NULL AND n.updated_at <> datetime($fixed) "
                          "RETURN collect(coalesce(n.id, n.finding_id)) AS keys",
                          u=self.uid, p=self.pid, fixed=FIXED).single()["keys"]
        self.assertEqual(moved, [], "a Multi mute must not write updated_at")

    # --- strategy row 3 ------------------------------------------------------

    def test_undo_reverts_its_own_batch_only(self):
        for key in ("k1", "k2", "k3", "k4", "k5"):
            self.node("Vulnerability", key, source="nuclei", severity="low")
        self.batch("Vulnerability", ["k1", "k2"], self.ceiling(4), batch_id=BATCH_A)
        self.batch("Vulnerability", ["k3"], self.ceiling(4), batch_id=BATCH_B)
        self.client.mute_finding(self.uid, self.pid, "k4", muted_by=self.uid)
        # Batch A's stamp but another person's mute: an Undo is that person's.
        self.batch("Vulnerability", ["k5"], self.ceiling(4), batch_id=BATCH_A,
                   muted_by="someone-else")

        out = self.client.unmute_findings(self.uid, self.pid,
                                          ["k1", "k2", "k3", "k4", "k5"], only_batch=BATCH_A)

        self.assertEqual(sorted(i["key"] for i in out["items"]), ["k1", "k2"])
        for key in ("k1", "k2"):
            p = self.props("Vulnerability", key)
            self.assertFalse(p["_muted"])
            self.assertNotIn("muted_token", p)
            self.assertNotIn("muted_channel", p)
        self.assertEqual(self.props("Vulnerability", "k3")["muted_token"], BATCH_B)
        self.assertTrue(self.props("Vulnerability", "k4")["_muted"])
        self.assertEqual(self.props("Vulnerability", "k5")["muted_by"], "someone-else")
        self.assertTrue(self.props("Vulnerability", "k5")["_muted"])

    # --- strategy row 8 ------------------------------------------------------

    def test_a_full_pool_is_suggested_on_without_stalling_the_event_loop(self):
        # A started agent has these loaded (api.py imports them at module
        # level); cold, their first import inside `suggest` is a one-off
        # ~1.7 s stall that a running agent never pays.
        import langchain_core.messages  # noqa: F401
        import llm_builder  # noqa: F401
        import orchestrator_helpers  # noqa: F401
        from multi_mute import batches, service

        # Bodies as long as the pool reads them (`queries.TEXT_CUTS`), with
        # the hosts, times and ids the fingerprint strips: a short body makes
        # fingerprinting free, and then a pool run on the loop would pass too.
        def body(i):
            page = " ".join(f"<p>Build {i % 40}.{j} served by edge-{j}.example.com at 10:{j:02d} "
                            f"request {i:06d}-{j:04d}</p>" for j in range(18))
            return (f"HTTP/1.1 200 OK\r\nServer: nginx/1.{i % 40}\r\nX-Request-Id: {i:08x}{i:08x}"
                    f"\r\n\r\n<html>{page}</html>")[:1500]

        rows = [{"id": f"p-{i:04d}", "name": f"Banner {i % 40}", "body": body(i)} for i in range(2001)]
        with self.driver.session() as s:
            s.run("UNWIND $rows AS r CREATE (v:Vulnerability {id: r.id, user_id: $u, "
                  "project_id: $p, name: r.name, severity: 'low', source: 'nuclei', "
                  "template_id: 'tech-detect', raw_response: r.body})",
                  rows=rows, u=self.uid, p=self.pid)
            s.run("CREATE (v:Vulnerability {id: 'p-seed', user_id: $u, project_id: $p, "
                  "name: 'Banner seed', severity: 'low', source: 'nuclei', "
                  "template_id: 'tech-detect', raw_response: 'Server: nginx'})",
                  u=self.uid, p=self.pid)

        class _Answer:
            content = '{"seed": {"reason": "not_worth_fixing", "why": "banner", "quote": ""}}'

        class _Llm:
            async def ainvoke(self, _messages):
                return _Answer()

        async def main():
            gaps = []
            done = asyncio.Event()

            async def ticker():
                last = time.monotonic()
                while not done.is_set():
                    await asyncio.sleep(0.02)
                    now = time.monotonic()
                    gaps.append(now - last)
                    last = now

            tick = asyncio.create_task(ticker())
            started = time.monotonic()
            try:
                payload = await service.suggest(
                    user_id=self.uid, project_id=self.pid, seed_key="p-seed", model="stub",
                    exempt_pairs=[], driver=self.driver, build_llm=lambda _m: _Llm())
            finally:
                done.set()
                await tick
            return payload, time.monotonic() - started, max(gaps or [0])

        service.reset_state()
        try:
            payload, seconds, worst_gap = asyncio.run(main())
        finally:
            batches.STORE.clear()
            service.reset_state()
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["pool"]["truncated"])
        self.assertLess(seconds, 15.0, f"suggest took {seconds:.1f}s")
        self.assertLess(worst_gap, 0.2, f"the event loop stalled for {worst_gap * 1000:.0f} ms")


if __name__ == "__main__":
    unittest.main()
