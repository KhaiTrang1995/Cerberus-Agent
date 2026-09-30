"""LIVE-Neo4j proof of the MCP mute and unmute paths in the triage mixin.

The unit tests pin the Cypher's shape against a stub driver. This runs it:
the `id(n) IN $gids` resolution with its notification setting, the lock-first
evidence and exemption checks, the "never touch an existing mute" rule, the
three-valued provenance and the token filter, and a mute racing the prune.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://redamon-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_mcp_mute_graph_live.py -v

Everything it creates lives under a throwaway tenant (two projects, so the
cross-project check has something to leak into) and is deleted in tearDown.
"""

import os
import sys
import threading
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

TOKEN = "rdmn_mcp_ab12cd34"
OTHER_TOKEN = "rdmn_mcp_00ff00ff"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveMcpMuteCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.base_mixin import BaseMixin
        from graph_db.mixins.node_filter_mixin import NodeFilterMixin
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"mm-{run}"
        self.pid = f"MM_{run}"
        self.pid2 = f"MM2_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(NodeFilterMixin, TriageMixin, BaseMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        for pid in (self.pid, self.pid2):
            self._seed(pid)

    def _seed(self, pid):
        with self.driver.session() as s:
            s.run(
                """
                CREATE (ip:IP {address: '192.0.2.10', user_id: $u, project_id: $p})
                WITH ip
                UNWIND $rows AS r
                CREATE (v:Vulnerability {id: r.id, user_id: $u, project_id: $p,
                        name: 'Banner ' + r.id, severity: r.sev, source: 'nuclei',
                        updated_at: datetime('2026-09-23T10:00:00Z')})
                CREATE (ip)-[:HAS_VULNERABILITY]->(v)
                """,
                u=self.uid, p=pid, rows=[
                    {"id": "v-plain", "sev": "info"},
                    {"id": "v-second", "sev": "low"},
                    {"id": "v-confirmed", "sev": "high"},
                    {"id": "v-proof", "sev": "high"},
                    {"id": "v-chain", "sev": "high"},
                    {"id": "v-exempt", "sev": "info"},
                    {"id": "v-person", "sev": "info"},
                    {"id": "v-rule", "sev": "info"},
                    {"id": "v-noise", "sev": "info"},
                ])
            s.run("CREATE (:MalPackageFinding {finding_id: 'mf-1', user_id: $u, project_id: $p, "
                  "name: 'evil-pkg', severity: 'critical', source: 'supply_chain'})",
                  u=self.uid, p=pid)
            # A Secret sharing a Vulnerability's id: `_BY_ID` spans eight labels.
            s.run("CREATE (:Secret {id: 'v-second', user_id: $u, project_id: $p, "
                  "secret_type: 'aws', severity: 'high', source: 'js_recon'})",
                  u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-confirmed', user_id: $u, project_id: $p}) "
                  "SET v.triage_status = 'confirmed', v.triage_source = 'human'", u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-proof', user_id: $u, project_id: $p}) "
                  "SET v.triage_proof = 'poc.txt'", u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-chain', user_id: $u, project_id: $p}) "
                  "CREATE (:ChainFinding {id: 'cf-' + $p, user_id: $u, project_id: $p})-[:CONFIRMS]->(v)",
                  u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-noise', user_id: $u, project_id: $p}) "
                  "SET v.triage_status = 'likely_noise', v.triage_source = 'human'", u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-person', user_id: $u, project_id: $p}) "
                  "SET v:Muted, v.muted = true, v.muted_at = datetime(), v.muted_by = 'alice', "
                  "v.muted_reason = 'noise'", u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'v-rule', user_id: $u, project_id: $p}) "
                  "SET v:Muted, v.muted = true, v.muted_at = datetime(), "
                  "v.muted_by = 'rule:vuln.nuclei/k3f9a2', v.muted_reason = 'Filter rule: Info'",
                  u=self.uid, p=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)
        self.driver.close()

    # --- helpers -------------------------------------------------------------

    def mute(self, keys=(), graph_ids=(), exempt=(), pid=None, token=TOKEN):
        return self.client.mute_findings_delegated(
            self.uid, pid or self.pid, keys=list(keys), graph_ids=list(graph_ids),
            exempt_pairs=[list(p) for p in exempt], muted_by=self.uid,
            reason="dev banner, per the owner", token_prefix=token)

    def node(self, key, label="Vulnerability", pid=None):
        prop = "finding_id" if label == "MalPackageFinding" else "id"
        with self.driver.session() as s:
            rec = s.run(
                f"MATCH (n:{label} {{{prop}: $k, user_id: $u, project_id: $p}}) "
                "RETURN n:Muted AS muted, n.muted_by AS by, n.muted_reason AS reason, "
                "n.muted_channel AS channel, n.muted_token AS token, "
                "toString(n.muted_at) AS at, toString(n.stale_since) AS stale, "
                "last(split(elementId(n), ':')) AS gid",
                k=key, u=self.uid, p=pid or self.pid).single()
        return dict(rec) if rec else None

    def outcomes(self, result):
        return {(i["ref"], i["label"]): i["outcome"] for i in result["items"]}

    # --- mute ---------------------------------------------------------------

    def test_a_mute_by_key_is_stamped_as_an_agents(self):
        result = self.mute(keys=["v-plain"])
        self.assertEqual(self.outcomes(result), {("v-plain", "Vulnerability"): "muted"})
        n = self.node("v-plain")
        self.assertTrue(n["muted"])
        self.assertEqual((n["by"], n["channel"], n["token"]), (self.uid, "mcp", TOKEN))
        self.assertEqual(n["reason"], "dev banner, per the owner")
        self.assertEqual(result["items"][0]["node_id"], n["gid"])
        self.assertEqual(result["items"][0]["name"], "Banner v-plain")

    def test_a_mute_by_node_id_and_by_finding_id(self):
        gid = self.node("mf-1", "MalPackageFinding")["gid"]
        result = self.mute(graph_ids=[gid])
        self.assertEqual(self.outcomes(result), {(gid, "MalPackageFinding"): "muted"})
        self.assertTrue(self.node("mf-1", "MalPackageFinding")["muted"])

    def test_an_asset_node_id_is_not_a_finding_and_nothing_is_written(self):
        with self.driver.session() as s:
            gid = s.run("MATCH (ip:IP {user_id: $u, project_id: $p}) "
                        "RETURN toString(id(ip)) AS g", u=self.uid, p=self.pid).single()["g"]
        result = self.mute(graph_ids=[gid])
        self.assertEqual(result["items"][0]["outcome"], "not_a_finding")
        with self.driver.session() as s:
            self.assertEqual(s.run("MATCH (n:Muted) WHERE n.user_id = $u AND n.project_id = $p "
                                   "RETURN count(n) AS c", u=self.uid, p=self.pid).single()["c"], 2)

    def test_proven_findings_are_refused_but_human_noise_is_not(self):
        result = self.mute(keys=["v-confirmed", "v-proof", "v-chain", "v-noise"])
        self.assertEqual(self.outcomes(result), {
            ("v-confirmed", "Vulnerability"): "proven",
            ("v-proof", "Vulnerability"): "proven",
            ("v-chain", "Vulnerability"): "proven",
            ("v-noise", "Vulnerability"): "muted",
        })
        for key in ("v-confirmed", "v-proof", "v-chain"):
            self.assertFalse(self.node(key)["muted"], key)

    def test_an_exempt_finding_is_kept_visible(self):
        result = self.mute(keys=["v-exempt"], exempt=[("Vulnerability", "v-exempt")])
        self.assertEqual(result["items"][0]["outcome"], "kept_visible")
        self.assertFalse(self.node("v-exempt")["muted"])
        # An exemption for another label with the same key does not apply.
        result = self.mute(keys=["v-exempt"], exempt=[("Secret", "v-exempt")])
        self.assertEqual(result["items"][0]["outcome"], "muted")

    def test_an_existing_mute_is_never_touched(self):
        before = {k: self.node(k) for k in ("v-person", "v-rule")}
        result = self.mute(keys=["v-person", "v-rule"])
        self.assertEqual(sorted((i["ref"], i["outcome"], i["was_via"]) for i in result["items"]),
                         [("v-person", "already_muted", "person"),
                          ("v-rule", "already_muted", "rule")])
        for key, node in before.items():
            self.assertEqual(self.node(key), node, key)

    def test_another_tenants_ids_are_not_found(self):
        other_gid = self.node("v-plain", pid=self.pid2)["gid"]
        result = self.mute(keys=["nope"], graph_ids=[other_gid])
        self.assertEqual(sorted(result["not_found"]), sorted(["nope", other_gid]))
        self.assertEqual(result["items"], [])
        self.assertFalse(self.node("v-plain", pid=self.pid2)["muted"])

    def test_one_key_matching_two_nodes_reports_both(self):
        result = self.mute(keys=["v-second"])
        self.assertEqual(self.outcomes(result), {("v-second", "Vulnerability"): "muted",
                                                 ("v-second", "Secret"): "muted"})

    def test_the_lock_leaves_no_scratch_property_behind(self):
        self.mute(keys=["v-plain", "v-person"])
        self.client.mute_finding(self.uid, self.pid, "v-exempt", self.uid)
        self.client.unmute_findings(self.uid, self.pid, ["v-plain"])
        with self.driver.session() as s:
            left = s.run("MATCH (n) WHERE n.user_id = $u AND n._mute_lock IS NOT NULL "
                         "RETURN count(n) AS c", u=self.uid).single()["c"]
        self.assertEqual(left, 0)

    # --- a person's mute ------------------------------------------------------

    def test_the_ui_mute_on_an_agent_mute_changes_nothing(self):
        self.mute(keys=["v-plain"])
        before = self.node("v-plain")
        result = self.client.mute_finding(self.uid, self.pid, "v-plain", "bob", "stale row")
        self.assertEqual(result, {"muted": True, "already": True, "label": "Vulnerability"})
        self.assertEqual(self.node("v-plain"), before)

    def test_a_fresh_ui_mute_clears_leftover_provenance(self):
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id: 'v-plain', user_id: $u, project_id: $p}) "
                  "SET v.muted_channel = 'mcp', v.muted_token = $t", u=self.uid, p=self.pid, t=TOKEN)
        self.client.mute_finding(self.uid, self.pid, "v-plain", "bob")
        n = self.node("v-plain")
        self.assertEqual((n["muted"], n["by"], n["channel"], n["token"]), (True, "bob", None, None))

    # --- unmute ---------------------------------------------------------------

    def test_unmute_clears_the_provenance(self):
        self.mute(keys=["v-plain"])
        result = self.client.unmute_findings(self.uid, self.pid, ["v-plain"])
        self.assertEqual(result["items"][0]["was_via"], "mcp")
        n = self.node("v-plain")
        self.assertEqual((n["muted"], n["by"], n["channel"], n["token"]), (False, None, None, None))

    def test_an_mcp_unmute_spares_rule_mutes_unless_asked(self):
        self.mute(keys=["v-plain"])
        result = self.client.unmute_findings(self.uid, self.pid, ["v-rule", "v-plain"],
                                             skip_rule_mutes=True)
        self.assertEqual([i["key"] for i in result["items"]], ["v-plain"])
        self.assertEqual([i["key"] for i in result["skipped"]], ["v-rule"])
        self.assertTrue(self.node("v-rule")["muted"])
        self.client.unmute_findings(self.uid, self.pid, ["v-rule"])
        self.assertFalse(self.node("v-rule")["muted"])

    def test_resolve_reads_and_buckets_without_writing(self):
        gid = self.node("v-person")["gid"]
        before = {k: self.node(k) for k in ("v-person", "v-rule")}
        result = self.client.resolve_muted(self.uid, self.pid, keys=["v-rule", "v-plain"],
                                           graph_ids=[gid])
        self.assertEqual([(i["key"], i["ref"], i["was_via"]) for i in result["to_unmute"]],
                         [("v-person", gid, "person")])
        self.assertEqual([i["key"] for i in result["skipped_rule_mute"]], ["v-rule"])
        self.assertEqual(result["not_found"], ["v-plain"])
        self.assertEqual({k: self.node(k) for k in before}, before)
        with_rules = self.client.resolve_muted(self.uid, self.pid, keys=["v-rule"],
                                               include_rule_mutes=True)
        self.assertEqual([i["key"] for i in with_rules["to_unmute"]], ["v-rule"])

    # --- Muted Nodes reads ------------------------------------------------------

    def test_the_list_is_three_valued_with_a_token_filter_and_facets(self):
        self.mute(keys=["v-plain", "v-exempt"])
        self.mute(keys=["v-noise"], token=OTHER_TOKEN)
        rows = {r["id"]: r for r in self.client.list_muted(self.uid, self.pid)}
        self.assertEqual({k: r["muted_via"] for k, r in rows.items()}, {
            "v-plain": "mcp", "v-exempt": "mcp", "v-noise": "mcp",
            "v-person": "person", "v-rule": "rule"})
        self.assertEqual(rows["v-plain"]["muted_token"], TOKEN)
        self.assertEqual(rows["v-person"]["muted_token"], "")
        count = self.client.count_muted
        self.assertEqual(count(self.uid, self.pid, muted_via="mcp"), 3)
        self.assertEqual(count(self.uid, self.pid, muted_via="person"), 1)
        self.assertEqual(count(self.uid, self.pid, muted_via="rule"), 1)
        self.assertEqual(count(self.uid, self.pid, token=TOKEN), 2)
        self.assertEqual(count(self.uid, self.pid, token=OTHER_TOKEN), 1)
        facets = self.client.muted_facets(self.uid, self.pid)
        self.assertEqual((facets["total"], facets["by_person"], facets["by_mcp"]), (5, 1, 3))
        self.assertEqual(facets["tokens"], [{"token": TOKEN, "count": 2},
                                            {"token": OTHER_TOKEN, "count": 1}])

    def test_an_all_digit_search_finds_the_exact_node_id(self):
        gid = self.node("v-person")["gid"]
        rows = self.client.list_muted(self.uid, self.pid, search=gid)
        self.assertEqual([r["id"] for r in rows], ["v-person"])

    # --- the rule sweep and the prune --------------------------------------------

    def test_a_rule_sweep_never_touches_an_agent_mute(self):
        self.mute(keys=["v-plain"])
        before = self.node("v-plain")
        info = {"id": "k3f9a2", "name": "Info", "enabled": True,
                "all": [{"field": "severity", "op": "in", "value": ["info"]}]}
        for enabled in (True, False):
            self.client.apply_node_filters(self.uid, self.pid, {"mode": "denylist", "rules": {
                "version": 1, "kinds": {"vuln.nuclei": {"enabled": enabled, "action": "mute",
                                                        "rules": [info]}}}}, log=lambda *_: None)
            self.assertEqual(self.node("v-plain"), before, f"rule enabled={enabled}")

    def test_a_rule_mute_of_an_exempt_node_is_released_at_the_next_sweep(self):
        """What makes an unmute of a rule mute converge: the scan-end sweep read
        its exemptions when it started and may re-mute; the next one releases."""
        info = {"id": "k3f9a2", "name": "Info", "enabled": True,
                "all": [{"field": "severity", "op": "in", "value": ["info"]}]}
        config = {"mode": "denylist", "rules": {"version": 1, "kinds": {
            "vuln.nuclei": {"enabled": True, "action": "mute", "rules": [info]}}}}
        self.client.apply_node_filters(self.uid, self.pid, config, log=lambda *_: None)
        self.assertTrue(self.node("v-exempt")["muted"])
        self.client.apply_node_filters(self.uid, self.pid, config, log=lambda *_: None,
                                       exemptions=[("Vulnerability", "v-exempt")])
        self.assertFalse(self.node("v-exempt")["muted"])

    def test_the_prune_keeps_an_agent_mute_as_stale(self):
        self.mute(keys=["v-plain"])
        self.client.prune_unseen_findings(self.uid, self.pid, ["nuclei"], "2026-12-01T00:00:00+00:00")
        self.assertIsNotNone(self.node("v-plain")["stale"])
        self.assertIsNone(self.node("v-exempt"), "the control: an unmuted stale finding survived")

    def test_a_mute_committed_while_the_prune_runs_is_kept(self):
        """The prune reads `n:Muted` into `keep` and then DETACH DELETEs. A mute
        that committed in between used to be deleted with the node."""
        self._race_the_prune(self._prune, expect_kept=True)

    def test_the_race_is_real_without_the_lock(self):
        """The control: the pre-fix prune shape, in the same race, deletes the
        mute. Without it the test above could pass without ever racing."""
        self._race_the_prune(self._unlocked_prune, expect_kept=False)

    def _prune(self):
        self.client.prune_unseen_findings(self.uid, self.pid, ["nuclei"], "2026-12-01T00:00:00+00:00")

    def _unlocked_prune(self):
        with self.driver.session() as s:
            s.run("""
            MATCH (n:Vulnerability)
            WHERE n.user_id = $u AND n.project_id = $p AND n.source = 'nuclei'
            WITH n, ((n:Muted AND NOT coalesce(n.muted_by, '') STARTS WITH 'rule:')
                     OR coalesce(n.triage_source, '') = 'human') AS keep
            WITH collect(CASE WHEN keep THEN NULL ELSE n END) AS candidates
            FOREACH (d IN [c IN candidates WHERE c IS NOT NULL] | DETACH DELETE d)
            """, u=self.uid, p=self.pid).consume()

    def _race_the_prune(self, prune, expect_kept):
        session = self.driver.session()
        tx = session.begin_transaction()
        # A mute that has taken the node's lock and not yet committed.
        tx.run("MATCH (v:Vulnerability {id: 'v-plain', user_id: $u, project_id: $p}) "
               "SET v:Muted, v.muted = true, v.muted_at = datetime(), v.muted_by = $u",
               u=self.uid, p=self.pid).consume()
        errors = []

        def run():
            try:
                prune()
            except Exception as exc:  # surfaced below, not swallowed
                errors.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        time.sleep(2.0)
        self.assertTrue(worker.is_alive(), "the prune did not wait for the mute's lock")
        tx.commit()
        session.close()
        worker.join(timeout=60)
        self.assertEqual(errors, [])
        node = self.node("v-plain")
        if expect_kept:
            self.assertIsNotNone(node, "a mute committed mid-prune was deleted")
            self.assertTrue(node["muted"])
            self.assertIsNotNone(node["stale"])
        else:
            self.assertIsNone(node, "the unlocked prune kept it: the race was not exercised")


if __name__ == "__main__":
    unittest.main()
