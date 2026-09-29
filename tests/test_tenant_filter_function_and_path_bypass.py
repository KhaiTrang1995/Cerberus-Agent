"""REGRESSION: two shapes that read across tenants past the pattern-based scoper.

Both were reproduced against the running stack (a query that `scope_query`
approved for ONE project returned data from all 27), and both share a cause:
tenant scoping rewrites NODE PATTERNS, so anything that reaches data without
being written as a node pattern is invisible to it.

1. APOC FUNCTIONS.  The procedure allowlist only inspects `CALL <name>`. APOC
   also exposes the same capability as FUNCTIONS, which need no CALL and are
   legal anywhere an expression is:

       MATCH (d:Domain) WITH d LIMIT 1
       RETURN apoc.cypher.runFirstColumnSingle('MATCH (n) RETURN ...', {})

   The inner query is a string literal, so it is never scoped. `apoc.load.*`
   points the same hole outward as an SSRF from inside the database container.

2. VARIABLE-LENGTH PATHS.  The intermediate nodes of `[*]` / `{n,m}` are never
   written as `()` patterns, so they get neither the tenant filter nor the
   `!Muted` exclusion, while the reference labels (CVE/MitreData/Capec) are
   exempt once ONE tenant-anchored pattern exists:

       MATCH (t:Technology) WITH t LIMIT 1
       MATCH p=(:CVE)-[*2]-(:CVE) UNWIND nodes(p) AS n RETURN n

   walks from the shared CVE nodes straight into other projects' nodes.

Run: python -m unittest tests.test_tenant_filter_function_and_path_bypass
"""
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.tenant_filter import (  # noqa: E402
    TenantScopeError,
    find_disallowed_call,
    has_variable_length_path,
    scope_query,
)

ANCHOR = "MATCH (d:Domain) WITH d LIMIT 1 "
UID, PID = "attacker-user", "attacker-project"


def refused(cypher: str) -> bool:
    try:
        scope_query(cypher, UID, PID)
        return False
    except TenantScopeError:
        return True


def approved(cypher: str) -> str:
    return scope_query(cypher, UID, PID)


class ApocFunctionBypassTests(unittest.TestCase):
    def test_the_confirmed_cross_tenant_read_is_refused(self):
        self.assertTrue(refused(
            ANCHOR + "RETURN apoc.cypher.runFirstColumnSingle("
            "'MATCH (n) WHERE n.project_id IS NOT NULL "
            "RETURN count(DISTINCT n.project_id)', {}) AS projects"
        ))

    def test_every_function_form_that_runs_cypher_or_fetches_is_refused(self):
        for fn in (
            "apoc.cypher.runFirstColumnSingle",
            "apoc.cypher.runFirstColumnMany",
            "apoc.load.json",
            "apoc.load.csv",
            "apoc.load.xml",
            "apoc.text.regexGroups",
            "apoc.util.sleep",
        ):
            with self.subTest(fn=fn):
                self.assertTrue(refused(ANCHOR + f"RETURN {fn}('x', {{}}) AS v"), fn)

    def test_the_name_cannot_be_hidden_by_quoting_spacing_or_comments(self):
        for variant in (
            "`apoc`.`cypher`.`runFirstColumnSingle`",
            "`apoc.cypher.runFirstColumnSingle`",
            "apoc . cypher . runFirstColumnSingle",
            "apoc/**/.cypher.runFirstColumnSingle",
            "APOC.CYPHER.RUNFIRSTCOLUMNSINGLE",
            "apoc\n.cypher\n.runFirstColumnSingle",
        ):
            with self.subTest(variant=variant):
                self.assertTrue(
                    refused(ANCHOR + f"RETURN {variant}('x', {{}}) AS v"), variant
                )

    def test_a_call_procedure_form_is_still_refused(self):
        # The path that already worked must not regress.
        self.assertTrue(refused(
            ANCHOR + "CALL apoc.cypher.run('MATCH (n) RETURN n', {}) YIELD value RETURN value"
        ))

    def test_an_invented_namespace_is_refused_too(self):
        # A positive allowlist, not a denylist: a namespace nobody thought of.
        self.assertTrue(refused(ANCHOR + "RETURN some.brand.newFunction(d) AS v"))

    def test_an_apoc_name_in_a_string_or_comment_is_not_a_false_positive(self):
        approved("MATCH (f:Finding) WHERE f.description CONTAINS "
                 "'apoc.load.json(x) is dangerous' RETURN f.title")
        approved("// apoc.cypher.runFirstColumnSingle\nMATCH (i:IP) RETURN i.address")


class LegitimateFunctionsStillWorkTests(unittest.TestCase):
    def test_builtin_namespaced_functions_are_approved(self):
        for expr in (
            "duration.between(i.first_seen, i.last_seen)",
            "point.distance(i.loc, i.loc)",
            "date.truncate('month', i.first_seen)",
            "datetime.fromepochmillis(i.ts)",
        ):
            with self.subTest(expr=expr):
                approved(f"MATCH (i:IP) RETURN {expr} AS v")

    def test_plain_unnamespaced_functions_are_approved(self):
        approved("MATCH (v:Vulnerability) RETURN count(v), collect(v.name), "
                 "toString(id(v)), size(v.name), coalesce(v.severity, 'n/a')")

    def test_property_access_and_map_projection_are_not_calls(self):
        # `n.name(` never appears, but `n{.a, .b}` and `n.a` are dotted too.
        approved("MATCH (n:Domain) RETURN n{.name, .status} AS m, n.name")

    def test_find_disallowed_call_returns_the_name(self):
        self.assertEqual(
            find_disallowed_call("RETURN apoc.load.json('x') AS v"), "apoc.load.json"
        )
        self.assertIsNone(find_disallowed_call("MATCH (i:IP) RETURN i.address"))


class VariableLengthPathBypassTests(unittest.TestCase):
    def test_the_confirmed_walk_through_reference_nodes_is_refused(self):
        self.assertTrue(refused(
            "MATCH (t:Technology) WITH t LIMIT 1 "
            "MATCH p=(:CVE)-[*2]-(:CVE) UNWIND nodes(p) AS n "
            "RETURN [x IN nodes(p) | [id(x), labels(x), x.name]]"
        ))

    def test_every_variable_length_spelling_is_refused(self):
        for hop in (
            "-[*]->", "-[*2]->", "-[*1..3]->", "-[*..3]->", "-[*0..]->",
            "-[:HAS_PORT*]->", "-[:HAS_PORT*1..2]->", "-[r:RESOLVES_TO*1..2]->",
            "-[:A|B*2]->", "<-[*2]-", "-[*]-",
        ):
            with self.subTest(hop=hop):
                self.assertTrue(
                    refused(f"MATCH (a:Domain){hop}(b:IP) RETURN a, b"), hop
                )

    def test_quantified_paths_and_relationships_are_refused(self):
        for q in (
            "MATCH ((a:Domain)-[:HAS_SUBDOMAIN]->(b:Subdomain)){1,3} RETURN a",
            "MATCH (a:Domain)-[:HAS_SUBDOMAIN]->{1,3}(b:Subdomain) RETURN b",
            "MATCH (a:Domain) ((x)-[:R]->(y)){2} (b:IP) RETURN b",
        ):
            with self.subTest(q=q):
                self.assertTrue(refused(q), q)

    def test_the_agent_prompt_no_longer_teaches_a_variable_length_walk(self):
        # The prompt's own decisions example used `[:NEXT_STEP*0..]`; leaving it
        # would teach the model a query that always fails.
        from agentic.prompts import TEXT_TO_CYPHER_SYSTEM
        for line in TEXT_TO_CYPHER_SYSTEM.splitlines():
            if line.strip().startswith(("//", "-", "#", "Bad", "  Bad")):
                continue
            self.assertFalse(
                has_variable_length_path(line),
                f"the Cypher generator prompt teaches a refused query: {line.strip()}",
            )


class LegitimateShapesStillWorkTests(unittest.TestCase):
    def test_fixed_length_multi_hop_traversals_are_approved(self):
        approved("MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)"
                 "-[:HAS_PORT]->(p:Port) RETURN d.name, i.address, p.number")

    def test_a_star_inside_a_string_literal_is_not_a_path(self):
        approved("MATCH (i:IP) WHERE i.note = '[*] scanned' RETURN i")
        approved("MATCH (i:IP) WHERE i.note CONTAINS '-[*2]->' RETURN i")

    def test_list_slices_maps_and_comprehensions_are_not_paths(self):
        approved("MATCH (d:Domain) RETURN collect(d.name)[0..5] AS first5")
        approved("MATCH (d:Domain) RETURN d{.name} AS m")
        approved("MATCH (v:Vulnerability) RETURN [x IN collect(v.name) WHERE size(x) > 3] AS n")
        approved("MATCH (v:Vulnerability) RETURN {a: 1, b: {c: 2}} AS m, count(*) * 2")

    def test_a_comment_mentioning_a_path_is_not_a_path(self):
        approved("// walks -[*1..3]->\nMATCH (i:IP) RETURN i.address")

    def test_the_reference_chain_from_tenant_data_still_works(self):
        # The exemption is intact: an anchored, fixed-length reference traversal.
        out = approved("MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)-[:HAS_CWE]->"
                       "(m:MitreData)-[:HAS_CAPEC]->(k:Capec) RETURN t.name, c.id, m.cwe_id, k.capec_id")
        self.assertIn("$tenant_user_id", out)

    def test_has_variable_length_path_unit(self):
        self.assertTrue(has_variable_length_path("MATCH (a)-[*]->(b) RETURN a"))
        self.assertFalse(has_variable_length_path("MATCH (a)-[:R]->(b) RETURN a"))


if __name__ == "__main__":
    unittest.main()
