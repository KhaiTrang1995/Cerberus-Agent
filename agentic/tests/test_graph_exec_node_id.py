"""Graph reads must carry each node's Node ID.

The webapp tables show `id(n)` in their leftmost column so a user can point an
external agent at one row. The agent reads the graph through /graph/exec (the
MCP `query_graph` tool and the sandbox's redagraph both do), and its coercion
used to emit only labels and properties - so a node came back with no way to
match it to the row the user was looking at.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
from prompts import TEXT_TO_CYPHER_SYSTEM  # noqa: E402


class _FakeNode:
    """The driver Node surface the coercion reads: labels, element_id, items().

    Not a dict subclass: the real Node is not one, and the coercion checks
    `isinstance(v, dict)` first, so a dict-based fake never reaches the node
    branch at all.
    """

    def __init__(self, element_id, labels, props):
        self._props = dict(props)
        self.element_id = element_id
        self.labels = frozenset(labels)

    def items(self):
        return self._props.items()


class _FakeRel:
    def __init__(self, rel_type, props):
        self._props = dict(props)
        self.type = rel_type
        self.nodes = ()

    def items(self):
        return self._props.items()


class NodeIdTests(unittest.TestCase):
    def test_a_node_carries_the_id_the_ui_shows(self):
        node = _FakeNode("4:947d2a1b-f59a-49ff-ba7f-08f352ab9277:1234", ["Vulnerability"],
                         {"name": "xss"})
        out = api._graph_exec_coerce(node)
        self.assertEqual(out["_kind"], "node")
        self.assertEqual(out["nodeId"], 1234)

    def test_the_id_property_is_left_alone(self):
        # CVE ids and finding keys live in an `id` PROPERTY that means something
        # else; the Node ID must not overwrite or be confused with it.
        node = _FakeNode("4:db:77", ["Vulnerability"], {"id": "nuclei-abc"})
        out = api._graph_exec_coerce(node)
        self.assertEqual(out["nodeId"], 77)
        self.assertEqual(out["properties"]["id"], "nuclei-abc")

    def test_nested_nodes_keep_their_ids(self):
        rows = [{"hosts": [_FakeNode("4:db:1", ["IP"], {}), _FakeNode("4:db:2", ["IP"], {})]}]
        out = api._graph_exec_coerce(rows)
        self.assertEqual([n["nodeId"] for n in out[0]["hosts"]], [1, 2])

    def test_an_unrecognised_element_id_is_null_not_a_guess(self):
        # A wrong id would point the caller at a different node; null says
        # "unknown" honestly.
        for element_id in ("opaque-id", "4:db:12a", "", None):
            with self.subTest(element_id=element_id):
                node = _FakeNode(element_id, ["IP"], {})
                self.assertIsNone(api._graph_exec_coerce(node)["nodeId"])

    def test_relationships_are_unchanged(self):
        out = api._graph_exec_coerce(_FakeRel("HAS_PORT", {"since": 1}))
        self.assertEqual(out, {"_kind": "relationship", "type": "HAS_PORT",
                               "properties": {"since": 1}})


class GeneratorPromptTests(unittest.TestCase):
    """The NL path must know what a Node ID is, or "tell me about node 1234"
    becomes `n.id = "1234"` and matches nothing."""

    def test_it_maps_node_id_to_the_id_function(self):
        self.assertIn("MATCH (n) WHERE id(n) = 1234", TEXT_TO_CYPHER_SYSTEM)

    def test_it_tells_the_property_and_the_id_apart(self):
        self.assertIn("It is NOT the `id` PROPERTY", TEXT_TO_CYPHER_SYSTEM)

    def test_the_rule_sits_before_the_schema_marker(self):
        # After the marker it would be spliced into the middle of the generated
        # schema instead of reading as a rule.
        self.assertLess(TEXT_TO_CYPHER_SYSTEM.index("## Node IDs"),
                        TEXT_TO_CYPHER_SYSTEM.index("__GRAPH_SCHEMA__"))

    def _section(self):
        start = TEXT_TO_CYPHER_SYSTEM.index("## Node IDs")
        return TEXT_TO_CYPHER_SYSTEM[start:TEXT_TO_CYPHER_SYSTEM.index("__GRAPH_SCHEMA__")]

    def test_every_good_example_is_one_the_tenant_filter_accepts(self):
        # A "Good:" example the scoper refuses teaches the model a query that
        # always fails; the first draft of this section had one (a lone CVE).
        from graph_db.tenant_filter import scope_query
        goods = [l.split("Good:", 1)[1].strip() for l in self._section().splitlines() if "Good:" in l]
        self.assertGreaterEqual(len(goods), 3)
        for cypher in goods:
            with self.subTest(cypher=cypher):
                scope_query(cypher, "u", "p")

    def test_the_lone_reference_node_example_is_marked_bad_and_is(self):
        from graph_db.tenant_filter import scope_query, TenantScopeError
        self.assertIn("Bad:  MATCH (c:CVE) WHERE id(c) = 1234 RETURN c", self._section())
        with self.assertRaises(TenantScopeError):
            scope_query("MATCH (c:CVE) WHERE id(c) = 1234 RETURN c", "u", "p")

    def test_the_nodeid_column_rule_excludes_aggregations(self):
        # `RETURN v.severity, count(v), id(v) AS nodeId` makes every count 1.
        self.assertIn("Never add it to a\nquery that counts, groups, aggregates or uses DISTINCT", self._section())


if __name__ == "__main__":
    unittest.main()
