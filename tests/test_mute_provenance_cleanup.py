"""The mute-provenance cleanup strips leftovers and never unmutes.

Pinned on the Cypher it runs, with a fake driver: it only matches findings
WITHOUT `:Muted`, removes only `muted_channel`/`muted_token`, is a dry run
unless told to write, and refuses to run without saying which projects.

Run: ./redamon.sh test unit   (root-agent section)
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "tooling" / "scripts"))
sys.path.insert(0, str(_REPO))

import mute_provenance_cleanup as mpc  # noqa: E402


def driver(found):
    queries = []
    session = MagicMock()

    def run(query, **params):
        queries.append((query, params))
        result = MagicMock()
        if "RETURN n.project_id" in query:
            result.__iter__ = lambda _s: iter([{"project_id": p, "n": n} for p, n in found.items()])
        else:
            result.single.return_value = {"n": sum(found.values())}
        return result

    session.run = run
    session.__enter__ = lambda _s: session
    session.__exit__ = lambda *_: False
    drv = MagicMock()
    drv.session.return_value = session
    return drv, queries


class TestCleanup(unittest.TestCase):
    def test_it_strips_only_the_provenance_of_unmuted_findings(self):
        drv, queries = driver({"p1": 3})
        stats = mpc.cleanup(drv, None, apply=True, out=lambda *_: None)
        self.assertEqual(stats, {"found": {"p1": 3}, "stripped": 3})
        strip = queries[-1][0]
        self.assertIn("WHERE NOT n:Muted", strip)
        self.assertIn("REMOVE n.muted_channel, n.muted_token", strip)
        # It never unmutes and never touches a verdict.
        self.assertNotIn("REMOVE n:Muted", strip)
        for prop in ("n.muted_by", "n.muted_at", "n.muted_reason", "triage_"):
            self.assertNotIn(prop, strip.split("CALL")[1])
        self.assertIn("IN TRANSACTIONS", strip)

    def test_it_matches_exactly_the_muteable_labels(self):
        from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
        self.assertEqual(set(mpc.FINDING_LABELS), set(MUTEABLE_LABELS))

    def test_the_default_is_a_dry_run(self):
        drv, queries = driver({"p1": 5, "p2": 2})
        stats = mpc.cleanup(drv, None, apply=False, out=lambda *_: None)
        self.assertEqual(len(queries), 1)
        self.assertNotIn("REMOVE", queries[0][0])
        self.assertEqual(stats["stripped"], 0)

    def test_one_project_is_scoped_to_it(self):
        drv, queries = driver({"p1": 1})
        mpc.cleanup(drv, "p1", apply=True, out=lambda *_: None)
        for query, params in queries:
            self.assertIn("n.project_id = $pid", query)
            self.assertEqual(params["pid"], "p1")

    def test_nothing_to_do_runs_no_write(self):
        drv, queries = driver({})
        mpc.cleanup(drv, None, apply=True, out=lambda *_: None)
        self.assertEqual(len(queries), 1)

    def test_a_blank_project_id_is_never_every_project(self):
        for blank in ("", "   "):
            with self.assertRaises(SystemExit):
                mpc.main(["--project", blank])
            drv, queries = driver({"p1": 1})
            with self.assertRaises(ValueError):
                mpc.cleanup(drv, blank, apply=True, out=lambda *_: None)
            self.assertEqual(queries, [])

    def test_it_must_be_told_which_projects(self):
        with self.assertRaises(SystemExit):
            mpc.main([])
        with self.assertRaises(SystemExit):
            mpc.main(["--project", "p1", "--all"])


if __name__ == "__main__":
    unittest.main()
