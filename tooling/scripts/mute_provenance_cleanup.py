#!/usr/bin/env python3
"""Strip MCP mute provenance from findings that are no longer muted.

An agent's (MCP) mute is stamped `muted_channel = 'mcp'` and `muted_token`.
Every unmute on this build removes both, but a build from before them does
not: after a rollback, an MCP-muted finding unmuted on the old build keeps the
two properties on a node that is not muted. They are harmless while it stays
unmuted, because every mute on this build clears them, so this is housekeeping
to run after a roll-forward.

It only ever touches a finding WITHOUT the `Muted` label, and only those two
properties. It never unmutes anything and never touches a verdict.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/mute_provenance_cleanup.py --all

  # one project, for real
  python tooling/scripts/mute_provenance_cleanup.py --project <project id> --apply

Idempotent: a second run finds nothing to do.

Reads NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD, like every other graph tool.
"""
from __future__ import annotations

import argparse
import os
import sys

#: The eight muteable finding labels, as `MUTEABLE_LABELS` in
#: graph_db/mixins/recon/triage_mixin.py. Spelled out so the script runs
#: without the graph_db package on the path.
FINDING_LABELS = (
    "Vulnerability", "JsReconFinding", "Secret", "MultiscannerFinding",
    "GithubSecret", "GithubSensitiveFile", "MalPackageFinding", "ExploitGvm",
)
_LABELS = "|".join(FINDING_LABELS)

COUNT = f"""
MATCH (n:{_LABELS})
WHERE NOT n:Muted
  AND (n.muted_channel IS NOT NULL OR n.muted_token IS NOT NULL) {{scope}}
RETURN n.project_id AS project_id, count(n) AS n
ORDER BY project_id
"""

#: Batched so a large project is not one transaction.
STRIP = f"""
MATCH (n:{_LABELS})
WHERE NOT n:Muted
  AND (n.muted_channel IS NOT NULL OR n.muted_token IS NOT NULL) {{scope}}
CALL (n) {{{{
  REMOVE n.muted_channel, n.muted_token
}}}} IN TRANSACTIONS OF 1000 ROWS
RETURN count(n) AS n
"""


def _scope(project_id: str | None) -> str:
    return "AND n.project_id = $pid" if project_id else ""


def cleanup(driver, project_id: str | None, apply: bool, out=print) -> dict:
    """Per-project counts of leftover provenance, stripped only when `apply`.

    `project_id=None` means every project; a blank id is refused, never read
    as "every project" (an unset shell variable must not widen the write).
    """
    if project_id is not None and not project_id.strip():
        raise ValueError("a blank project id; pass --all to mean every project")
    params = {"pid": project_id} if project_id else {}
    with driver.session() as session:
        found = {r["project_id"]: int(r["n"]) for r in session.run(
            COUNT.format(scope=_scope(project_id)), **params)}
        for pid, n in found.items():
            out(f"[mute provenance] {pid}: {n} unmuted finding(s) with leftover provenance"
                f"{'' if apply else ' (dry run)'}")
        stripped = 0
        if found and apply:
            record = session.run(STRIP.format(scope=_scope(project_id)), **params).single()
            stripped = int(record["n"]) if record else 0
    out(f"[mute provenance] {'stripped' if apply else 'would strip'} "
        f"{stripped if apply else sum(found.values())} finding(s) in {len(found)} project(s)")
    return {"found": found, "stripped": stripped}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Strip MCP mute provenance from findings that are no longer muted.")
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="one project id")
    target.add_argument("--all", action="store_true", help="every project")
    ap.add_argument("--apply", action="store_true",
                    help="write; without it this only counts")
    args = ap.parse_args(argv)
    if args.project is not None and not args.project.strip():
        ap.error("--project is blank (an unset variable?); pass --all to mean every project")

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    driver = GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_USER", "neo4j"),
                                             os.environ.get("NEO4J_PASSWORD", "")))
    try:
        cleanup(driver, None if args.all else args.project, args.apply)
    finally:
        driver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
