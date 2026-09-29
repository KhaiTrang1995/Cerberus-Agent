#!/usr/bin/env python3
"""Remove every mute a node-filter RULE applied. For reverting the feature.

A rule mute is the `:Muted` label plus `muted`, `muted_at`, `muted_by` and
`muted_reason`, with `muted_by` starting `rule:`. This removes exactly those,
so the findings come back everywhere. An operator's own mute (any other
`muted_by`) is never touched, and neither is a verdict.

  # what it would do, per project, changing nothing
  python tooling/scripts/node_filters_rollback.py --all --dry-run

  # one project
  python tooling/scripts/node_filters_rollback.py --project <project id>

  # every project
  python tooling/scripts/node_filters_rollback.py --all

Idempotent: a second run finds nothing to do. It leaves the four Postgres
tables (project_node_filters, node_filter_runs, node_filter_exemptions and
the users' saved presets, user_mute_rules_presets) alone; a `db push` of a
schema without them drops them, so export them first.

Reads NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD, like every other graph tool.
"""
from __future__ import annotations

import argparse
import os
import sys

RULE_PREFIX = "rule:"

COUNT = """
MATCH (n:Muted)
WHERE coalesce(n.muted_by, '') STARTS WITH $prefix {scope}
RETURN n.project_id AS project_id, count(n) AS n
ORDER BY project_id
"""

#: Batched so a project with a million rule mutes is not one transaction.
RELEASE = """
MATCH (n:Muted)
WHERE coalesce(n.muted_by, '') STARTS WITH $prefix {scope}
CALL (n) {{
  REMOVE n:Muted, n.muted, n.muted_at, n.muted_by, n.muted_reason,
         n.muted_channel, n.muted_token
}} IN TRANSACTIONS OF 1000 ROWS
RETURN count(n) AS n
"""


def _scope(project_id: str | None) -> str:
    return "AND n.project_id = $pid" if project_id else ""


def rollback(driver, project_id: str | None, dry_run: bool, out=print) -> dict:
    """Per-project counts of rule mutes found, and released unless `dry_run`.

    `project_id=None` means every project; a blank id is refused, never read
    as "every project" (an unset shell variable must not widen the release).
    """
    if project_id is not None and not project_id.strip():
        raise ValueError("a blank project id; pass --all to mean every project")
    params = {"prefix": RULE_PREFIX}
    if project_id:
        params["pid"] = project_id
    with driver.session() as session:
        found = {r["project_id"]: int(r["n"]) for r in session.run(
            COUNT.format(scope=_scope(project_id)), **params)}
        for pid, n in found.items():
            out(f"[node-filters rollback] {pid}: {n} rule mute(s){' (dry run)' if dry_run else ''}")
        released = 0
        if found and not dry_run:
            record = session.run(RELEASE.format(scope=_scope(project_id)), **params).single()
            released = int(record["n"]) if record else 0
    out(f"[node-filters rollback] {'would release' if dry_run else 'released'} "
        f"{sum(found.values()) if dry_run else released} rule mute(s) in {len(found)} project(s)")
    return {"found": found, "released": released}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Remove every node-filter rule mute.")
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="one project id")
    target.add_argument("--all", action="store_true", help="every project")
    ap.add_argument("--dry-run", action="store_true", help="count, change nothing")
    args = ap.parse_args(argv)
    if args.project is not None and not args.project.strip():
        ap.error("--project is blank (an unset variable?); pass --all to mean every project")

    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    driver = GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_USER", "neo4j"),
                                             os.environ.get("NEO4J_PASSWORD", "")))
    try:
        rollback(driver, None if args.all else args.project, args.dry_run)
    finally:
        driver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
