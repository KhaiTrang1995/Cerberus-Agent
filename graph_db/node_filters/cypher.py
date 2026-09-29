"""The only place node-filter Cypher is assembled.

A label and a property name cannot be Cypher parameters, so they are
interpolated, and ONLY from the checked catalog: each one is re-checked against
`^[A-Za-z_][A-Za-z0-9_]*$` here as well, and backquoted. Everything that came
from an operator or a scanner (selector values, rule values, keys, the paging
cursor, the time bound) travels as a parameter. A rule's `field` is resolved in
Python and never appears in a query at all.

None of these queries writes `updated_at`. Prune freshness, the triage publish
check (a string equality on `updated_at`) and the unseen badges all read it, so
a mute must not look like a scanner write.
"""
from __future__ import annotations

from .catalog import IDENT, CatalogError
from .guards import GUARD_COLUMNS, GUARD_WRITE_CHECK

RULE_PREFIX = "rule:"

#: An MCP mute's provenance (graph_db/mixins/recon/triage_mixin.py). A rule
#: never writes it, so every rule mute clears it and every unmute removes it:
#: otherwise a later mute would be attributed to an old access token.
MUTE_PROVENANCE = "n.muted_channel, n.muted_token"


def ident(name) -> str:
    if not isinstance(name, str) or not IDENT.match(name):
        raise CatalogError(f"{name!r} is not a safe Cypher identifier")
    return f"`{name}`"


def selector_clause(select: list) -> tuple[str, dict]:
    """A kind's structured selector as WHERE clauses plus their parameters."""
    clauses, params = [], {}
    for i, item in enumerate(select or []):
        prop, p = ident(item["prop"]), f"sel{i}"
        if "eq" in item:
            clauses.append(f"n.{prop} = ${p}")
            params[p] = item["eq"]
        elif "in" in item:
            clauses.append(f"n.{prop} IN ${p}")
            params[p] = list(item["in"])
        elif "not_eq" in item:
            # A node without the property is not the excluded value, so it stays in.
            clauses.append(f"coalesce(n.{prop}, '') <> ${p}")
            params[p] = item["not_eq"]
        else:
            raise CatalogError(f"selector item on {item.get('prop')!r} has no operator")
    return "".join(f"\n  AND {c}" for c in clauses), params


def projection_query(kind: dict, props, *, touched: bool = False, sources: bool = False,
                     rule_muted_only: bool = False) -> tuple[str, dict]:
    """One keyset page of a kind's nodes, with what the decision needs.

    `touched`/`sources` scope a scan-time sweep to what that scan wrote.
    `datetime(toString(...))` also reads the ISO strings a restored graph
    carries. `rule_muted_only` narrows an inactive kind to the nodes a rule
    muted, the only ones a sweep can still change there.
    """
    label, key = ident(kind["graph_label"]), ident(kind["key"])
    sel, params = selector_clause(kind.get("select") or [])
    extra = ""
    if touched:
        extra += "\n  AND datetime(toString(n.updated_at)) >= datetime($touched_since)"
    if sources:
        extra += "\n  AND n.source IN $sources"
    if rule_muted_only:
        extra += "\n  AND n:Muted AND coalesce(n.muted_by, '') STARTS WITH $rule_prefix"
        params["rule_prefix"] = RULE_PREFIX
    names = sorted(set(props))
    projected = "n {" + ", ".join(f".{ident(p)}" for p in names) + "}" if names else "{}"
    query = f"""MATCH (n:{label})
WHERE n.user_id = $uid AND n.project_id = $pid{sel}{extra}
  AND n.{key} > $after
WITH n ORDER BY n.{key} LIMIT $page
RETURN n.{key} AS key,
       n:Muted AS muted,
       coalesce(n.muted_by, '') AS muted_by,
       {GUARD_COLUMNS},
       coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS display,
       coalesce(n.triage_host, n.host, n.hostname, n.target_hostname, '') AS host,
       {projected} AS props"""
    return query, params


def _lock(carry: str) -> str:
    """Take the node's write lock before its mute state and guards are read.

    Neo4j evaluates a WHERE under read committed, BEFORE a SET locks the node,
    so a person's mute or a verdict committed in between would be overwritten.
    With the lock held, the checks that follow see the latest committed state
    and nothing can change it until this write commits. Net effect: none.
    """
    return f"""SET n._node_filter_lock = true
REMOVE n._node_filter_lock
WITH {carry}"""


def mute_query(kind: dict) -> str:
    label, key = ident(kind["graph_label"]), ident(kind["key"])
    return f"""UNWIND $rows AS row
MATCH (n:{label} {{{key}: row.key, user_id: $uid, project_id: $pid}})
WHERE NOT n:Muted
{_lock('n, row')}
WHERE NOT n:Muted
  AND {GUARD_WRITE_CHECK}
SET n:Muted, n.muted = true, n.muted_at = datetime(),
    n.muted_by = row.muted_by, n.muted_reason = row.reason
REMOVE {MUTE_PROVENANCE}
RETURN count(n) AS n"""


def restamp_query(kind: dict) -> str:
    """Re-attribute a rule mute to the rule that now matches, keeping its time."""
    label, key = ident(kind["graph_label"]), ident(kind["key"])
    return f"""UNWIND $rows AS row
MATCH (n:{label}:Muted {{{key}: row.key, user_id: $uid, project_id: $pid}})
WHERE coalesce(n.muted_by, '') STARTS WITH '{RULE_PREFIX}'
  AND n.muted_by <> row.muted_by
{_lock('n, row')}
WHERE n:Muted
  AND coalesce(n.muted_by, '') STARTS WITH '{RULE_PREFIX}'
  AND n.muted_by <> row.muted_by
  AND {GUARD_WRITE_CHECK}
SET n.muted_by = row.muted_by, n.muted_reason = row.reason
REMOVE {MUTE_PROVENANCE}
RETURN count(n) AS n"""


def unmute_query(kind: dict) -> str:
    """Release rule mutes only. A person's or an agent's (MCP) mute never
    matches the STARTS WITH: an MCP mute keeps its owner's id in `muted_by`."""
    label, key = ident(kind["graph_label"]), ident(kind["key"])
    return f"""UNWIND $keys AS key
MATCH (n:{label}:Muted {{{key}: key, user_id: $uid, project_id: $pid}})
WHERE coalesce(n.muted_by, '') STARTS WITH '{RULE_PREFIX}'
{_lock('n')}
WHERE n:Muted AND coalesce(n.muted_by, '') STARTS WITH '{RULE_PREFIX}'
REMOVE n:Muted, n.muted, n.muted_at, n.muted_by, n.muted_reason, {MUTE_PROVENANCE}
RETURN count(n) AS n"""
