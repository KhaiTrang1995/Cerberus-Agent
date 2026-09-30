"""Graph reads for Multi mute: the seed, the bounded pool and its counts (plan §7.2).

The pool query is built FROM the seed label's `FINDING_QUERIES` entry rather
than written a second time: its RETURN clause is reused as-is, so a field the
triage board projects can never be missing here. Three things change around it:

- the MATCH selects the seed's kind (`kind.kind_where`) and leaves out muted,
  stale and JS-file-container nodes; MalPackageFinding does not require its
  `Package -[:FLAGGED_AS]->` parent, as the triage entry does;
- the long text fields are cut in Cypher (`left()`), because the entry returns
  `raw_response` and `evidence` whole for every row, and a pool reads 2,000;
- what `build_bundle` / `group_key` read and the entries lack
  (`POOL_EXTRA_FIELDS`), the guard fields, and the row identity are added.

Rows come back closest-first (the seed's own source and detector, then the
nearest severity), capped at `POOL_MAX + 1` so the caller can tell a truncated
pool from a full one. Every query is tenant-scoped with `$userId/$projectId`,
and a label is only ever interpolated from `POOL_LABELS`.

Blocking (the neo4j driver): callers run these through `asyncio.to_thread`.
"""
from __future__ import annotations

import re

from cypherfix_triage.fact_queries import FINDING_QUERIES
from graph_db.mixins.recon.triage_mixin import (
    MUTEABLE_LABELS,
    _ceiling_severity_rank,
    _FUNCTIONAL_LABEL,
    _NODE_ID,
    _PROVEN,
)

from . import GUARD_FIELDS, POOL_EXTRA_FIELDS, POOL_LABELS, projected_fields
from .kind import Kind, fallback_source_expr, kind_where
from .pool import POOL_MAX

#: Cut in Cypher, per plan §11.
TEXT_CUTS = {"raw_response": 1500, "evidence": 1500, "description": 1500}
RAW_REQUEST_CUT = 500
#: The triage entry for Vulnerability projects `raw_request` itself; it is cut
#: to the same length as the column added for labels that do not.
_PROJECTION_CUTS = {**TEXT_CUTS, "raw_request": RAW_REQUEST_CUT}

#: What a row's "detector" is for ordering only. The exact detector is Python
#: (`score_model.detector_key`); this just puts the seed's look-alikes first.
_DETECTOR_EXPR = ("coalesce(n.template_id, n.detector_name, n.key_type, n.secret_type, "
                  "n.finding_type, n.advisory_id, n.name, '')")

_LINE_COMMENT = re.compile(r"//[^\n]*")
_CUT_FIELD = re.compile(
    r"(?P<expr>[A-Za-z_][\w.]*(?:\([^()]*\))?)\s+AS\s+(?P<alias>"
    + "|".join(_PROJECTION_CUTS) + r")\b")


class SeedMissing(LookupError):
    """No live, unmuted finding with this key in this tenant."""


def _entry(label: str) -> dict:
    for entry in FINDING_QUERIES:
        if entry.get("label") == label:
            return entry
    raise ValueError(f"no FINDING_QUERIES entry for {label!r}")


def entry_var(label: str) -> str:
    """The variable the entry binds the finding to (`v`, `s`, `f`, ...)."""
    query = _entry(label)["query"]
    match = re.search(rf"\((\w+):{label}\b", query)
    if not match:
        raise ValueError(f"cannot find the {label} variable in its FINDING_QUERIES entry")
    return match.group(1)


def entry_projection(label: str) -> str:
    """The entry's RETURN clause with the long text fields cut."""
    query = _LINE_COMMENT.sub("", _entry(label)["query"])
    at = re.search(r"^RETURN\s", query, re.M)
    if not at:
        raise ValueError(f"no RETURN in the {label} FINDING_QUERIES entry")
    projection = query[at.end():].strip()

    def cut(match: re.Match) -> str:
        alias = match.group("alias")
        return f"left(toStringOrNull({match.group('expr')}), {_PROJECTION_CUTS[alias]}) AS {alias}"

    return _CUT_FIELD.sub(cut, projection)


def _extra_columns(label: str, kind: Kind | None) -> list:
    have = set(projected_fields(label))
    columns = []
    for field in POOL_EXTRA_FIELDS:
        if field in have:
            continue
        if field == "raw_request":
            columns.append(f"left(toStringOrNull(n.raw_request), {RAW_REQUEST_CUT}) AS raw_request")
        else:
            columns.append(f"n.{field} AS {field}")
        have.add(field)
    for field in GUARD_FIELDS:
        if field in have:
            continue
        if field == "proven":
            columns.append(f"{_PROVEN} AS proven")
        elif field == "muted":
            columns.append("n:Muted AS muted")
        elif field == "stale_since":
            columns.append("toString(n.stale_since) AS stale_since")
        else:
            columns.append(f"n.{field} AS {field}")
        have.add(field)
    # The pool re-checks the kind in Python (`kind.matches`), so every property
    # its selector names must reach the row as the node holds it.
    for item in (kind.selector or ()) if kind else ():
        prop = str(item.get("prop") or "")
        if re.fullmatch(r"[a-z_][a-z0-9_]*", prop) and prop not in have:
            columns.append(f"n.{prop} AS {prop}")
            have.add(prop)
    key = ("coalesce(n.finding_id, n.id)" if label == "MalPackageFinding"
           else "coalesce(n.id, n.finding_id)")
    columns.append(f"{key} AS key")
    columns.append(f"{_NODE_ID} AS node_id")
    return columns


def _binding(label: str) -> str:
    """Rebind the finding under the entry's own variable name, plus its parents."""
    var = entry_var(label)
    binding = f"WITH n, n AS {var}"
    if label == "MalPackageFinding":
        binding += (", head([(p:Package)-[:FLAGGED_AS]->(n)"
                    " WHERE p.user_id = $userId AND p.project_id = $projectId | p]) AS pkg")
    return binding


def _check_label(label: str) -> None:
    if label not in POOL_LABELS:
        raise ValueError(f"{label!r} is not a Multi mute label")


def pool_query(label: str, kind: Kind) -> tuple[str, dict]:
    """The bounded pool of candidates of `kind`, closest to the seed first."""
    _check_label(label)
    where, params = kind_where(kind)
    js_clause = ("\n  AND coalesce(n.finding_type, '') <> 'js_file'"
                 if label == "JsReconFinding" else "")
    source = f"coalesce({fallback_source_expr(label)}, '')"
    query = f"""
MATCH (n:{label})
WHERE n.user_id = $userId AND n.project_id = $projectId
  AND NOT n:Muted AND n.stale_since IS NULL{js_clause}
  AND ({where})
{_binding(label)}
RETURN {entry_projection(label)},
       {", ".join(_extra_columns(label, kind))},
       CASE WHEN {source} = $mm_seed_source AND {_DETECTOR_EXPR} = $mm_seed_detector
            THEN 0 ELSE 1 END AS _mm_like,
       abs(({_ceiling_severity_rank(label)}) - $mm_seed_rank) AS _mm_distance
ORDER BY _mm_like, _mm_distance, key
LIMIT $pool_limit
"""
    return query, {**params, "pool_limit": POOL_MAX + 1}


def count_query(label: str, kind: Kind) -> tuple[str, dict]:
    """How many of `kind` are live, stale, or JS file containers (unmuted only)."""
    _check_label(label)
    where, params = kind_where(kind)
    js = ("coalesce(n.finding_type, '') = 'js_file'" if label == "JsReconFinding" else "false")
    query = f"""
MATCH (n:{label})
WHERE n.user_id = $userId AND n.project_id = $projectId
  AND NOT n:Muted
  AND ({where})
WITH n, {js} AS js_file
RETURN count(CASE WHEN n.stale_since IS NULL AND NOT js_file THEN 1 END) AS live,
       count(CASE WHEN n.stale_since IS NOT NULL AND NOT js_file THEN 1 END) AS stale,
       count(CASE WHEN js_file THEN 1 END) AS js_file
"""
    return query, params


_ANY_FINDING = "|".join(MUTEABLE_LABELS)


def locate_query() -> str:
    """The seed's label, mute state and raw properties, by key."""
    return f"""
MATCH (n:{_ANY_FINDING})
WHERE n.user_id = $userId AND n.project_id = $projectId
  AND (n.id = $seed_key OR n.finding_id = $seed_key)
RETURN {_FUNCTIONAL_LABEL} AS label, n:Muted AS muted,
       properties(n) AS props
LIMIT 2
"""


def seed_query(label: str, kind: Kind) -> str:
    """The seed, with exactly the pool's projection, plus its ordering keys."""
    _check_label(label)
    source = f"coalesce({fallback_source_expr(label)}, '')"
    return f"""
MATCH (n:{label})
WHERE n.user_id = $userId AND n.project_id = $projectId
  AND (n.id = $seed_key OR n.finding_id = $seed_key)
{_binding(label)}
RETURN {entry_projection(label)},
       {", ".join(_extra_columns(label, kind))},
       {source} AS _mm_source, {_DETECTOR_EXPR} AS _mm_detector
LIMIT 1
"""


def _plain(value):
    """Neo4j temporal values as ISO strings; everything else untouched."""
    if hasattr(value, "iso_format"):
        return value.iso_format()
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _row(record) -> dict:
    return {k: _plain(v) for k, v in dict(record).items()}


def _session(driver):
    """A session that does not log a notification per missing property.

    The pool projects every field any writer might set, and most graphs lack
    some of them; the server flags each one, and the driver would log them all
    as warnings on every suggestion.
    """
    try:
        return driver.session(notifications_min_severity="OFF")
    except TypeError:  # pragma: no cover - a driver older than the agent image's
        return driver.session()


def _read(driver, query: str, params: dict) -> list:
    def work(tx):
        return [_row(r) for r in tx.run(query, **params)]

    with _session(driver) as session:
        return session.execute_read(work)


def locate_seed(driver, user_id: str, project_id: str, seed_key: str) -> dict:
    """{label, muted, props}. Raises SeedMissing."""
    rows = _read(driver, locate_query(),
                 {"userId": user_id, "projectId": project_id, "seed_key": seed_key})
    if not rows:
        raise SeedMissing(seed_key)
    return rows[0]


def read_seed(driver, user_id: str, project_id: str, seed_key: str, kind: Kind) -> dict:
    rows = _read(driver, seed_query(kind.label, kind),
                 {"userId": user_id, "projectId": project_id, "seed_key": seed_key})
    if not rows:
        raise SeedMissing(seed_key)
    return rows[0]


def read_pool(driver, user_id: str, project_id: str, kind: Kind, seed: dict,
              seed_rank: int) -> list:
    query, params = pool_query(kind.label, kind)
    rows = _read(driver, query, {
        **params, "userId": user_id, "projectId": project_id,
        "mm_seed_source": str(seed.get("_mm_source") or ""),
        "mm_seed_detector": str(seed.get("_mm_detector") or ""),
        "mm_seed_rank": int(seed_rank),
    })
    for row in rows:
        row.pop("_mm_like", None)
        row.pop("_mm_distance", None)
    return rows


def read_counts(driver, user_id: str, project_id: str, kind: Kind) -> dict:
    query, params = count_query(kind.label, kind)
    rows = _read(driver, query, {**params, "userId": user_id, "projectId": project_id})
    row = rows[0] if rows else {}
    return {k: int(row.get(k) or 0) for k in ("live", "stale", "js_file")}
