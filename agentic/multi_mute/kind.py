"""Which findings are "the same type" as the seed (plan §3, §7.1).

The type is the Mute Rules KIND whose `graph_label` and selector match the seed,
so Multi mute and Mute Rules agree on what a type is. Labels with no kind yet
(GVM, GitHub secrets and files, the secret multiscanner and AI attack are only
`planned`) fall back to the label plus the same coalesced source expression that
label's `FINDING_QUERIES` entry projects, so the pool and the triage board read
"source" the same way.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
from graph_db.node_filters.catalog import CatalogError, load_catalog
from graph_db.node_filters.cypher import selector_clause

logger = logging.getLogger(__name__)


class SeedNotMuteable(ValueError):
    """The seed can be muted by a person, but not used for Multi mute."""


@dataclass(frozen=True)
class Kind:
    """The seed's type.

    `selector` holds the catalog kind's selector items (possibly empty: the
    kind is the whole label) and is None for a fallback kind, which is typed by
    `source_expr` (a Cypher expression over `n`) equal to `source_value`.
    """
    id: str
    label: str
    display: str
    selector: tuple | None
    source_expr: str | None
    source_value: str | None


#: Per label, the `source` its FINDING_QUERIES entry projects: the properties
#: coalesced in order, then the literal default. A test re-derives each one from
#: the query text, so the two cannot drift apart.
_SOURCE_CHAIN = {
    "Vulnerability": (("source",), None),
    "Secret": (("source",), "js_recon"),
    "JsReconFinding": ((), "js_recon"),
    "MultiscannerFinding": (("source", "source_type"), "trufflehog"),
    "GithubSecret": ((), "github_hunt"),
    "GithubSensitiveFile": ((), "github_hunt"),
    "MalPackageFinding": (("source_tool",), "osv"),
}

_LABEL_DISPLAY = {
    "Vulnerability": "Vulnerabilities",
    "Secret": "Secrets",
    "JsReconFinding": "JS Recon findings",
    "MultiscannerFinding": "Secret multiscanner findings",
    "GithubSecret": "GitHub secrets",
    "GithubSensitiveFile": "GitHub sensitive files",
    "MalPackageFinding": "Malicious packages",
}


def _cypher_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def fallback_source_expr(label: str) -> str:
    """The coalesced source expression over `n` for a label with no catalog kind."""
    props, default = _SOURCE_CHAIN[label]
    parts = [f"n.{p}" for p in props]
    if default is not None:
        parts.append(_cypher_literal(default))
    if len(parts) == 1:
        return parts[0]
    return f"coalesce({', '.join(parts)})"


def seed_source(label: str, props: dict) -> str:
    """The value `fallback_source_expr(label)` has on this row, '' when null.

    Works on raw node properties and on a pool row alike. A pool row carries the
    projected `source`, which for MalPackageFinding stands in for the
    `source_tool` the row may not carry.
    """
    props = props or {}
    chain, default = _SOURCE_CHAIN[label]
    if not chain:
        return default or ""
    for prop in chain:
        value = props.get(prop)
        if value is not None:
            return str(value)
    if "source" not in chain and props.get("source") is not None:
        return str(props["source"])
    return default or ""


def selector_matches(select, props: dict) -> bool:
    """Python mirror of `selector_clause`'s Cypher, including its null handling.

    `eq` and `in` never admit a missing property (Cypher compares to null);
    `not_eq` does, because the Cypher coalesces to ''.
    """
    props = props or {}
    for item in select or ():
        value = props.get(item["prop"])
        if "eq" in item:
            if value is None or value != item["eq"]:
                return False
        elif "in" in item:
            if value is None or value not in item["in"]:
                return False
        elif "not_eq" in item:
            if ("" if value is None else value) == item["not_eq"]:
                return False
        else:
            return False
    return True


def _catalog_kinds(catalog) -> dict:
    if catalog is None:
        try:
            catalog = load_catalog()
        except CatalogError as e:
            # Same posture as Mute Rules: an unreadable catalog types nothing,
            # so every seed falls back to label + source.
            logger.warning("multi mute: node-filter catalog unavailable: %s", e)
            return {}
    kinds = getattr(catalog, "kinds", None)
    if kinds is None and isinstance(catalog, dict):
        kinds = catalog.get("kinds")
    return kinds or {}


def _check_muteable(label: str, props: dict) -> None:
    if label == "ExploitGvm":
        raise SeedNotMuteable("ExploitGvm is a confirmed exploitation")
    if label not in MUTEABLE_LABELS or label not in _SOURCE_CHAIN:
        raise SeedNotMuteable(f"{label!r} is not a muteable finding label")
    # Muting a JS file container orphans every finding under it.
    if label == "JsReconFinding" and str((props or {}).get("finding_type") or "") == "js_file":
        raise SeedNotMuteable("a JS file container is not a finding")


def resolve_kind(label: str, props: dict, catalog=None) -> Kind:
    """The seed's kind: a catalog kind when one matches, else label + source.

    `catalog` is a loaded `Catalog`, or a dict with a `kinds` map; None loads
    the runtime catalog. Raises `SeedNotMuteable`.
    """
    label = str(label or "")
    props = props or {}
    _check_muteable(label, props)

    kinds = _catalog_kinds(catalog)
    for kind_id in sorted(kinds):
        entry = kinds[kind_id]
        if entry.get("behaviour", "finding") != "finding" or entry.get("graph_label") != label:
            continue
        select = entry.get("select") or []
        if selector_matches(select, props):
            return Kind(id=kind_id, label=label, display=str(entry.get("label") or kind_id),
                        selector=tuple(dict(item) for item in select),
                        source_expr=None, source_value=None)

    source = seed_source(label, props)
    display = _LABEL_DISPLAY[label]
    if _SOURCE_CHAIN[label][0] and source:
        display = f"{display} ({source})"
    return Kind(id=f"{label}:{source}", label=label, display=display, selector=None,
                source_expr=fallback_source_expr(label), source_value=source)


def matches(kind: Kind, row: dict) -> bool:
    """Is this row of `kind`? The Python mirror of `kind_where`."""
    row = row or {}
    if str(row.get("label") or "") != kind.label:
        return False
    if kind.selector is not None:
        return selector_matches(kind.selector, row)
    return seed_source(kind.label, row) == (kind.source_value or "")


def kind_where(kind: Kind) -> tuple[str, dict]:
    """A boolean Cypher expression over `n` selecting `kind`, and its parameters.

    It does not constrain the label or the tenant; the caller's MATCH does. A
    catalog kind's parameters are named `sel0`, `sel1`, ... (by
    `selector_clause`); a fallback kind's is `mm_source`. A kind with an empty
    selector is the whole label, `true`.
    """
    if kind.selector is not None:
        clause, params = selector_clause(list(kind.selector))
        parts = [c for c in clause.split("\n  AND ") if c.strip()]
        return (" AND ".join(parts) if parts else "true"), params
    # coalesce so a seed with no source finds the other findings with none.
    return f"coalesce({kind.source_expr}, '') = $mm_source", {"mm_source": kind.source_value or ""}
