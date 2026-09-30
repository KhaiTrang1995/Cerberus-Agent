"""The pool: what is never a candidate, and the seed's ceiling (plan §3, §7.3).

These rules run in code before anything reaches the model, and the ceiling is
checked again under the write lock by the graph mixin's `mute_batch`, which
cannot import this module. So the mixin MIRRORS `severity_rank` in Cypher:

- lowercase and trim the severity;
- a word maps through `SEVERITY_RANK`;
- a number (CVSS-like 0-10, or 0-100 divided by 10) maps >= 9 critical,
  >= 7 high, >= 4 medium, > 0 low, else info;
- `info` on a row whose `source` is `osv` is UNKNOWN: OSV writes `info` to mean
  "never graded";
- anything else, null included, is UNKNOWN, and UNKNOWN ranks as medium.

It mirrors the proof markers case-insensitively too (`toLower(trim(...))`),
and the tier through `score_model.TIER_LEVELS`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from cypherfix_triage.score_model import TIER_LEVELS, normalise_severity

from .kind import Kind, matches

POOL_MAX = 2000

#: Every word `normalise_severity` can return.
SEVERITY_RANK = {
    "info": 0, "informational": 0, "none": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4,
}
UNKNOWN_RANK = SEVERITY_RANK["medium"]

_CANONICAL = {"informational": "info", "none": "info", "moderate": "medium"}

#: Exclusion reasons, in the order they are checked. `js_file` comes first
#: because a JS file container also fails its kind's selector, and the modal
#: names it separately.
EXCLUSION_REASONS = (
    "js_file", "other_kind", "muted", "stale", "proven", "kept_visible",
    "proof_seed_lacks", "above_seed",
)


def normalised_severity(row: dict) -> str:
    """One of info, low, medium, high, critical, or `unknown`."""
    row = row or {}
    word = normalise_severity(row.get("severity"))
    if word is None:
        return "unknown"
    word = _CANONICAL.get(word, word)
    if word == "info" and str(row.get("source") or "").strip().lower() == "osv":
        return "unknown"
    return word


def severity_rank(row: dict) -> int:
    """0 (info) to 4 (critical); unknown ranks as medium."""
    return SEVERITY_RANK.get(normalised_severity(row), UNKNOWN_RANK)


def tier_rank(tier) -> int | None:
    """TIER_LEVELS' value (T1 = 3, the most urgent), or None when untriaged."""
    return TIER_LEVELS.get(str(tier or "").strip().upper())


def _marker(value) -> str:
    return str(value or "").strip().lower()


def _proof(row: dict) -> dict:
    return {
        "validated": _marker(row.get("validation_status")) == "validated",
        "malicious": _marker(row.get("verdict")) == "malicious",
        "confirmed": _marker(row.get("confidence_tier")) == "confirmed",
    }


def ceiling_for(seed: dict) -> dict:
    """What a candidate may not exceed: the seed's own level and proof."""
    seed = seed or {}
    return {
        "severity_rank": severity_rank(seed),
        "tier_rank": tier_rank(seed.get("triage_tier")),
        **_proof(seed),
    }


def ceiling_reason(row: dict, ceiling: dict) -> str | None:
    """`proof_seed_lacks`, `above_seed`, or None when the row is within the ceiling."""
    proof = _proof(row or {})
    if any(proof[m] and not ceiling.get(m) for m in proof):
        return "proof_seed_lacks"
    if severity_rank(row) > int(ceiling.get("severity_rank", UNKNOWN_RANK)):
        return "above_seed"
    mine, theirs = tier_rank((row or {}).get("triage_tier")), ceiling.get("tier_rank")
    # Only when both are triaged: an untriaged tier says nothing either way.
    if mine is not None and theirs is not None and mine > theirs:
        return "above_seed"
    return None


def within_ceiling(row: dict, ceiling: dict) -> bool:
    return ceiling_reason(row, ceiling) is None


@dataclass
class PoolResult:
    candidates: list
    excluded: dict = field(default_factory=dict)
    total: int = 0
    truncated: bool = False


def _row_keys(row: dict) -> set:
    return {str(row[k]) for k in ("key", "id", "finding_id") if row.get(k)}


def _is_seed(row: dict, seed: dict) -> bool:
    return (str(row.get("label") or "") == str(seed.get("label") or "")
            and str(row.get("key") or "") == str(seed.get("key") or ""))


def exclusion_reason(row: dict, kind: Kind, ceiling: dict, exempt: set) -> str | None:
    """The first rule that keeps this row out of the pool, or None."""
    label = str(row.get("label") or "")
    if label == "JsReconFinding" and str(row.get("finding_type") or "") == "js_file":
        return "js_file"
    if not matches(kind, row):
        return "other_kind"
    if row.get("muted"):
        return "muted"
    if row.get("stale_since") not in (None, ""):
        return "stale"
    # _PROVEN, not the Mute Rules guard: a person's own `likely_noise` verdict
    # makes a finding a better candidate, never a protected one.
    if row.get("proven"):
        return "proven"
    if any((label, k) in exempt for k in _row_keys(row)):
        return "kept_visible"
    return ceiling_reason(row, ceiling)


def apply_pool_rules(seed: dict, kind: Kind, rows: list, exempt_pairs: list,
                     total: int | None = None) -> PoolResult:
    """The candidates, and how many rows each rule left out.

    `rows` arrive closest-first from the pool query, which reads at most
    POOL_MAX + 1; past POOL_MAX the tail is dropped and `truncated` is set.
    `exempt_pairs` are `[label, key]`: findings a person brought back. The seed
    is never a candidate and is not counted as an exclusion.
    """
    seed = seed or {}
    rows = list(rows or [])
    truncated = len(rows) > POOL_MAX
    ceiling = ceiling_for(seed)
    exempt = {(str(p[0]), str(p[1])) for p in (exempt_pairs or [])
              if isinstance(p, (list, tuple)) and len(p) >= 2}

    excluded = {reason: 0 for reason in EXCLUSION_REASONS}
    candidates = []
    for row in rows[:POOL_MAX]:
        if not isinstance(row, dict) or _is_seed(row, seed):
            continue
        reason = exclusion_reason(row, kind, ceiling, exempt)
        if reason:
            excluded[reason] += 1
        else:
            candidates.append(row)
    return PoolResult(candidates=candidates, excluded=excluded,
                      total=len(rows) if total is None else int(total),
                      truncated=truncated)
