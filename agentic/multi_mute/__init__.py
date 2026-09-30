"""Multi mute: suggest the other findings a person would mute for the same reason.

The engine is split so that everything that decides anything is pure and
testable without a graph or a model:

- `kind`     which findings count as "the same type" as the seed;
- `pool`     what is never a candidate, and the seed's ceiling;
- `clusters` evidence fingerprints, clusters, the exact lenses, ranking;
- `prompt`   the system prompt, the rendered user turn, redaction;
- `validate` parsing and checking the model's answer, the pre-check rule and the
             group assembly;
- `batches`  the in-process store of suggestions a later mute may draw from.

The graph reads (`queries`) and the orchestration (`service`) sit on top.

THE ROW CONTRACT
Every function here takes finding rows as plain dicts, the seed included. A row
carries:

- `key`: the stored `id`, or `finding_id` for a MalPackageFinding. Never
  Neo4j's elementId, which changes when an activation recreates the node;
- `label`: the functional label, one of `MUTEABLE_LABELS`;
- `node_id`: Neo4j's internal id as a string, for display only;
- every field the seed label's `FINDING_QUERIES` entry projects, under the same
  alias (so `source` is that entry's coalesced source expression, and
  `triage_host` its resolved host);
- `POOL_EXTRA_FIELDS`: what `evidence.build_bundle` and `grouping.group_key`
  read that the `FINDING_QUERIES` entries do not project;
- `GUARD_FIELDS`: `proven` (the triage mixin's `_PROVEN`, as a bool),
  `validation_status`, `verdict`, `confidence_tier`, `triage_tier`,
  `triage_factors` (a JSON string or a dict; read defensively),
  `triage_ai_verdict`, `triage_group_key`, `finding_type`, `stale_since`, and
  `muted` (bool).

Pass RAW rows, as the pool query returns them. The functions normalise a copy
(`fact_queries.normalise_finding_row`) where a reused triage function expects
it, and redact (`prompt.redact_row`) wherever target text is read. Both steps
are idempotent, so a row that was already normalised or redacted is fine too.
The one thing normalising loses is a raw `host` that differs from
`triage_host`, which is why the host is resolved from the raw row first.

`REQUIRED_ROW_FIELDS[label]` is the set a pool projection for that label must
cover; the projection-coverage test asserts against it.
"""
from __future__ import annotations

import re

from cypherfix_triage.fact_queries import FINDING_QUERIES

#: Read by `build_bundle` and `group_key` (and by the fingerprint), absent from
#: every `FINDING_QUERIES` entry. Plan §7.2, plus `source_tool`: the
#: MalPackageFinding projection folds it into `source`, but the bundle's "Tool"
#: line is what tells the model an OSV listing from a GuardDog heuristic.
POOL_EXTRA_FIELDS = (
    "matcher_name", "raw_request", "fuzzing_parameter",
    "missing_header", "provider", "technique", "vector", "vulnerability_type",
    "ai_owasp_llm_id", "payload_class",
    "matched_text", "sample", "location", "path",
    "target_port", "solution_type",
    "cwe_ids",
    "source_tool",
)

GUARD_FIELDS = (
    "proven", "validation_status", "verdict", "confidence_tier",
    "triage_tier", "triage_factors", "triage_ai_verdict", "triage_group_key",
    "finding_type", "stale_since", "muted",
)

IDENTITY_FIELDS = ("key", "label", "node_id")

#: ExploitGvm is muteable by a person but never a Multi mute seed or candidate:
#: it is a confirmed exploitation.
POOL_LABELS = (
    "Vulnerability", "JsReconFinding", "Secret", "MultiscannerFinding",
    "GithubSecret", "GithubSensitiveFile", "MalPackageFinding",
)

_ALIAS = re.compile(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)")
_LINE_COMMENT = re.compile(r"//[^\n]*")


def projected_fields(label: str) -> frozenset:
    """The aliases `label`'s FINDING_QUERIES entry returns, empty when it has none."""
    for entry in FINDING_QUERIES:
        if entry.get("label") == label:
            query = _LINE_COMMENT.sub("", entry["query"])
            return frozenset(_ALIAS.findall(query))
    return frozenset()


REQUIRED_ROW_FIELDS = {
    label: frozenset(IDENTITY_FIELDS) | projected_fields(label)
    | frozenset(POOL_EXTRA_FIELDS) | frozenset(GUARD_FIELDS)
    for label in POOL_LABELS
}
