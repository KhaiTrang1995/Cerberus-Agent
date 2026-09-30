"""The single-finding triage operations behind `/graph/triage`.

One engine, two doors: the Priority Board's routes and the MCP tools both land
here, through the webapp's `lib/triage/actions.ts`. Everything that decides
(what the evidence is, whether a review may be written, what the score becomes)
is in the agent; the graph mixin only locks, reads and writes.

These run in a worker thread (`asyncio.to_thread`), on the synchronous driver
of the long-lived triage `Neo4jClient`.
"""

from __future__ import annotations

import json
from typing import Optional

from neo4j import READ_ACCESS

from . import evidence, layers
from .fact_queries import FINDING_QUERIES, finding_query_by_id, normalise_finding_row
from .prompts import review as review_prompt


def read_finding_row(driver, user_id: str, project_id: str, finding_id: str,
                     label: Optional[str] = None) -> Optional[dict]:
    """The run's own row for one finding, or None when it is not in triage scope.

    Tries each finding query in order and stops at the first label that
    matches, narrowed to `label` when the caller knows it.
    """
    for query_def in FINDING_QUERIES:
        if label and query_def["label"] != label:
            continue
        with driver.session(default_access_mode=READ_ACCESS) as session:
            rows = [dict(r) for r in session.run(
                finding_query_by_id(query_def),
                findingId=finding_id, userId=user_id, projectId=project_id)]
        if rows:
            return normalise_finding_row(rows[0])
    return None


def _proven_at_base(props: dict) -> bool:
    base = layers.base_from_props(props)
    return bool(base and base.inputs.proven)


def _current_review(props: dict) -> Optional[dict]:
    verdict = props.get("triage_ai_verdict")
    if verdict not in ("real", "doubtful", "false_positive", "unclear"):
        return None
    return {
        "verdict": verdict,
        "channel": props.get("triage_ai_channel") or "builtin",
        "by": props.get("triage_ai_by") or "",
        "model": props.get("triage_ai_model") or "",
        "at": props.get("triage_ai_at"),
        "current": evidence.review_is_current(
            props.get("triage_ai_evidence_hash"), props.get("triage_evidence_hash")),
    }


def reviewability(props: dict, row: Optional[dict], bundle: str) -> Optional[str]:
    """Why an EXTERNAL review may not be written now, or None. `row` None = out of scope.

    Proof is not a reason here: a proven finding takes a review that raises it
    and refuses one that lowers it, which only `validate_external_review` can
    tell apart.
    """
    base = layers.base_from_props(props)
    return evidence.not_reviewable_reason(
        in_scope=row is not None,
        scored=base is not None,
        decided=evidence.person_decided(props.get("triage_status"), props.get("triage_source")),
        proven=False,
        state=(base.state if base else props.get("triage_state") or "open"),
        source=(row or {}).get("source"),
        bundle=bundle,
    )


def detail_props(detail_row: dict) -> dict:
    """The layer properties `get_triage_detail` returns, keyed as on the node."""
    keep = ("triage_status", "triage_source", "triage_base_factors", "triage_base_tier",
            "triage_base_tier_rule", "triage_base_state", "triage_tier_inputs",
            "triage_math_score", "triage_evidence_hash", "triage_ai_verdict",
            "triage_ai_corrections", "triage_ai_evidence_hash", "triage_ai_channel",
            "triage_ai_by", "triage_ai_model", "triage_ai_at", "triage_run_id",
            "triage_state")
    props = {k: detail_row.get(k) for k in keep}
    if props.get("triage_ai_verdict") == "":
        props["triage_ai_verdict"] = None
    return props


def finding_evidence(client, user_id: str, project_id: str, finding_id: str,
                     label: Optional[str] = None) -> dict:
    """What an external reviewer reads: the redacted bundle, its hash, and the rules."""
    detail = client.get_triage_detail(user_id, project_id, finding_id, label)
    if not detail.get("found"):
        return {"found": False, **({"ambiguous": detail["ambiguous"]}
                                   if detail.get("ambiguous") else {})}
    row = detail["row"]
    props = detail_props(row)
    finding = read_finding_row(client.driver, user_id, project_id, finding_id, row["label"])
    bundle = evidence.build_bundle(finding) if finding else ""
    digest = evidence.bundle_hash(bundle)
    reason = reviewability(props, finding, bundle)
    return {
        "found": True,
        "finding_id": row.get("id"),
        "label": row.get("label"),
        "evidence": bundle,
        "evidence_hash": digest,
        "matches_last_run": bool(digest) and digest == (props.get("triage_evidence_hash") or ""),
        "reviewable": reason is None,
        "not_reviewable_because": reason,
        # A review may raise a proven finding, never lower it.
        "proven": bool(row.get("proven_now")) or _proven_at_base(props),
        "review_survives_rescan": evidence.review_survives_rescan(
            row.get("label"), (finding or {}).get("source") or row.get("source")),
        "current_review": _current_review(props),
        "contract": layers.review_contract(),
    }


def submit_review(client, user_id: str, project_id: str, finding_id: str,
                  label: Optional[str], item: dict, evidence_hash: str,
                  token_prefix: str) -> dict:
    """Validate an external agent's review against the evidence, write it, rescore.

    The bundle is rebuilt from the graph here; the caller's `evidence_hash`
    must equal both it and the hash the last run recorded, so a review can only
    ever describe the evidence as it stands and as the base was scored on.
    """
    detail = client.get_triage_detail(user_id, project_id, finding_id, label)
    if not detail.get("found"):
        if detail.get("ambiguous"):
            return {"written": False, "reason": "ambiguous", "labels": detail["ambiguous"]}
        return {"written": False, "reason": "not_found"}
    found_label = detail["row"]["label"]
    finding = read_finding_row(client.driver, user_id, project_id, finding_id, found_label)
    bundle = evidence.build_bundle(finding) if finding else ""
    digest = evidence.bundle_hash(bundle)
    seen = (finding or {}).get("seen_updated_at")

    def decide(props, proven_now, updated_at, _label):
        if finding is not None and updated_at != seen:
            return {"refused": "evidence_changed"}
        reason = reviewability(props, finding, bundle)
        if reason:
            return {"refused": reason}
        if not evidence_hash or evidence_hash != digest \
                or (props.get("triage_evidence_hash") or "") != digest:
            return {"refused": "evidence_changed"}
        accepted, refusal = review_prompt.validate_external_review(
            item or {}, bundle, {"id": finding_id, "proven": _proven_at_base(props)},
            proven_now=proven_now)
        if refusal:
            return {"refused": refusal}
        return {
            "review": layers.review_props(
                accepted, channel="mcp", by=token_prefix, model="",
                evidence_hash=digest, prompt_version=""),
            "dropped": accepted.get("dropped") or [],
            "accepted": {k: accepted[k] for k in ("verdict", "impact_multiplier")}
                        | {"disputed_facts": [d["fact"] for d in accepted["disputed_facts"]]},
        }

    accepted_summary: dict = {}

    def decide_and_remember(props, proven_now, updated_at, lbl):
        out = decide(props, proven_now, updated_at, lbl)
        if out.get("accepted"):
            accepted_summary.clear()
            accepted_summary.update(out["accepted"])
        return out

    result = client.write_review(user_id, project_id, finding_id, decide_and_remember,
                                 layers.combine_props, label=found_label)
    if result.get("written"):
        if accepted_summary:
            result["accepted"] = dict(accepted_summary)
        result["review_survives_rescan"] = evidence.review_survives_rescan(
            found_label, (finding or {}).get("source"))
    return result


def parse_json_fields(row: dict) -> dict:
    """The JSON-string properties of a board row, parsed, for a caller that wants data."""
    out = dict(row or {})
    for key in ("triage_factors", "triage_base_factors", "triage_tier_inputs",
                "triage_ai_corrections", "triage_proof"):
        value = out.get(key)
        if isinstance(value, str) and value:
            try:
                out[key] = json.loads(value)
            except ValueError:
                pass
    return out
