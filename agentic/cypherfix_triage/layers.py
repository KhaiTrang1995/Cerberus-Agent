"""Stored triage properties <-> the score model's layers.

A finding carries three layers as node properties (see `TRIAGE_PROPS` in
graph_db/mixins/recon/triage_mixin.py). This module is the one place that reads
them back into `score_model.BaseLayer` / `ReviewLayer` / `DecisionLayer`, and the
one place that turns an accepted review into the properties it is stored as, so
the run, a person's verdict and an external agent's review all combine the same
stored shape the same way.

Pure: no I/O. The graph mixin calls `combine_props` inside its write
transaction, on the properties it just read under the node's lock.
"""

from __future__ import annotations

import json
from typing import Optional

from . import evidence, score_model as sm
from .prompts import review as review_prompt


def _json(value):
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def base_from_props(props: dict) -> Optional[sm.BaseLayer]:
    """The stored base layer, or None when no v3.2 run has scored this finding."""
    props = props or {}
    factors = _json(props.get("triage_base_factors"))
    if not isinstance(factors, dict) or not factors:
        return None
    values = sm.factor_values(factors)
    state = props.get("triage_base_state") or sm.STATE_OPEN
    risk = 0.0 if state in sm.RESOLVED_STATES else min(
        1.0, values["C"] * values["L"] * values["I"] * values["R"])
    return sm.BaseLayer(
        factors=factors,
        tier=props.get("triage_base_tier") or "T4",
        tier_rule=props.get("triage_base_tier_rule") or "",
        state=state if state in (sm.STATE_OPEN, *sm.RESOLVED_STATES) else sm.STATE_OPEN,
        inputs=sm.TierInputs.from_dict(_json(props.get("triage_tier_inputs"))),
        score=sm.as_float(props.get("triage_math_score")) or 0.0,
        risk=round(risk, 6),
    )


def review_from_props(props: dict) -> Optional[sm.ReviewLayer]:
    """The stored review, valid or not. `combine_layers` decides validity."""
    props = props or {}
    verdict = props.get("triage_ai_verdict")
    if verdict not in sm.REVIEW_VERDICTS:
        return None
    corrections = _json(props.get("triage_ai_corrections")) or {}
    if not isinstance(corrections, dict):
        corrections = {}
    channel = props.get("triage_ai_channel") or "builtin"
    return sm.ReviewLayer(
        verdict=verdict,
        evidence_hash=props.get("triage_ai_evidence_hash") or "",
        channel=channel if channel in sm.REVIEW_CHANNELS else "builtin",
        impact_multiplier=sm.as_float(corrections.get("impact_multiplier")) or 1.0,
        impact_quote=str(corrections.get("impact_quote") or ""),
        disputed_facts=[d for d in (corrections.get("disputed_facts") or [])
                        if isinstance(d, dict)],
    )


def decision_from_props(props: dict) -> Optional[sm.DecisionLayer]:
    props = props or {}
    if evidence.person_decided(props.get("triage_status"), props.get("triage_source")):
        return sm.DecisionLayer(props["triage_status"])
    return None


def combine_props(props: dict, proven_now: bool = False) -> Optional[dict]:
    """The final values for a finding, from its stored layers. None without a base."""
    base = base_from_props(props)
    if base is None:
        return None
    final = sm.combine_layers(
        base, review_from_props(props), decision_from_props(props),
        (props or {}).get("triage_evidence_hash") or "", proven_now)
    return final.as_dict()


def review_props(accepted: dict, *, channel: str, by: str, model: str,
                 evidence_hash: str, prompt_version: str) -> dict:
    """A validated review (`validate_review` output) as the properties it is stored as.

    `triage_fix_lever` travels with the review and nowhere else: it is written
    only when a review is, and never over a person's decision.
    """
    return {
        "triage_ai_verdict": accepted["verdict"],
        "triage_ai_corrections": {
            "verdict": accepted["verdict"],
            "impact_multiplier": accepted.get("impact_multiplier", 1.0),
            "impact_quote": accepted.get("impact_quote") or "",
            "disputed_facts": accepted.get("disputed_facts") or [],
        },
        "triage_ai_quote": accepted.get("evidence_quote") or None,
        "triage_ai_model": model or None,
        "triage_ai_why": accepted.get("why") or None,
        "triage_ai_channel": channel,
        "triage_ai_by": by or "",
        "triage_ai_evidence_hash": evidence_hash or None,
        "triage_ai_prompt_version": prompt_version or None,
        "triage_fix_lever": accepted.get("fix_lever") or None,
    }


#: What an external reviewer is told it may say. Returned by
#: `get_finding_evidence`, so an agent never has to guess the vocabulary.
FACT_MEANINGS = {
    "reachable": "the evidence shows the target cannot actually be reached as the model assumed",
    "tool_confirmed": "the scanner's match is not a real confirmation (an error page, a default response)",
    "extracted_proof": "what the scanner extracted is not proof of the issue",
    "dast_confirmed": "the DAST hit does not show the injected behaviour",
    "exploitable_class": "the finding is not really of the exploitable class it was filed under",
    "public_poc": "the public proof of concept does not apply to what the evidence shows",
    "sensitive_asset": "the asset is not sensitive (a static page, a placeholder)",
    "credential_in_response": "the credential-looking text is a sample or placeholder, not a credential",
}


def review_contract() -> dict:
    return {
        "verdicts": {
            "real": "the evidence shows what the finding claims; quote the part that shows it",
            "doubtful": "the evidence makes the finding unlikely; quote why",
            "false_positive": "the evidence shows it is not real (an error page, a sample, a comment); quote it",
            "unclear": "the evidence does not tell; changes nothing",
        },
        "disputable_facts": dict(FACT_MEANINGS),
        "impact_multiplier": {"min": review_prompt.MULTIPLIER_MIN,
                              "max": review_prompt.MULTIPLIER_MAX,
                              "needs": "impactQuote"},
        "min_quote_length": 8,
        "max_quote_length": review_prompt.MAX_QUOTE,
        "max_why": review_prompt.MAX_WHY,
        "max_fix_lever": review_prompt.MAX_FIX_LEVER,
    }
