"""Shared by the live-graph triage tests: a publish row and the run's combine.

Not a test module (no `test_` prefix). It builds rows exactly the way the
orchestrator does and hands the mixin the orchestrator's own publish-time
`combine`, so a live test exercises the real layered publish end to end.
"""

from cypherfix_triage import evidence, score_model as sm
from cypherfix_triage.orchestrator import TriageOrchestrator

#: The orchestrator's publish-time combine. It reads no instance state.
PUBLISH_COMBINE = TriageOrchestrator._publish_combine(None)


def layer_row(finding: dict, run_id: str = "run-live", review=None, seen=None,
              facts=None, detector=None, mark_not_reviewed=False) -> dict:
    """One publish row for `finding` (a dict of node properties + id/label)."""
    facts = facts or sm.ProjectFacts()
    result = sm.score(finding, facts, {})
    base = sm.BaseLayer.from_result(result)
    bundle = evidence.build_bundle(finding)
    return {
        "id": finding["id"],
        "label": finding.get("label") or "Vulnerability",
        "math_score": base.score,
        "base_factors": base.factors,
        "base_tier": base.tier,
        "base_tier_rule": base.tier_rule,
        "base_state": base.state,
        "tier_inputs": base.inputs.as_dict(),
        "evidence_hash": evidence.bundle_hash(bundle) or None,
        "signals": result.signals,
        "host": result.host,
        "group_key": "g",
        "detector": detector or sm.detector_key(finding),
        "run_id": run_id,
        "model_version": sm.SCORE_MODEL_VERSION,
        "intel_date": None,
        "proof": None,
        "mark_not_reviewed": mark_not_reviewed,
        "review": review,
        "seen_updated_at": seen,
    }
