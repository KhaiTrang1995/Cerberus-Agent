/**
 * Every property the Priority Board's triage layers store on a finding node.
 *
 * Mirrors `TRIAGE_PROPS` in graph_db/mixins/recon/triage_mixin.py, which is the
 * declaration; `properties.test.ts` fails when the two drift. Readers here use
 * it to treat the whole set the same way: Recon Delta ignores it (a triage
 * write is not a scan change), and "Ask agent about this node" keeps only the
 * parts that are safe to hand a model with tools.
 */
export const TRIAGE_PROPERTIES = [
  // DECISION: a person (the UI, or an MCP token carrying their authority)
  'triage_status',
  'triage_confidence',
  'triage_reason',
  'triage_source',
  'triage_verdict_channel',
  'triage_verdict_by',
  'triage_verdict_token',
  'triage_verdict_at',
  // BASE: the rules, written only by a run's publish
  'triage_math_score',
  'triage_base_factors',
  'triage_base_tier',
  'triage_base_tier_rule',
  'triage_base_state',
  'triage_tier_inputs',
  'triage_evidence_hash',
  'triage_signals',
  'triage_host',
  'triage_group_key',
  'triage_detector',
  'triage_run_id',
  'triaged_at',
  'triage_model_version',
  'triage_intel_date',
  'triage_proof',
  'triage_cluster_id',
  // REVIEW: the built-in AI in a run, or an external agent over MCP
  'triage_ai_verdict',
  'triage_ai_corrections',
  'triage_ai_quote',
  'triage_ai_model',
  'triage_ai_at',
  'triage_ai_why',
  'triage_ai_channel',
  'triage_ai_by',
  'triage_ai_evidence_hash',
  'triage_ai_prompt_version',
  'triage_fix_lever',
  // FINAL: combine_layers, written by a publish or an instant rescore
  'triage_priority_score',
  'triage_tier',
  'triage_tier_rule',
  'triage_risk',
  'triage_factors',
  'triage_state',
  'triage_decided_by',
  'triage_rescored_at',
] as const

/**
 * Free text an external agent or the review model wrote, and JSON blobs that
 * carry it. Never handed to the in-app agent (which has tools) as node context:
 * it would be text an unattended MCP client planted in another model's prompt.
 */
export const TRIAGE_TEXT_PROPERTIES = [
  'triage_reason',
  'triage_ai_why',
  'triage_fix_lever',
  'triage_ai_quote',
  'triage_ai_corrections',
  'triage_base_factors',
  'triage_tier_inputs',
] as const
