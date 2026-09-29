/**
 * How the Priority Board reads a finding's three layers (rules, review,
 * decision) off a board row. Pure: the table and the detail panel both render
 * from these, so a chip or a score line cannot say one thing in the row and
 * another in the panel.
 *
 * The server computes the final values; nothing here scores anything. It only
 * decides which layer to NAME, and compares the final factors with the
 * rules-only ones so a moved factor can be pointed at.
 */

export type TriageStatus = 'confirmed' | 'likely_noise' | 'unreviewed'

/**
 * The four tiers the score model assigns. These are no longer score BANDS: the
 * tier is decided by fixed rules on the facts, and the score is built from it
 * (25 x tier + 25 x risk), so reading the tier back off the number would be
 * backwards. The server sends `triage_tier`; `tierForScore` is only the
 * fallback for a row from before the model existed.
 */
export type TriageTier = 'T1' | 'T2' | 'T3' | 'T4'

export const TIER_ORDER: TriageTier[] = ['T1', 'T2', 'T3', 'T4']

export const TIER_LABELS: Record<TriageTier, string> = {
  T1: 'Act now',
  T2: 'Act soon',
  T3: 'Plan',
  T4: 'Track',
}

/** One board row, as `GET /api/triage/findings` and the verdict answer send it. */
export interface TriageFinding {
  id: string
  /** Neo4j's internal id, for the Node ID column only. `id` stays the key every
   *  verdict and mute is written against. */
  node_id?: string | null
  label: string
  name: string
  severity: string
  source: string
  location?: string
  host?: string
  /** Which of the board's four sections this row belongs in. Decided by the
   *  server so the client cannot disagree with it. */
  section?: number
  triage_state?: string
  triage_status: TriageStatus
  triage_confidence: number | null
  /** A person's reason, sent only while their decision stands. */
  triage_reason: string | null
  triage_source?: string | null
  triage_tier?: string
  triage_tier_rule?: string
  /** FINAL factors, JSON `{C,L,I,R: {value, evidence}}`. */
  triage_factors?: string | null
  /** The rules-only score. */
  triage_math_score?: number | null
  triage_risk?: number | null
  /** The FINAL score. */
  triage_priority_score?: number | null
  triage_signals?: string[]
  triage_group_key?: string
  triage_run_id?: string
  triage_detector?: string
  /** Rules-only factors; null on a row no layered run has scored yet. */
  triage_base_factors?: string | null
  triage_base_tier?: string
  triage_base_tier_rule?: string
  triage_base_state?: string | null
  /** JSON `{proven, kev}`: the tier inputs that are not factors. */
  triage_tier_inputs?: string | null
  triage_decided_by?: 'rules' | 'review' | 'person' | string
  /** The channel of a person's decision: `app`, `mcp`, or '' with none. */
  decided_via?: string
  triage_verdict_token?: string
  triage_verdict_at?: string | null
  triage_rescored_at?: string | null
  triage_ai_verdict?: string | null
  triage_ai_corrections?: string | null
  triage_ai_quote?: string | null
  triage_ai_model?: string
  triage_ai_at?: string | null
  triage_ai_why?: string
  reviewed_via?: 'builtin' | 'mcp' | 'none' | string
  /** The token prefix of an MCP review. */
  triage_ai_by?: string
  review_state?: 'current' | 'stale' | 'none' | string
  triage_fix_lever?: string
  triage_proof?: string | null
  triaged_at?: string | null
  updated_at?: string | null
  stale_since?: string | null
}

export interface Factor {
  value: number
  evidence: string
}

export type Factors = Record<string, Factor>

export const FACTOR_KEYS = ['C', 'L', 'I', 'R'] as const

export const FACTOR_NAMES: Record<string, string> = {
  C: 'real', L: 'exploit', I: 'impact', R: 'reach',
}

/** Mirrors score_model.py: 25 x tier_level + 25 x risk. */
export function tierForScore(score: number | null | undefined): TriageTier {
  const s = score ?? -1
  if (s >= 75) return 'T1'
  if (s >= 50) return 'T2'
  if (s >= 25) return 'T3'
  return 'T4'
}

export function asTier(value: string | null | undefined): TriageTier | null {
  return TIER_ORDER.includes(value as TriageTier) ? (value as TriageTier) : null
}

export function tierOf(f: TriageFinding): TriageTier {
  return asTier(f.triage_tier) ?? tierForScore(f.triage_priority_score)
}

/** A JSON property as the graph stores it. Never throws: an older row simply
 *  has nothing to show. */
export function parseJson<T>(raw: unknown): T | null {
  if (raw === null || raw === undefined || raw === '') return null
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
    return parsed && typeof parsed === 'object' ? (parsed as T) : null
  } catch {
    return null
  }
}

export function parseFactors(raw: unknown): Factors | null {
  return parseJson<Factors>(raw)
}

export function formatFactor(key: string, value: number | undefined): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '?'
  return key === 'C' || key === 'L' ? `${Math.round(value * 100)}%` : value.toFixed(2)
}

/** The factors a review or a decision moved away from the rules' value. Empty
 *  for a row with no rules-only factors: there is nothing to compare with. */
export function changedFactors(finalF: Factors | null, baseF: Factors | null): Set<string> {
  const out = new Set<string>()
  if (!finalF || !baseF) return out
  for (const key of FACTOR_KEYS) {
    const a = finalF[key]?.value
    const b = baseF[key]?.value
    if (typeof a === 'number' && typeof b === 'number' && Math.abs(a - b) >= 0.005) out.add(key)
  }
  return out
}

/** The evidence behind each factor, one line per factor, for a hover. */
export function factorEvidence(factors: Factors | null): string {
  if (!factors) return ''
  return FACTOR_KEYS
    .map(key => {
      const evidence = factors[key]?.evidence
      return evidence ? `${FACTOR_NAMES[key]}: ${evidence}` : ''
    })
    .filter(Boolean)
    .join('\n')
}

/** True while a person's Real / False positive stands. A Reset leaves status
 *  `unreviewed`, which is NOT a decision (B8). */
export function personDecided(f: Pick<TriageFinding, 'triage_status' | 'triage_source'>): boolean {
  return f.triage_source === 'human' &&
    (f.triage_status === 'confirmed' || f.triage_status === 'likely_noise')
}

export interface Chip {
  text: string
  title: string
}

export function decisionChip(f: TriageFinding): Chip | null {
  if (!personDecided(f)) return null
  const outcome = f.triage_status === 'confirmed' ? 'Real' : 'False positive'
  if (f.decided_via === 'mcp') {
    const token = f.triage_verdict_token || 'token'
    return {
      text: `You via MCP · ${token}: ${outcome}`,
      title: `Decided with your MCP token ${token}. A person's decision outranks every review.`,
    }
  }
  return {
    text: `You: ${outcome}`,
    title: "Your decision. It outranks every review, and no run changes it.",
  }
}

/** What a review concluded, in words an operator can act on. */
export const REVIEW_VERDICT_LABELS: Record<string, string> = {
  real: 'Real',
  doubtful: 'Doubtful',
  false_positive: 'False positive',
  unclear: 'Unclear',
}

/** The chip's tint follows what the review concluded. */
export const REVIEW_VERDICT_TONE: Record<string, 'real' | 'doubtful' | 'dismissed'> = {
  real: 'real',
  doubtful: 'doubtful',
  unclear: 'doubtful',
  false_positive: 'dismissed',
}

/** `builtin`, `mcp` or `none`, tolerating a row from an agent that predates the field. */
export function reviewedVia(f: TriageFinding): string {
  if (f.reviewed_via) return f.reviewed_via
  return REVIEW_VERDICT_LABELS[f.triage_ai_verdict || ''] ? 'builtin' : 'none'
}

export interface ReviewChip extends Chip {
  verdict: string
  stale: boolean
}

export function reviewChip(f: TriageFinding): ReviewChip | null {
  const via = reviewedVia(f)
  const verdict = f.triage_ai_verdict || ''
  const label = REVIEW_VERDICT_LABELS[verdict]
  if (via === 'none' || !label) return null
  const stale = f.review_state === 'stale'
  const staleNote = stale
    ? '\nOut of date: the evidence changed since this review, so it no longer counts.'
    : ''
  if (via === 'mcp') {
    const by = f.triage_ai_by || 'an MCP token'
    return {
      text: `Agent: ${label}`, verdict, stale,
      title: `Reviewed by an external agent over MCP (token ${by}).${staleNote}`,
    }
  }
  return {
    text: `AI: ${label}`, verdict, stale,
    title: `Reviewed by ${f.triage_ai_model || 'the built-in AI'}.${staleNote}`,
  }
}

/** The layer that moved the score away from the rules, in a sentence. */
export function movedBy(f: TriageFinding): string {
  if (f.triage_decided_by === 'person') {
    return f.decided_via === 'mcp' ? 'your decision over MCP' : 'your decision'
  }
  if (f.triage_decided_by === 'review') {
    return reviewedVia(f) === 'mcp' ? "an external agent's review" : 'the AI review'
  }
  return 'the rules'
}

export interface BaseLine {
  text: string
  delta: string
  up: boolean
  title: string
}

function fmtScore(score: number): string {
  return score.toFixed(1)
}

/**
 * `rules 62.5 · Act soon` and the signed delta, when a review or a decision
 * moved the final score away from the rules. Null when nothing moved it, and
 * for a legacy row with no rules-only factors: its math score was written by a
 * run that kept no separate layer, so a "difference" there would be invented.
 */
export function baseLine(f: TriageFinding): BaseLine | null {
  if (!parseFactors(f.triage_base_factors)) return null
  const base = f.triage_math_score
  const final = f.triage_priority_score
  if (typeof base !== 'number' || typeof final !== 'number') return null
  const diff = final - base
  const baseTier = asTier(f.triage_base_tier) ?? tierForScore(base)
  if (Math.abs(diff) < 0.05 && baseTier === tierOf(f)) return null
  const sign = diff > 0 ? '+' : diff < 0 ? '−' : '±'
  return {
    text: `rules ${fmtScore(base)} · ${TIER_LABELS[baseTier]}`,
    delta: `${sign}${fmtScore(Math.abs(diff))}`,
    up: diff > 0,
    title: `The rules alone score this ${fmtScore(base)} (${TIER_LABELS[baseTier]}). ` +
      `${capitalise(movedBy(f))} moved it to ${fmtScore(final)}.`,
  }
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** The row's "why": a person's reason, else the review's, never both. */
export function whyText(f: TriageFinding): string {
  if (personDecided(f) && f.triage_reason) return f.triage_reason
  if (reviewChip(f)) return f.triage_ai_why || ''
  return ''
}

/** Why a finding cannot be reviewed, as `GET /api/triage/evidence` names it. */
export const NOT_REVIEWABLE_TEXT: Record<string, string> = {
  proven: 'It is proven (an exploit, a validation or a confirming chain finding), ' +
    'so no review may lower it.',
  decided_by_person: 'You decided it, and a decision outranks every review.',
  source_not_reviewed: 'Its source is not reviewed: for security checks, OSV and ' +
    'retire.js the matched facts are the evidence.',
  not_open: 'It is not open (fixed, gone, inactive or a false positive).',
  no_evidence: 'There is no evidence text to review.',
  not_scored: 'No run has scored it yet.',
  out_of_triage_scope: 'It is outside what a triage run reads, so no review applies.',
}

/**
 * The Reset confirm. It names what the finding loses, because the protection a
 * decision gives is invisible until it is gone.
 */
export function resetConfirmText(name: string): string {
  return `Reset your decision on "${name}"?\n\n` +
    'The finding is ranked from the rules and any review again. It also loses ' +
    'the protection your decision gave it: Mute Rules may mute it, and a scan ' +
    'that no longer reports it removes it from the graph.'
}

export type VerdictStatus = TriageStatus

/** What a verdict call came back with; the caller shows a failure inline. */
export type VerdictResult =
  | { ok: true }
  | { ok: false; cancelled?: boolean; status?: number; code?: string; message: string }

export function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}
