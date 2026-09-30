/**
 * The pure half of Multi mute: the shapes the suggest and apply routes answer
 * with, and how the modal words them. Kept apart from the component so the
 * wording is one table, not strings scattered through JSX.
 */
import { enabledKinds, NODE_FILTER_CATALOG, type NodeFilterCatalog } from '@/lib/nodeFilters/catalog'

/** The finding a Multi mute starts from, as each call site knows it. */
export interface MultiMuteSeed {
  /** Shown until the suggestion names the finding itself. */
  name: string
  /** The finding's stored key, preferred: it survives an import or activation. */
  nodeId?: string | null
  /** Neo4j's internal id, resolved server-side when no stored key is known. */
  graphId?: string | null
  label?: string
  /** JsReconFinding's `finding_type`; a `js_file` is a container, not a finding. */
  findingType?: string | null
}

export interface MultiMuteOptions {
  /** The seed itself was muted (and not undone); the node drawer closes here. */
  onSeedMuted?: () => void
  /** Every key still muted when the modal closes, for a view that drops rows locally. */
  onMuted?: (keys: string[]) => void
}

export type SeedReason = 'false_positive' | 'not_worth_fixing' | 'not_our_asset' | 'unclear'
export type Verdict = 'match' | 'maybe' | 'no'

export const EXACT_CONCEPTS = ['same_problem', 'same_detector', 'same_host'] as const
export type GroupConcept =
  | 'same_problem' | 'same_detector' | 'same_host' | 'same_fp_pattern' | 'same_low_risk'
export type ApplyConcept = GroupConcept | 'selected' | 'seed'

export interface MultiMuteMember {
  key: string
  node_id: string
  name: string
  host: string
  severity: string
  verdict: Verdict | null
  why: string | null
  quote: string | null
  quote_verified: boolean
  /** Pre-ticked by code (D15), never by the model alone. */
  checked: boolean
  /** Only in AI groups: nothing exact put it here. */
  ai_only: boolean
}

export interface MultiMuteGroup {
  id: string
  concepts: GroupConcept[]
  labels: string[]
  /** Membership came from the model alone. */
  ai: boolean
  title: string | null
  why: string | null
  members: MultiMuteMember[]
  probably_not: MultiMuteMember[]
}

export interface SuggestResult {
  status: 'ok' | 'model_unreadable' | 'empty_pool'
  batch_id: string
  prompt_version?: string
  model: string
  seed: {
    key: string
    node_id: string
    label: string
    kind: string
    name: string
    host: string
    severity: string
    source: string
    triaged: boolean
    /** A catalog kind id, if a later agent sends one. */
    kind_id?: string
  }
  read: { reason: SeedReason; why: string; quote: string; quote_verified: boolean } | null
  pool: {
    total: number
    candidates: number
    excluded: Record<string, number>
    truncated: boolean
    clusters_sent: number
  }
  groups: MultiMuteGroup[]
}

export type MuteOutcome =
  | 'muted' | 'already_muted' | 'proven' | 'kept_visible' | 'above_seed' | 'stale' | 'not_muteable'
  | 'gone' | 'not_found'

export interface ApplyItem {
  key: string
  label: string
  node_id: string
  name: string
  severity: string
  outcome: MuteOutcome
}

/** One write's ceiling (`MULTI_MUTE_MAX_KEYS`); a larger selection goes in several calls under one batch. */
export const APPLY_CHUNK = 500

export const ROWS_PER_PAGE = 50

export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

// Controls, bidi overrides and zero-width characters. The agent strips them
// already; this is the second net, because a right-to-left override in a
// scanner-controlled name can make a row read as something it is not.
const UNSAFE_TEXT = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g

export function cleanText(value: unknown): string {
  return typeof value === 'string' ? value.replace(UNSAFE_TEXT, '').trim() : ''
}

/** "Nuclei findings", but "Secrets" and "JS Recon findings" as they are. */
export function kindFindings(kind: string): string {
  const k = cleanText(kind)
  if (!k) return 'findings'
  const base = k.replace(/\s*\([^)]*\)\s*$/, '')
  return /findings$/i.test(base) || /[^s]s$/i.test(base) ? k : `${k} findings`
}

export const REASON_WORDS: Record<SeedReason, string> = {
  false_positive: 'a false positive',
  not_worth_fixing: 'not worth fixing',
  not_our_asset: 'not our asset',
  unclear: 'unclear',
}

/** The "why ▾" list: why a finding of the same kind was never proposed. */
export const EXCLUSION_WORDS: Record<string, string> = {
  above_seed: 'higher level than this finding',
  proven: 'proven',
  kept_visible: 'kept visible by a person',
  stale: 'no longer reported',
  js_file: 'a JS file container',
  proof_seed_lacks: 'proof this finding lacks',
  muted: 'already muted',
  other_kind: 'another kind',
}

export function exclusionWords(reason: string): string {
  return EXCLUSION_WORDS[reason] ?? reason.replace(/_/g, ' ')
}

/** A row after a write. Anything but muted means the server re-checked and refused. */
export const OUTCOME_WORDS: Record<MuteOutcome, string> = {
  muted: 'Muted',
  already_muted: 'Already muted',
  proven: 'Skipped: proven since',
  kept_visible: 'Skipped: kept visible by a person',
  above_seed: 'Skipped: now above this finding',
  stale: 'Skipped: no longer reported',
  not_muteable: 'Skipped: not muteable',
  gone: 'Skipped: changed since',
  not_found: 'Skipped: changed since',
}

export function outcomeWords(outcome: string): string {
  return OUTCOME_WORDS[outcome as MuteOutcome] ?? 'Skipped: changed since'
}

export function isMutedOutcome(outcome: string | undefined): boolean {
  return outcome === 'muted' || outcome === 'already_muted'
}

export const VERDICT_WORDS: Record<Verdict, string> = { match: 'match', maybe: 'maybe', no: 'no' }

export function isHighOrCritical(severity: string): boolean {
  const s = severity.toLowerCase()
  return s === 'high' || s === 'critical'
}

/** A card's heading: the model's title for an AI group, the concept labels otherwise. */
export function groupHeading(group: MultiMuteGroup): string {
  const title = cleanText(group.title)
  if (group.ai && title) return title
  return group.labels.map(cleanText).filter(Boolean).join(' · ') || 'Similar findings'
}

/** The verdict badge's tooltip. Only a quote the agent verified in the evidence is shown. */
export function verdictTooltip(member: MultiMuteMember): string {
  const lines = ['AI suggestion']
  const why = cleanText(member.why)
  if (why) lines.push(why)
  const quote = cleanText(member.quote)
  if (quote && member.quote_verified) lines.push(`Quote (verified in the evidence): "${quote}"`)
  if (!member.verdict) lines.push('The model did not judge this one.')
  return lines.join('\n')
}

/**
 * The Mute Rules kind an exact group can be turned into, or null.
 * The agent names the kind by its catalog label; a label + source fallback
 * (GVM, GitHub, multiscanner) has no catalog kind yet, so no rule to offer.
 */
export function muteRuleKindFor(
  seed: SuggestResult['seed'],
  catalog: NodeFilterCatalog = NODE_FILTER_CATALOG,
): string | null {
  const kinds = enabledKinds(catalog)
  if (seed.kind_id && kinds.some(k => k.id === seed.kind_id)) return seed.kind_id
  const hit = kinds.find(k => k.graph_label === seed.label && k.label === seed.kind)
  return hit?.id ?? null
}

/** Every key a group can act on: its members, then its "Probably not" rows. */
export function groupKeys(group: MultiMuteGroup): string[] {
  return [...group.members, ...group.probably_not].map(m => m.key)
}
