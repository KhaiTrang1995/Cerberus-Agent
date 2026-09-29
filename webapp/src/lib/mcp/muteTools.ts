/**
 * Mute and unmute over MCP: hiding a finding, and bringing one back.
 *
 * THIS REVERSES A DELIBERATE RULE. The surface was built on "only a person
 * mutes or unmutes", because a mute makes a finding invisible to every read -
 * the graph views, the reports, RedAmon's own agent and every tool here - and
 * "this is a false positive, mute it" is an entirely plausible injection
 * against an agent whose context is full of target-controlled text. That rule
 * is what bounded a prompt injection to "mislabel a verdict a human can
 * overrule".
 *
 * What replaces it is enforced in code, not in the tool descriptions, which an
 * injected agent will not read charitably:
 *
 *  - an opt-in permission (`triage:mute`) no profile ever ticks;
 *  - evidence guards in the graph write, under the node's lock: a proven
 *    finding and one a person brought back (it has an exemption) are refused;
 *  - no mute is ever overwritten, whoever made it;
 *  - a rule mute is released only on an explicit flag, and never while a recon
 *    scan is running (its end-of-scan sweep read the exemptions when it began);
 *  - a reason on every mute, a per-call cap and a per-token DAILY budget, the
 *    one bound on how much an injected agent can hide in total;
 *  - provenance that is READ, not just written: `muted_channel` / `muted_token`
 *    split agent mutes from people's in Muted Nodes, the report and here, so
 *    they can be reviewed and reverted per token;
 *  - busy checks that fail closed, and an unknown outcome that says so rather
 *    than "unavailable", because a lost answer to a write may have committed.
 *
 * `set_finding_verdict` still refuses a muted finding, and now for a narrower
 * reason: so that `triage:write` alone can never release a rule mute.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { activationBusy } from '@/lib/activationLock'
import {
  assertMcpProjectAccess,
  refundMuteBudget,
  requireScope,
  reserveMuteBudget,
  type BudgetDecision,
} from '@/lib/mcpAuth'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { describeScanWriters } from '@/lib/graphWriters'
import { invalidateCache } from '@/app/api/graph/cache'
import { auditUnmute, ensureExemptions, removeExemptions, type ExemptionPair } from '@/lib/unmuteExemptions'
import {
  annotateMutedFacets,
  loadMutedRuleDoc,
  mutedViaOf,
  MUTED_TOKEN_PATTERN,
} from '@/lib/nodeFilters/mutedAnnotate'
import { describeMutedBy, liveRuleMutedBy } from '@/lib/nodeFilters/model'
import { McpToolError } from '@/lib/mcp/errors'
import {
  listMutedPage,
  muteMany,
  mutedFacets,
  resolveMuted,
  unmuteMany,
  type MuteManyItem,
  type TriageFinding,
} from '@/lib/mcp/triageGraph'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

export const MUTE_MAX_REFS = 25
export const UNMUTE_MAX_REFS = 100
export const MUTE_REASON_MIN = 3
export const MUTE_REASON_MAX = 500

export const SEARCH_DEFAULT_LIMIT = 50
export const SEARCH_MAX_LIMIT = 100
/**
 * Every page runs the exact count and a full sort of the filtered set, so a
 * deep offset is paid on every call. Past this, narrow with a filter instead.
 */
export const SEARCH_MAX_OFFSET = 10_000

export const FINDING_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/
export const NODE_ID_PATTERN = /^\d{1,18}$/
export const MUTED_VIA_FILTERS = ['person', 'rule', 'mcp', 'deleted_rule'] as const
export const MUTED_ORDERS = ['recent', 'person_first'] as const

function busy(what: string): McpToolError {
  return new McpToolError(
    `Nothing was changed: ${what}. A mute or unmute written now could be lost or undone. ` +
      'Retry once it has finished.',
    'busy'
  )
}

const ACTIVATION_BUSY = 'a version activation is in progress on this project, or its state could not be read'

/** De-duplicated refs, checked, and bounded in total. A numeric Node ID (as
 *  query_graph returns it) is taken as its digits. */
function refsOf(
  findingIds: string[] | undefined,
  nodeIds: (string | number)[] | undefined,
  max: number
): { keys: string[]; graphIds: string[] } {
  const keys = [...new Set(findingIds ?? [])]
  const graphIds = [...new Set((nodeIds ?? []).map(String))]
  for (const k of keys) {
    if (!k || k.length > 200 || !FINDING_ID_PATTERN.test(k)) {
      throw new McpToolError(`"${String(k).slice(0, 40)}" is not a finding id.`, 'bad_args')
    }
  }
  for (const g of graphIds) {
    if (!NODE_ID_PATTERN.test(g)) {
      throw new McpToolError(`"${String(g).slice(0, 40)}" is not a Node ID.`, 'bad_args')
    }
  }
  const total = keys.length + graphIds.length
  if (total === 0) {
    throw new McpToolError('Name at least one finding, in findingIds or nodeIds.', 'bad_args')
  }
  if (total > max) {
    throw new McpToolError(`At most ${max} findings per call; this named ${total}.`, 'bad_args')
  }
  return { keys, graphIds }
}

function budgetView(b: BudgetDecision | null) {
  return b ? { used: b.used, limit: b.limit, resetsAt: b.resetsAt } : undefined
}

// --- mute ------------------------------------------------------------------------

export async function muteFindings(
  ctx: McpContext,
  projectId: string,
  args: { findingIds?: string[]; nodeIds?: (string | number)[]; reason: string }
) {
  requireScope(ctx.token, 'triage:mute')
  enforceRate(ctx, 'write')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const { keys, graphIds } = refsOf(args.findingIds, args.nodeIds, MUTE_MAX_REFS)
  const reason = (args.reason ?? '').trim()
  if (reason.length < MUTE_REASON_MIN || reason.length > MUTE_REASON_MAX) {
    throw new McpToolError(
      `A reason of ${MUTE_REASON_MIN}-${MUTE_REASON_MAX} characters is required: people read it in Muted Nodes.`,
      'bad_args'
    )
  }

  const tokenId = ctx.token.tokenId
  const requested = keys.length + graphIds.length
  const reservation = reserveMuteBudget(tokenId, requested)
  if (!reservation.allowed) {
    throw new McpToolError(
      `This token's daily mute budget is spent: ${reservation.used} of ${reservation.limit} ` +
        `findings muted in the current window, and this call asked for ${requested} more. It ` +
        `resets at ${reservation.resetsAt}. Nothing was muted. Report this to a person rather ` +
        'than working around it.',
      'budget_exhausted'
    )
  }

  // What to give back when the call ends. Everything, unless something was
  // muted or MAY have been.
  let refund = requested
  try {
    if (await activationBusy(projectId)) throw busy(ACTIVATION_BUSY)

    let exemptPairs: [string, string][]
    try {
      const rows = await prisma.nodeFilterExemption.findMany({
        where: { projectId },
        select: { label: true, nodeKey: true },
      })
      exemptPairs = rows.map(r => [r.label, r.nodeKey])
    } catch (err) {
      console.error('[mcp] mute_findings could not read the exemptions:', err)
      throw busy('the findings a person brought back could not be read, so they could not be protected')
    }

    let result: { items: MuteManyItem[]; notFound: string[] }
    try {
      result = await muteMany(ctx.token.userId, projectId, {
        keys, graphIds, exemptPairs, reason, tokenPrefix: ctx.token.tokenPrefix,
      })
    } catch (err) {
      if (err instanceof McpToolError && err.code === 'mute_outcome_unknown') {
        // It may have landed, so it counts, and the cached graph may be stale.
        refund = 0
        invalidateCache(projectId)
        void writeAudit({
          actorId: ctx.token.userId,
          action: 'muted_nodes.muted',
          targetType: 'project',
          targetId: projectId,
          after: {
            tokenId, tokenPrefix: ctx.token.tokenPrefix, reason, outcome: 'unknown',
            requested: { findingIds: keys, nodeIds: graphIds },
          },
          source: 'mcp',
        })
      }
      throw err
    }

    const muted = result.items.filter(i => i.outcome === 'muted')
    refund = Math.max(0, requested - muted.length)

    const warning = (await activationBusy(projectId))
      ? 'A version activation started during this call, and these mutes may not survive it. ' +
        'Re-check with search_muted_findings when it finishes.'
      : undefined
    if (muted.length > 0) invalidateCache(projectId)

    void writeAudit({
      actorId: ctx.token.userId,
      action: 'muted_nodes.muted',
      targetType: 'project',
      targetId: projectId,
      after: {
        tokenId,
        tokenPrefix: ctx.token.tokenPrefix,
        reason,
        count: muted.length,
        items: result.items.slice(0, 100).map(i => ({ key: i.key ?? i.ref, label: i.label, outcome: i.outcome })),
        ...(result.notFound.length ? { notFound: result.notFound.slice(0, 100) } : {}),
      },
      source: 'mcp',
    })

    const nodeIdOf = (i: MuteManyItem) =>
      typeof i.node_id === 'string' && NODE_ID_PATTERN.test(i.node_id) ? { nodeId: i.node_id } : {}
    const budget = refundMuteBudget(tokenId, refund)
    refund = 0
    return {
      projectId,
      muted: muted.map(i => ({
        findingId: i.key, ...nodeIdOf(i), label: i.label, name: i.name, severity: i.severity,
      })),
      alreadyMuted: result.items
        .filter(i => i.outcome === 'already_muted')
        .map(i => ({ findingId: i.key, ...nodeIdOf(i), label: i.label, mutedVia: i.was_via })),
      refused: result.items
        .filter(i => ['proven', 'kept_visible', 'not_a_finding'].includes(i.outcome))
        .map(i => ({ ref: i.ref, reason: i.outcome, label: i.label })),
      notFound: result.notFound,
      budget: budgetView(budget),
      ...(warning ? { warning } : {}),
      notes: [
        'A muted finding is hidden from everyone, including you: no read here returns it except ' +
          'search_muted_findings and list_muted_findings.',
        'Each mute is marked as an agent\'s, with this token\'s prefix, and a person can undo it in ' +
          'Muted Nodes.',
        '"proven" and "kept_visible" are refusals a person decides on, in RedAmon. Do not retry them.',
        'If every finding of a remediation is muted, the next triage run removes that remediation.',
      ],
    }
  } finally {
    if (refund > 0) refundMuteBudget(tokenId, refund)
  }
}

// --- unmute ----------------------------------------------------------------------

export async function unmuteFindings(
  ctx: McpContext,
  projectId: string,
  args: { findingIds?: string[]; nodeIds?: (string | number)[]; includeRuleMutes?: boolean }
) {
  requireScope(ctx.token, 'triage:mute')
  enforceRate(ctx, 'write')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const { keys, graphIds } = refsOf(args.findingIds, args.nodeIds, UNMUTE_MAX_REFS)
  const includeRuleMutes = args.includeRuleMutes === true
  const userId = ctx.token.userId

  // A rule mute is re-muted by a sweep that read the exemptions before this
  // unmute wrote one: an apply (a NodeFilterRun) or, for a rule mute, the
  // end-of-scan sweep, which only the scan check sees. Both fail closed.
  const graphWriter = () => (includeRuleMutes ? describeScanWriters(projectId) : describeNodeFilterWriter(projectId))

  if (await activationBusy(projectId)) throw busy(ACTIVATION_BUSY)
  const writer = await graphWriter()
  if (writer) throw busy(writer)

  const resolved = await resolveMuted(userId, projectId, { keys, graphIds, includeRuleMutes })
  const pairs: ExemptionPair[] = resolved.toUnmute.map(r => ({ label: r.label, key: r.key }))

  const doc = resolved.skippedRuleMutes.length > 0 ? await loadMutedRuleDoc(projectId) : null
  const skippedRuleMutes = resolved.skippedRuleMutes.map(r => {
    const state = doc ? describeMutedBy(doc, r.muted_by) : { via: 'person' as const }
    return {
      findingId: r.key,
      ...(r.node_id && NODE_ID_PATTERN.test(r.node_id) ? { nodeId: r.node_id } : {}),
      label: r.label,
      ruleName: state.via === 'rule' ? state.ruleName : null,
    }
  })

  const base = {
    projectId,
    skippedRuleMutes,
    notFound: resolved.notFound,
  }
  if (pairs.length === 0) {
    return { ...base, unmuted: [], exempted: 0, notes: unmuteNotes(includeRuleMutes, skippedRuleMutes.length) }
  }

  // The exemptions go in FIRST: a lost answer then converges on its own (the
  // next sweep releases a rule mute on an exempt finding), and a retry of the
  // rest is safe.
  let exemptions: { created: ExemptionPair[]; total: number }
  try {
    exemptions = await ensureExemptions(projectId, pairs, { createdBy: userId, realActorUserId: null })
  } catch (err) {
    console.error('[mcp] unmute_findings could not save the exemptions:', err)
    throw new McpToolError(
      'The exemptions that keep an unmuted finding visible could not be saved, so nothing was unmuted.',
      'exemptions_failed'
    )
  }

  if ((await activationBusy(projectId)) || (await graphWriter())) {
    await removeExemptions(projectId, exemptions.created)
    throw busy('the project started writing its graph during this call')
  }

  let result: Awaited<ReturnType<typeof unmuteMany>>
  try {
    result = await unmuteMany(userId, projectId, {
      keys: [...new Set(pairs.map(p => p.key))],
      includeRuleMutes,
    })
  } catch (err) {
    if (err instanceof McpToolError && err.code === 'unmute_outcome_unknown') {
      invalidateCache(projectId)
      void auditUnmute({
        actorId: userId, projectId, source: 'mcp', realActorUserId: null,
        tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
        items: [], exempted: exemptions.total, outcome: 'unknown',
        requested: { findingIds: keys, nodeIds: graphIds },
      })
    } else {
      await removeExemptions(projectId, exemptions.created)
    }
    throw err
  }

  // A finding the agent left muted (a rule re-muted it after the lookup, and
  // the flag was off) must not keep an exemption that would release it later.
  const skippedNow = new Set(result.skipped.map(s => `${s.label}\u0000${s.key}`))
  const dropped = exemptions.created.filter(p => skippedNow.has(`${p.label}\u0000${p.key}`))
  if (dropped.length > 0) await removeExemptions(projectId, dropped)

  invalidateCache(projectId)
  // A finding resolved above that someone else unmuted meanwhile is not in the
  // agent's rows; it is visible, which is what was asked, so it is reported.
  const unmuted = resolved.toUnmute
    .filter(r => !skippedNow.has(`${r.label}\u0000${r.key}`))
    .map(r => ({
      findingId: r.key,
      ...(r.node_id && NODE_ID_PATTERN.test(r.node_id) ? { nodeId: r.node_id } : {}),
      label: r.label,
      wasMutedVia: r.was_via,
    }))

  await auditUnmute({
    actorId: userId, projectId, source: 'mcp', realActorUserId: null,
    tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
    items: unmuted.map(u => ({ key: u.findingId, label: u.label, wasMutedVia: u.wasMutedVia })),
    exempted: exemptions.total - dropped.length, outcome: 'ok',
  })

  return {
    ...base,
    unmuted,
    exempted: exemptions.total - dropped.length,
    notes: unmuteNotes(includeRuleMutes, skippedRuleMutes.length),
  }
}

function unmuteNotes(includeRuleMutes: boolean, skipped: number): string[] {
  return [
    'The verdict on each finding is kept; it is ranked again at the next triage run.',
    'Each unmuted finding is now exempt from the Mute Rules, visible on the Mute Rules page, ' +
      'so no rule hides it again until a person clears that.',
    ...(skipped > 0 && !includeRuleMutes
      ? ['Findings a Mute Rule muted were left muted. Pass includeRuleMutes only when a person asked for them.']
      : []),
    'An unmuted finding shows as ADDED in a comparison against a version frozen while it was muted.',
  ]
}

// --- search ----------------------------------------------------------------------

export async function searchMutedFindings(
  ctx: McpContext,
  projectId: string,
  args: {
    limit?: number
    offset?: number
    label?: string
    mutedVia?: string
    rule?: string
    mutedByToken?: string
    search?: string
    order?: string
    facets?: boolean
  } = {}
) {
  requireScope(ctx.token, 'triage:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const limit = Math.max(1, Math.min(args.limit ?? SEARCH_DEFAULT_LIMIT, SEARCH_MAX_LIMIT))
  const offset = Math.max(0, Math.min(args.offset ?? 0, SEARCH_MAX_OFFSET))
  if (args.mutedByToken !== undefined && !MUTED_TOKEN_PATTERN.test(args.mutedByToken)) {
    throw new McpToolError('mutedByToken must be a token prefix, as facets.tokens lists them.', 'bad_args')
  }

  const doc = await loadMutedRuleDoc(projectId)
  const page = await listMutedPage(ctx.token.userId, projectId, {
    limit,
    offset,
    label: args.label,
    mutedVia: args.mutedVia,
    rule: args.rule?.slice(0, 200) || undefined,
    search: args.search?.slice(0, 200) || undefined,
    order: args.order,
    token: args.mutedByToken,
    liveRules: args.mutedVia === 'deleted_rule' ? liveRuleMutedBy(doc) : undefined,
  })

  const findings = page.findings.map(f => mutedRow(doc, f))
  const total = typeof page.total === 'number' ? page.total : null

  let facets: Record<string, unknown> | undefined
  if (args.facets === true) {
    const raw = annotateMutedFacets(doc, await mutedFacets(ctx.token.userId, projectId))
    facets = {
      total: raw.total,
      byPerson: raw.by_person,
      byMcp: raw.by_mcp ?? 0,
      labels: raw.labels,
      rules: (raw.rules as Record<string, unknown>[]).map(r => ({
        mutedBy: r.muted_by,
        count: r.count,
        ruleName: r.rule_name,
        ...(r.rule_deleted ? { ruleDeleted: true } : {}),
      })),
      tokens: Array.isArray(raw.tokens) ? raw.tokens : [],
    }
  }

  return {
    projectId,
    total,
    offset,
    returned: findings.length,
    ...(total !== null && offset + findings.length < total ? { truncated: true } : {}),
    findings,
    ...(facets ? { facets } : {}),
  }
}

/** The row allowlist. Nothing outside it reaches a caller. */
function mutedRow(doc: Parameters<typeof describeMutedBy>[0], f: TriageFinding): Record<string, unknown> {
  const mutedBy = String(f.muted_by ?? '')
  const state = describeMutedBy(doc, mutedBy)
  const via = mutedViaOf(f as Record<string, unknown>)
  const nodeId = typeof f.node_id === 'string' && NODE_ID_PATTERN.test(f.node_id) ? f.node_id : undefined
  const token = typeof f.muted_token === 'string' && MUTED_TOKEN_PATTERN.test(f.muted_token)
    ? f.muted_token : undefined
  return {
    id: f.id,
    ...(nodeId ? { nodeId } : {}),
    label: f.label,
    name: f.name,
    severity: f.severity,
    source: f.source,
    host: f.host,
    mutedAt: f.muted_at,
    mutedVia: via,
    mutedBy,
    ...(via === 'mcp' && token ? { mutedByToken: token } : {}),
    ruleName: state.via === 'rule' ? state.ruleName : null,
    ...(state.via === 'rule' && state.deleted ? { ruleDeleted: true } : {}),
    mutedReason: f.muted_reason,
    staleSince: f.stale_since ?? null,
    triageStatus: f.triage_status,
  }
}
