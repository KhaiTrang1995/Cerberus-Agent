/**
 * The MCP server's triage calls into the agent.
 *
 * Deliberately NOT `callGraphTriage` from `@/lib/triageClient`: that returns a
 * `NextResponse` rather than data, so every caller would re-parse an HTTP
 * envelope it never wanted, and it inherits `agentFetch`'s 30s default instead
 * of setting its own bound. Same shape as `graphClient.ts` instead: a direct
 * fetch with the internal key, an explicit timeout, and either parsed data or
 * an `McpToolError`.
 *
 * Every call sets `source: 'mcp'`. That is not decoration: it is what opts the
 * request into the agent's MCP concurrency ceiling. Without it these tools run
 * unthrottled against the same Neo4j the operator's own Priority Board reads
 * through this very endpoint.
 *
 * EVERY agent op name lives in this file and nowhere else on the MCP surface.
 * `list_muted` and `mute_many` are shaped like tool names, and the drift test
 * scans the agent-facing files for tool-shaped strings: an op literal there
 * would read as a tool that does not exist.
 */
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { McpToolError } from '@/lib/mcp/errors'

/** Generous enough for an untriaged project's full table, bounded all the same. */
const TRIAGE_TIMEOUT_MS = 60_000

export type McpTriageOp =
  | 'list_findings' | 'list_muted' | 'muted_facets' | 'human_verdict'
  | 'mute_many' | 'resolve_muted' | 'unmute_many'

/**
 * The ops that WRITE suppression state, and the verb their unknown-outcome code
 * is named after. A lost response to one of these is not "unavailable": the
 * write may have committed, and the caller must check before retrying.
 */
const WRITE_OP_VERB: Partial<Record<McpTriageOp, string>> = {
  mute_many: 'mute',
  unmute_many: 'unmute',
}

/**
 * Transport errors that happen BEFORE the request leaves: nothing was sent, so
 * nothing was written. Everything else on a write (a timeout, an abort, a reset
 * after sending, an error this list does not know) is an UNKNOWN outcome,
 * which is the safe direction to be wrong in.
 */
const REFUSED_BEFORE_SENDING = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
])

/**
 * The codes the agent puts on a 5xx it answered before writing anything: the
 * node lock timed out (`busy`), a deadlock outlasted the retries (`retry`), or
 * the master key is missing (`not_configured`). Each one rolled back.
 */
const NOTHING_CHANGED_CODES = new Set(['busy', 'retry', 'not_configured'])

export function failedBeforeSending(err: unknown): boolean {
  const e = err as { code?: unknown; cause?: { code?: unknown } } | null
  const code = e?.cause?.code ?? e?.code
  return typeof code === 'string' && REFUSED_BEFORE_SENDING.has(code)
}

/** The outcome of a suppression write cannot be known. */
export function outcomeUnknown(verb: string): McpToolError {
  return new McpToolError(
    `Outcome unknown (${verb}_outcome_unknown): the ${verb} was sent, but no reliable answer ` +
      'came back, so it may or may not have been applied. ' +
      'Check with search_muted_findings before doing anything else. A retry is safe: an ' +
      'already-muted finding is reported, never changed, and an already-unmuted one is not found.',
    `${verb}_outcome_unknown`
  )
}

export interface TriageFinding {
  id: string
  /** Neo4j's internal id as a string, for display only; `id` is the key. Absent
   *  from an agent older than the Node ID column. */
  node_id?: string | null
  label: string
  name: string
  severity: string
  source: string
  [key: string]: unknown
}

export interface TriageFindingsResult {
  findings: TriageFinding[]
  total?: number
}

/**
 * One `/graph/triage` op, as data.
 *
 * The tenant is the RESOLVED identity, never anything from the caller's
 * arguments: the mixin scopes `node_id` by it, so a guessed id from another
 * project matches nothing rather than acting on it.
 */
export async function callTriage(
  op: McpTriageOp,
  userId: string,
  projectId: string,
  extra: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const verb = WRITE_OP_VERB[op]
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/graph/triage`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        op,
        user_id: userId,
        project_id: projectId,
        source: 'mcp',
        ...extra,
      }),
      signal: AbortSignal.timeout(TRIAGE_TIMEOUT_MS),
    })
  } catch (err) {
    console.error(`[mcp] triage ${op} transport error:`, err)
    if (verb && !failedBeforeSending(err)) throw outcomeUnknown(verb)
    // NEVER an empty findings list. "The scan found nothing" and "the findings
    // service could not be reached" must not look the same to an agent writing
    // a security report.
    throw new McpToolError('The findings service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    const detail = (await resp.json().catch(() => null)) as { error?: unknown; code?: unknown } | null
    console.error(`[mcp] triage ${op} failed (${resp.status})`, detail?.error ?? '')
    if (resp.status === 400 && /unknown op/i.test(String(detail?.error ?? ''))) {
      throw new McpToolError(
        'The findings service is older than this RedAmon build and does not know this ' +
          'operation, so nothing was done. The operator must rebuild the agent image.',
        'agent_outdated'
      )
    }
    // A server error on a write can follow a commit whose acknowledgement was
    // lost. Only a refusal, or a 5xx the agent coded as "nothing was changed",
    // is a definite failure.
    if (verb && resp.status >= 500 && !NOTHING_CHANGED_CODES.has(String(detail?.code ?? ''))) {
      throw outcomeUnknown(verb)
    }
    throw new McpToolError(
      verb ? `The ${verb} was refused by the findings service, and nothing was changed.`
        : 'The findings could not be read.',
      'agent_failed'
    )
  }
  const body = (await resp.json().catch(() => null)) as Record<string, unknown> | null
  if (!body || typeof body !== 'object') {
    // A write answered 200 and then lost its body: it committed or it did not.
    if (verb) throw outcomeUnknown(verb)
    throw new McpToolError('The findings could not be read.', 'agent_failed')
  }
  warnIfAgentIsOlder(body)
  return body
}

/** Once per process: a hundred identical lines would bury the one that matters. */
let staleAgentWarned = false

/**
 * Say so when the agent on the other end predates this code.
 *
 * The agent's Python is baked into its own image; a deploy that rebuilds only
 * the webapp leaves an older one running. Pydantic ignores unknown fields, so
 * that agent accepts `source`, `limit` and `verdict_by`, silently discards all
 * three, and answers 200. The MCP concurrency ceiling then does not apply to
 * these calls, and every verdict is recorded with no channel and no actor -
 * with nothing anywhere to indicate it.
 */
function warnIfAgentIsOlder(body: Record<string, unknown>): void {
  if (body.mcp_gated === true || staleAgentWarned) return
  staleAgentWarned = true
  console.error(
    '[mcp] the agent did not acknowledge the MCP triage gate. It predates this webapp build, ' +
    'so findings calls are NOT taking the graph concurrency ceiling and verdicts are being ' +
    'written without a channel or an actor. Rebuild the agent image: ' +
    '`docker compose build agent && docker compose up -d agent`.'
  )
}

/** Test seam: the warning is once-per-process by design. */
export function __resetAgentVersionWarning(): void {
  staleAgentWarned = false
}

/** `list_findings`, with the row cap pushed down to the agent. */
export async function listTriageFindings(
  userId: string,
  projectId: string,
  limit: number
): Promise<TriageFindingsResult> {
  const body = await callTriage('list_findings', userId, projectId, { limit })
  const findings = Array.isArray(body.findings) ? (body.findings as TriageFinding[]) : null
  if (!findings) throw new McpToolError('The findings could not be read.', 'agent_failed')
  return {
    findings,
    total: typeof body.total === 'number' ? body.total : undefined,
  }
}

/**
 * `list_muted`, person-first. The mixin applies no limit unless one is asked
 * for, so the cap has to travel WITH the request - capping only the rows this
 * side returns still pulls the whole suppressed set across the wire.
 *
 * Person-first because a Mute Rule can mute thousands of findings in one
 * apply: newest-first, those would push every mute that IS a person's decision
 * out of a capped window. `total` is the uncapped count; an agent older than
 * that field returns none, and the caller falls back to "at least".
 */
export async function listMutedFindings(
  userId: string,
  projectId: string,
  limit: number
): Promise<{ findings: TriageFinding[]; total?: number }> {
  const body = await callTriage('list_muted', userId, projectId, { limit, order: 'person_first' })
  const findings = Array.isArray(body.findings) ? (body.findings as TriageFinding[]) : null
  if (!findings) throw new McpToolError('The muted findings could not be read.', 'agent_failed')
  return { findings, total: typeof body.total === 'number' ? body.total : undefined }
}

/**
 * A suppression op's answer, refused unless the agent acknowledged the MCP gate.
 *
 * Only an agent that knows these ops sends `mcp_gated`, and only that agent
 * validates the attribution and the exemptions, so a write answered without it
 * is not trusted. `unknown` is the outcome when the write itself may have run.
 */
function requireGated(body: Record<string, unknown>, verb?: string): void {
  if (body.mcp_gated === true) return
  if (verb) throw outcomeUnknown(verb)
  throw new McpToolError(
    'The findings service did not acknowledge this request as coming from an agent, so its ' +
      'answer is not used. The operator must rebuild the agent image.',
    'agent_outdated'
  )
}

const asArray = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : [])

export interface MuteManyItem {
  /** What the caller sent: a finding id, or a Node ID. */
  ref: string
  key: string | null
  label: string | null
  node_id: string | null
  name: string
  severity: string
  /** muted | already_muted | proven | kept_visible | not_a_finding */
  outcome: string
  /** For already_muted: person | mcp | rule. */
  was_via: string | null
}

/**
 * `mute_many`: an agent's mute, stamped with the token and bounded in the agent.
 * `exemptPairs` are the project's Mute Rules exemptions, which keep a finding a
 * person brought back from being hidden again.
 */
export async function muteMany(
  userId: string,
  projectId: string,
  args: {
    keys: string[]
    graphIds: string[]
    exemptPairs: [string, string][]
    reason: string
    tokenPrefix: string
  }
): Promise<{ items: MuteManyItem[]; notFound: string[] }> {
  const body = await callTriage('mute_many', userId, projectId, {
    keys: args.keys,
    graph_ids: args.graphIds,
    exempt_pairs: args.exemptPairs,
    reason: args.reason,
    token_prefix: args.tokenPrefix,
    muted_by: userId,
  })
  requireGated(body, 'mute')
  if (!Array.isArray(body.items)) throw outcomeUnknown('mute')
  return { items: asArray<MuteManyItem>(body.items), notFound: asArray<string>(body.not_found).map(String) }
}

export interface ResolvedMuted {
  ref: string
  key: string
  label: string
  node_id: string | null
  muted_by: string
  /** person | mcp | rule */
  was_via: string
}

/** `resolve_muted`: what an unmute of these refs would do. Reads only. */
export async function resolveMuted(
  userId: string,
  projectId: string,
  args: { keys: string[]; graphIds: string[]; includeRuleMutes: boolean }
): Promise<{ toUnmute: ResolvedMuted[]; skippedRuleMutes: ResolvedMuted[]; notFound: string[] }> {
  const body = await callTriage('resolve_muted', userId, projectId, {
    keys: args.keys,
    graph_ids: args.graphIds,
    include_rule_mutes: args.includeRuleMutes,
  })
  requireGated(body)
  if (!Array.isArray(body.to_unmute)) {
    throw new McpToolError('The muted findings could not be read.', 'agent_failed')
  }
  return {
    toUnmute: asArray<ResolvedMuted>(body.to_unmute),
    skippedRuleMutes: asArray<ResolvedMuted>(body.skipped_rule_mute),
    notFound: asArray<string>(body.not_found).map(String),
  }
}

export interface UnmutedItem {
  key: string
  label: string
  muted_by: string
  was_via: string | null
}

/**
 * `unmute_many` over MCP. The agent leaves a rule mute in place unless
 * `includeRuleMutes`, and reports it under `skipped`.
 */
export async function unmuteMany(
  userId: string,
  projectId: string,
  args: { keys: string[]; includeRuleMutes: boolean }
): Promise<{ items: UnmutedItem[]; skipped: UnmutedItem[] }> {
  const body = await callTriage('unmute_many', userId, projectId, {
    keys: args.keys,
    include_rule_mutes: args.includeRuleMutes,
  })
  requireGated(body, 'unmute')
  if (!Array.isArray(body.items)) throw outcomeUnknown('unmute')
  return { items: asArray<UnmutedItem>(body.items), skipped: asArray<UnmutedItem>(body.skipped) }
}

export interface MutedPageFilters {
  limit: number
  offset?: number
  label?: string
  mutedVia?: string
  rule?: string
  search?: string
  order?: string
  token?: string
  liveRules?: string[]
}

/** One page of `list_muted`, with the exact total of the filtered set. */
export async function listMutedPage(
  userId: string,
  projectId: string,
  f: MutedPageFilters
): Promise<{ findings: TriageFinding[]; total: number | undefined }> {
  const body = await callTriage('list_muted', userId, projectId, {
    limit: f.limit,
    offset: f.offset || undefined,
    label: f.label,
    muted_via: f.mutedVia,
    rule: f.rule,
    search: f.search,
    order: f.order,
    token: f.token,
    live_rules: f.liveRules,
  })
  const findings = Array.isArray(body.findings) ? (body.findings as TriageFinding[]) : null
  if (!findings) throw new McpToolError('The muted findings could not be read.', 'agent_failed')
  return { findings, total: typeof body.total === 'number' ? body.total : undefined }
}

/** `muted_facets`: exact counts per label, rule, token and who muted. */
export async function mutedFacets(userId: string, projectId: string): Promise<Record<string, unknown>> {
  return callTriage('muted_facets', userId, projectId)
}
