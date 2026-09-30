/**
 * The Priority Board tools over MCP: get_finding_triage, get_finding_evidence,
 * submit_finding_review, get_triage_status, start_triage_run, stop_triage_run.
 *
 * What is pinned, per tool: the scope it needs, the rate bucket it spends, the
 * order of its checks (access before rate on the starts, so a stranger cannot
 * spend a project's window), refusals that begin with a stable `Refused (<code>)`
 * prefix, free text only behind `includeQuotes` with the untrusted note, and
 * the spacing and daily cap on runs an agent starts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  order: [] as string[],
  findProject: vi.fn(),
  triageRuns: vi.fn(),
  readFinding: vi.fn(),
  readEvidence: vi.fn(),
  submitReview: vi.fn(),
  startRun: vi.fn(),
  stopRun: vi.fn(),
  facets: vi.fn(),
  preflight: vi.fn(),
  budget: vi.fn(),
  liveRun: vi.fn(),
  latestRuns: vi.fn(),
  rate: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => { h.order.push('access'); return h.findProject(...a) } },
    triageRun: { findMany: (...a: unknown[]) => h.triageRuns(...a) },
  },
}))
vi.mock('@/lib/mcp/tools', async (orig) => ({
  ...(await orig<typeof import('./tools')>()),
  enforceRate: (_ctx: unknown, bucket: string) => { h.order.push(`rate:${bucket}`); h.rate(bucket) },
}))
vi.mock('@/lib/triage/actions', async (orig) => {
  const real = await orig<typeof import('@/lib/triage/actions')>()
  return {
    ...real,
    readFinding: (...a: unknown[]) => h.readFinding(...a),
    readEvidence: (...a: unknown[]) => h.readEvidence(...a),
    submitReview: (...a: unknown[]) => { h.order.push('submit'); return h.submitReview(...a) },
    startRun: (...a: unknown[]) => { h.order.push('start'); return h.startRun(...a) },
    stopRun: (...a: unknown[]) => { h.order.push('stop'); return h.stopRun(...a) },
    triageFacets: (...a: unknown[]) => h.facets(...a),
  }
})
vi.mock('@/lib/triage/preflight', () => ({
  computePreflight: (...a: unknown[]) => { h.order.push('preflight'); return h.preflight(...a) },
  MAX_REVIEW_BUDGET: 1000,
  RUN_BLOCKS: ['version activation', 'Recon Delta against the current graph', 'Mute Rules apply',
               'start_recon', 'compare against the current graph'],
}))
vi.mock('@/lib/triageRun', () => ({
  findLiveTriageRun: (...a: unknown[]) => h.liveRun(...a),
  latestTriageRuns: (...a: unknown[]) => h.latestRuns(...a),
  mcpRunBudget: (...a: unknown[]) => { h.order.push('budget'); return h.budget(...a) },
  MCP_RUN_COOLDOWN_MS: 30 * 60 * 1000,
  MCP_RUNS_PER_DAY: 12,
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { TriageActionError } from '@/lib/triage/actions'
import {
  getFindingEvidence, getFindingTriage, getTriageStatus, startTriageRun, stopTriageRun,
  submitFindingReview, UNTRUSTED_NOTE,
} from './triageTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[]): McpContext => ({
  token: { tokenId: 'tok1', userId: 'owner', tokenPrefix: 'rdmn_mcp_0a1b2c3d', name: 'agent',
           scopes: scopes as never },
})

const ROW = {
  id: 'v1', node_id: '812', label: 'Vulnerability', name: 'Exposed .env', severity: 'high',
  source: 'nuclei', host: 'a.example', section: 0, triage_state: 'open',
  triage_status: 'unreviewed', triage_source: '',
  triage_priority_score: 30, triage_tier: 'T3', triage_tier_rule: 'credible', triage_risk: 0.2,
  triage_factors: '{"C":{"value":0.25,"evidence":"matched"}}', triage_decided_by: 'review',
  triage_math_score: 62.5, triage_base_tier: 'T2', triage_base_tier_rule: 'likely real',
  triage_base_state: 'open', triage_base_factors: '{"C":{"value":0.95,"evidence":"matched"}}',
  triage_tier_inputs: '{"proven":false,"kev":false}', triage_signals: ['KEV'],
  triage_ai_verdict: 'doubtful', reviewed_via: 'mcp', review_state: 'current',
  triage_ai_by: 'rdmn_mcp_ffffffff', triage_ai_model: '',
  triage_ai_corrections: '{"verdict":"doubtful","impact_multiplier":1,"disputed_facts":[{"fact":"reachable","quote":"TARGET-QUOTE"}]}',
  triage_ai_why: 'AGENT-WHY', triage_ai_quote: 'EVIDENCE-QUOTE', triage_fix_lever: 'rotate it',
  triage_group_key: 'cve:x', triage_run_id: 'r1', triage_model_version: 'v3.2.0',
  proof_types: [], proven_now: false,
}

const PREFLIGHT = {
  projectName: 'P', model: 'gpt-5-mini', modelRequired: false, hasModelKey: true,
  inScope: 40, newSinceLastRun: 3, openFindings: 30, reviewable: 10, reviewBudget: 150,
  reviewsKept: 7, externalReviews: 2, estimatedAiCalls: 1, estimatedReviewed: 10,
  pendingRemediations: 0, inProgressRemediations: 0, lastTriagedAt: '2026-09-29T10:00:00Z',
  lastRun: null, liveRun: null, blockedReason: null, blocking: [], defaultRepo: '',
  mcpRunsToday: 1, mcpRunsPerDay: 12, nextMcpStartAllowedAt: null, mcpStartRefusal: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.order.length = 0
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.triageRuns.mockResolvedValue([{ status: 'completed', finishedAt: new Date() }])
  h.readFinding.mockResolvedValue({ found: true, row: ROW, group: [{ id: 'v1' }],
                                    detector: { key: 'nuclei:env', real: 3, fp: 1 },
                                    review_survives_rescan: true })
  h.readEvidence.mockResolvedValue({ found: true, finding_id: 'v1', label: 'Vulnerability',
                                     evidence: 'Finding: x', evidence_hash: 'a'.repeat(40),
                                     matches_last_run: true, reviewable: true,
                                     not_reviewable_because: null, review_survives_rescan: true,
                                     current_review: null, contract: { verdicts: {} } })
  h.submitReview.mockResolvedValue({ label: 'Vulnerability', rescored: true,
                                     before: { score: 62.5 }, after: { score: 30 }, row: ROW,
                                     accepted: { verdict: 'doubtful' }, dropped: [],
                                     reviewSurvivesRescan: true })
  h.preflight.mockResolvedValue({ ...PREFLIGHT })
  h.budget.mockResolvedValue({ runsToday: 1, nextAllowedAt: null, reason: null })
  h.startRun.mockResolvedValue({ runId: 'run-9', attached: false })
  h.stopRun.mockResolvedValue({ stopped: true, runId: 'run-9' })
  h.liveRun.mockResolvedValue({ id: 'run-9', status: 'running' })
  h.latestRuns.mockResolvedValue([])
  h.facets.mockResolvedValue({ decided_by: { person: 1, review: 2, rules: 37 } })
})

describe('scopes', () => {
  test.each([
    ['get_finding_triage', () => getFindingTriage(ctx(['recon:read']), 'p1', 'v1')],
    ['get_finding_evidence', () => getFindingEvidence(ctx(['recon:read']), 'p1', 'v1')],
    ['get_triage_status', () => getTriageStatus(ctx(['recon:read']), 'p1')],
    ['submit_finding_review', () => submitFindingReview(ctx(['triage:read', 'triage:write']), 'p1', 'v1',
                                                        { evidenceHash: 'a'.repeat(40), verdict: 'real' })],
    ['start_triage_run', () => startTriageRun(ctx(['triage:read', 'triage:write']), 'p1')],
    ['stop_triage_run', () => stopTriageRun(ctx(['triage:read', 'triage:review']), 'p1')],
  ])('%s refuses a token without its scope, before touching anything', async (_n, call) => {
    await expect(call()).rejects.toBeInstanceOf(McpScopeError)
    expect(h.order).toEqual([])
  })

  test('a non-owner is refused as not found on every tool', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    const all = ctx(['triage:read', 'triage:review', 'triage:run'])
    for (const call of [
      () => getFindingTriage(all, 'p1', 'v1'),
      () => getFindingEvidence(all, 'p1', 'v1'),
      () => getTriageStatus(all, 'p1'),
      () => submitFindingReview(all, 'p1', 'v1', { evidenceHash: 'a'.repeat(40), verdict: 'real' }),
      () => startTriageRun(all, 'p1'),
      () => stopTriageRun(all, 'p1'),
    ]) {
      await expect(call()).rejects.toBeInstanceOf(McpAccessDenied)
    }
    expect(h.readFinding).not.toHaveBeenCalled()
    expect(h.startRun).not.toHaveBeenCalled()
  })
})

describe('get_finding_triage', () => {
  const read = (includeQuotes = false) =>
    getFindingTriage(ctx(['triage:read']), 'p1', 'v1', { includeQuotes })

  test('returns every layer, spending the read bucket', async () => {
    const out = await read()
    expect(h.rate).toHaveBeenCalledWith('read')
    expect(out.final).toMatchObject({ score: 30, tier: 'T3', decidedBy: 'review' })
    expect(out.rules).toMatchObject({ score: 62.5, tier: 'T2', tierInputs: { proven: false, kev: false } })
    expect(out.review).toMatchObject({ verdict: 'doubtful', channel: 'mcp', by: 'rdmn_mcp_ffffffff',
                                       current: true,
                                       corrections: { disputedFacts: ['reachable'], impactMultiplier: 1 } })
    expect(out.decision).toBeNull()
    expect(out.detector.judged).toBe('you judged 3 of 4 of these real')
    expect(out.sectionName).toBe('ranked')
  })

  test('the why and the quotes come only behind includeQuotes, with the untrusted note', async () => {
    const plain = JSON.stringify(await read(false))
    for (const text of ['AGENT-WHY', 'EVIDENCE-QUOTE', 'TARGET-QUOTE']) expect(plain).not.toContain(text)
    const quoted = await read(true)
    expect(JSON.stringify(quoted)).toContain('AGENT-WHY')
    expect(quoted.notes).toContain(UNTRUSTED_NOTE)
  })

  test('the fix lever is reviewer text too: only behind includeQuotes', async () => {
    // It went out to every triage:read token with no untrusted note.
    expect(JSON.stringify(await read(false))).not.toContain('rotate it')
    expect((await read(true)).review).toMatchObject({ fixLever: 'rotate it' })
  })

  test('proof on the finding\'s host is not counted as proof of the finding', async () => {
    h.readFinding.mockResolvedValue({ found: true, row: { ...ROW, triage_proof: 'cf-on-host' },
                                      group: [], detector: {} })
    const out = await read()
    expect(out.proof).toMatchObject({ count: 0, provenNow: false, onProvenHost: true })
  })

  test('a person\'s decision is its own layer', async () => {
    h.readFinding.mockResolvedValue({ found: true, row: { ...ROW, triage_status: 'confirmed',
      triage_source: 'human', decided_via: 'mcp', triage_verdict_token: 'rdmn_mcp_0a1b2c3d',
      triage_reason: 'checked' }, group: [], detector: {} })
    const out = await read()
    expect(out.decision).toEqual({ status: 'confirmed', channel: 'mcp', token: 'rdmn_mcp_0a1b2c3d',
                                   at: null, reason: 'checked' })
  })

  test('a refusal carries a stable prefix and its details go to the audit', async () => {
    h.readFinding.mockRejectedValue(new TriageActionError('two kinds', 'ambiguous', 409,
                                                          { labels: ['Secret', 'Vulnerability'] }))
    await expect(read()).rejects.toMatchObject({
      message: expect.stringMatching(/^Refused \(ambiguous\): /), code: 'ambiguous',
      audit: { details: { labels: ['Secret', 'Vulnerability'] } } })
  })
})

describe('get_finding_evidence', () => {
  test('returns the evidence, its hash and the contract, marked untrusted', async () => {
    const out = await getFindingEvidence(ctx(['triage:read']), 'p1', 'v1', { label: 'Vulnerability' })
    expect(out).toMatchObject({ evidenceHash: 'a'.repeat(40), reviewable: true, matchesLastRun: true })
    expect(out.notes).toContain(UNTRUSTED_NOTE)
    expect(h.readEvidence.mock.calls[0]).toEqual([{ userId: 'owner', projectId: 'p1' }, 'v1',
                                                  'Vulnerability', 'mcp'])
  })
})

describe('submit_finding_review', () => {
  const review = () => submitFindingReview(ctx(['triage:read', 'triage:review']), 'p1', 'v1', {
    evidenceHash: 'a'.repeat(40), verdict: 'doubtful', evidenceQuote: 'Finding: x',
    why: 'a sample', fixLever: 'remove it',
  })

  test('scope, then the write bucket, then access, then the write', async () => {
    await review()
    expect(h.order).toEqual(['rate:write', 'access', 'submit'])
  })

  test('the token\'s identity travels with the review', async () => {
    await review()
    expect(h.submitReview.mock.calls[0][1]).toMatchObject({
      findingId: 'v1', verdict: 'doubtful', tokenId: 'tok1', tokenPrefix: 'rdmn_mcp_0a1b2c3d',
      actorUserId: 'owner',
    })
  })

  test('the answer says what happened and what overrides it', async () => {
    const out = await review()
    expect(out).toMatchObject({ rescored: true, before: { score: 62.5 }, after: { score: 30 } })
    expect(out.notes.join(' ')).toMatch(/you never set it/)
    expect(out.notes.join(' ')).toMatch(/person's decision overrides/)
  })

  test('a finding recreated at every scan says its review will not survive', async () => {
    h.submitReview.mockResolvedValue({ label: 'MultiscannerFinding', rescored: true, before: null,
                                       after: null, row: null, accepted: {}, dropped: [],
                                       reviewSurvivesRescan: false })
    expect((await review()).notes.join(' ')).toMatch(/will not survive the next one/)
  })

  test('refusals keep their reason as the code', async () => {
    h.submitReview.mockRejectedValue(new TriageActionError('A person decided.', 'decided_by_person', 409))
    await expect(review()).rejects.toMatchObject({
      message: 'Refused (decided_by_person): A person decided.', code: 'decided_by_person' })
  })
})

describe('get_triage_status', () => {
  test('the state, the runs, the preflight, the counts and what a run blocks', async () => {
    h.preflight.mockResolvedValue({ ...PREFLIGHT, liveRun: { id: 'r2', status: 'running',
      startedAt: new Date(), trigger: 'mcp', phase: 'reviewing', progress: 55,
      tokenPrefix: 'rdmn_mcp_0a1b2c3d' } })
    const out = await getTriageStatus(ctx(['triage:read']), 'p1')
    expect(out.triageState).toBe('current')
    expect(out.liveRun).toMatchObject({ phase: 'reviewing', progress: 55, trigger: 'mcp' })
    expect(out.preflight).toMatchObject({ reviewsKept: 7, externalReviews: 2, reviewBudget: 150,
                                          modelConfigured: true, mcpRunsToday: 1 })
    expect(out.decidedByCounts).toEqual({ person: 1, review: 2, rules: 37 })
    expect(out.blocking).toContain('Mute Rules apply')
    expect(h.rate).toHaveBeenCalledWith('read')
  })

  test('an imported project reports imported (C17)', async () => {
    h.triageRuns.mockResolvedValue([])
    expect((await getTriageStatus(ctx(['triage:read']), 'p1')).triageState).toBe('imported')
  })

  test('with no model a run would review nothing', async () => {
    h.preflight.mockResolvedValue({ ...PREFLIGHT, model: '' })
    const out = await getTriageStatus(ctx(['triage:read']), 'p1')
    expect(out.preflight).toMatchObject({ modelConfigured: false, reviewBudget: 0 })
  })
})

describe('start_triage_run', () => {
  const start = () => startTriageRun(ctx(['triage:read', 'triage:run']), 'p1')

  beforeEach(() => {
    h.liveRun.mockResolvedValue(null)
  })

  test('access and the cheap refusals come before the write bucket; the preflight after it', async () => {
    await start()
    expect(h.order).toEqual(['access', 'budget', 'rate:write', 'preflight', 'start'])
    expect(h.rate).not.toHaveBeenCalledWith('start')
  })

  test('a start refused by the cooldown never runs the graph preflight', async () => {
    // A caller looping on the cooldown ran the heaviest read with no rate limit.
    h.budget.mockResolvedValue({ runsToday: 2, nextAllowedAt: new Date(), reason: 'cooldown' })
    await expect(start()).rejects.toMatchObject({ code: 'cooldown' })
    expect(h.preflight).not.toHaveBeenCalled()
  })

  test('a live run is refused as busy before any rate or preflight', async () => {
    h.liveRun.mockResolvedValue({ id: 'r2', status: 'running', trigger: 'mcp' })
    await expect(start()).rejects.toMatchObject({
      code: 'busy', message: expect.stringMatching(/^Refused \(busy\): a triage run started over MCP/) })
    expect(h.rate).not.toHaveBeenCalled()
    expect(h.preflight).not.toHaveBeenCalled()
  })

  test('it starts as an MCP run with the token and the 1000 clamp', async () => {
    const out = await start()
    expect(h.startRun.mock.calls[0][1]).toEqual({ trigger: 'mcp', tokenId: 'tok1', maxReviewBudget: 1000 })
    expect(out).toMatchObject({ runId: 'run-9', attached: false, reviewBudget: 150, model: 'gpt-5-mini' })
    expect(out.notes.join(' ')).toMatch(/Poll get_triage_status/)
  })

  test('no model is not a refusal: the run ranks on the rules alone', async () => {
    h.preflight.mockResolvedValue({ ...PREFLIGHT, model: '', modelRequired: true })
    const out = await start()
    expect(h.startRun.mock.calls[0][1].maxReviewBudget).toBe(0)
    expect(out.reviewBudget).toBe(0)
  })

  test('the cooldown is refused, naming when the next start is allowed, and spends no rate', async () => {
    const at = new Date('2026-09-29T12:30:00Z')
    h.budget.mockResolvedValue({ runsToday: 2, nextAllowedAt: at, reason: 'cooldown' })
    await expect(start()).rejects.toMatchObject({
      message: expect.stringMatching(/^Refused \(cooldown\): .*30 minutes.*2026-09-29T12:30:00.000Z/),
      code: 'cooldown' })
    expect(h.rate).not.toHaveBeenCalled()
    expect(h.startRun).not.toHaveBeenCalled()
  })

  test('the daily cap is refused the same way', async () => {
    h.budget.mockResolvedValue({ runsToday: 12, nextAllowedAt: new Date(), reason: 'daily_cap' })
    await expect(start()).rejects.toMatchObject({
      message: expect.stringMatching(/^Refused \(cooldown\): 12 runs/) })
  })

  test('an unreadable cooldown refuses (fail closed)', async () => {
    h.budget.mockRejectedValue(new Error('db down'))
    await expect(start()).rejects.toMatchObject({ code: 'busy' })
    expect(h.startRun).not.toHaveBeenCalled()
  })

  test('a live run or a busy graph is refused as busy', async () => {
    h.preflight.mockResolvedValue({ ...PREFLIGHT, liveRun: { id: 'r2', status: 'running',
      trigger: 'app' }, blockedReason: 'A triage run is already in progress for this project.' })
    await expect(start()).rejects.toMatchObject({
      message: expect.stringMatching(/^Refused \(busy\): a triage run started in the app/) })
    h.preflight.mockResolvedValue({ ...PREFLIGHT, blockedReason: 'A version activation is in progress for this project.' })
    await expect(start()).rejects.toMatchObject({ message: expect.stringMatching(/^Refused \(busy\): A version/) })
    expect(h.startRun).not.toHaveBeenCalled()
  })

  test('the agent\'s "still finishing" refusal is surfaced', async () => {
    h.startRun.mockRejectedValue(new TriageActionError(
      'the previous triage run is still finishing; retry in a minute', 'busy', 409))
    await expect(start()).rejects.toMatchObject({ message: expect.stringMatching(/still finishing/) })
  })
})

describe('stop_triage_run', () => {
  const stop = () => stopTriageRun(ctx(['triage:read', 'triage:run']), 'p1')

  test('access, then the live run, then the write bucket, then the stop', async () => {
    const out = await stop()
    expect(h.order).toEqual(['access', 'rate:write', 'stop'])
    expect(out).toMatchObject({ stopped: true, runId: 'run-9' })
  })

  test('with no run it says so and spends nothing', async () => {
    h.liveRun.mockResolvedValue(null)
    expect(await stop()).toEqual({ projectId: 'p1', stopped: false, reason: 'no run in progress' })
    expect(h.rate).not.toHaveBeenCalled()
  })

  test('a publishing run is not stopped, and says why', async () => {
    h.stopRun.mockResolvedValue({ stopped: false, reason: 'publishing', runId: 'run-9' })
    const out = await stop()
    expect(out).toMatchObject({ stopped: false, reason: 'publishing' })
    expect('notes' in out ? out.notes?.join(' ') : '').toMatch(/half-write/)
  })
})
