/**
 * set_finding_verdict: the only write to a finding on this surface.
 *
 * Four things must hold, and three of them are failures that look like success:
 *
 *  - the verdict is stamped `human`, NOT a third provenance value. A third
 *    value makes the finding prune-eligible (a re-scan deletes it), lets a
 *    later AI run overwrite it, stops `likely_noise` meaning false-positive,
 *    and renders as "Not reviewed".
 *  - `updated: false` is never reported as success. The op answers HTTP 200 in
 *    two different failure shapes, both carrying it.
 *  - during a live triage run it is written only when the agent acknowledges
 *    that its publish honours decisions made meanwhile (`layered_publish`); an
 *    older agent would silently re-file the finding afterwards.
 *  - a decision a person made in the app is never changed from here.
 *  - it is audited, because a verdict is durable, suppresses future AI review,
 *    and had no actor record anywhere before this.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  liveTriageRun: vi.fn(),
  writeAudit: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => h.liveTriageRun(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: async () => false }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { setFindingVerdict } from './verdictTools'
import { __setLayeredAgentConfirmed } from '@/lib/triage/actions'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['triage:write']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const agentReturns = (body: unknown) =>
  h.fetch.mockResolvedValue({ ok: true, json: async () => body })

const sentBody = () => JSON.parse(h.fetch.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  __setLayeredAgentConfirmed(true)
  vi.stubGlobal('fetch', h.fetch)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.liveTriageRun.mockResolvedValue(null)
  agentReturns({ updated: true, label: 'Vulnerability', rescored: true,
                 before: { score: 40 }, after: { score: 75 }, layered_publish: true })
})

describe('permissions and arguments', () => {
  test('it needs triage:write; triage:read is not enough', async () => {
    await expect(setFindingVerdict(ctx(['triage:read']), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('ownership is checked before the agent is called', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('an unknown verdict is refused by name, listing the valid ones', async () => {
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'looks_bad'))
      .rejects.toThrow(/One of: confirmed, likely_noise, unreviewed/)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the three real verdicts are accepted', async () => {
    for (const status of ['confirmed', 'likely_noise', 'unreviewed']) {
      __resetRateLimiter()
      await expect(setFindingVerdict(ctx(), 'p1', 'v1', status)).resolves.toBeTruthy()
    }
  })
})

// REGRESSION: the obvious design - a third triage_source value so an agent's
// verdict is not laundered as a human's - breaks four behaviours that branch on
// that field being a closed two-value set. Most severely, the ingest-then-prune
// keep predicate is `(n:Muted OR coalesce(n.triage_source,'') = 'human')`, so a
// third value falls on the DELETE side and a re-scan removes the finding
// entirely rather than stamping stale_since.
describe('REGRESSION: provenance is a separate property, never a third source value', () => {
  test('the channel travels as `source`, which the mixin records separately', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    const body = sentBody()
    expect(body.op).toBe('human_verdict')
    expect(body.source).toBe('mcp')
    // The verdict VALUE is never sent: the mixin hardcodes 'human'.
    expect(body.triage_source).toBeUndefined()
  })

  test('the actor is sent, so a verdict records who and not only who it was not', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    expect(sentBody().verdict_by).toBe('owner')
  })

  test('the answer says the verdict is recorded as the operator\'s own', async () => {
    const notes = (await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')).notes.join(' ')
    expect(notes).toMatch(/recorded as the operator's decision/)
    expect(notes).toMatch(/arrived over MCP/)
  })

  test('the token prefix is sent, so the node records which token decided', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    expect(sentBody().token_prefix).toBe('rdmn_mcp_aaaaaaaa')
  })
})

describe('the layered model', () => {
  test('the answer carries the score before and after, rescored at once', async () => {
    const out = await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    expect(out).toMatchObject({ rescored: true, before: { score: 40 }, after: { score: 75 } })
    expect(out.notes.join(' ')).toMatch(/`real` factor is now 100%/)
  })

  test('a Reset says what it releases', async () => {
    const out = await setFindingVerdict(ctx(), 'p1', 'v1', 'unreviewed')
    expect(out.notes.join(' ')).toMatch(/no longer protected from Mute Rules/)
  })

  test('a label narrows an ambiguous id', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed', '', 'Secret')
    expect(sentBody().label).toBe('Secret')
  })

  test('a decision a person made in the app is refused, by a stable prefix', async () => {
    agentReturns({ updated: false, reason: 'decided_in_app', label: 'Vulnerability' })
    const err = await setFindingVerdict(ctx(), 'p1', 'v1', 'unreviewed')
      .then(() => null, (e: McpToolError) => e)
    expect(err).toMatchObject({ code: 'decided_in_app' })
    expect(err?.message).toMatch(/^Refused \(decided_in_app\): /)
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('an ambiguous id names the kinds it matched', async () => {
    agentReturns({ updated: false, reason: 'ambiguous', labels: ['Secret', 'Vulnerability'] })
    const err = await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
      .then(() => null, (e: McpToolError) => e)
    expect(err?.message).toMatch(/^Refused \(ambiguous\): .*Secret, Vulnerability/)
  })
})

describe('a failed write is never reported as success', () => {
  test('updated:false is an error, whatever else the body says', async () => {
    // The op answers 200 with {updated:false} for a wrong id, another tenant's
    // id, and a non-muteable label - deliberately indistinguishable.
    agentReturns({ updated: false, label: null })
    await expect(setFindingVerdict(ctx(), 'p1', 'gone', 'confirmed'))
      .rejects.toMatchObject({ code: 'not_updated' })
  })

  test('the message covers the real ambiguity and says what to do', async () => {
    agentReturns({ updated: false, label: null })
    const err = await setFindingVerdict(ctx(), 'p1', 'gone', 'confirmed')
      .then(() => null, (e: Error) => e)
    expect(err?.message).toMatch(/no longer exists, was never in this project, or is not a type/)
    expect(err?.message).toMatch(/re-read list_findings/)
  })

  test('an all-digit id is called out as the graph Node ID it probably is', async () => {
    // list_findings returns `nodeId` (id(n)) beside `id`, and this tool's input
    // is also named nodeId, so that is the likeliest wrong value to receive.
    agentReturns({ updated: false, label: null })
    const err = await setFindingVerdict(ctx(), 'p1', '1234', 'confirmed')
      .then(() => null, (e: Error) => e)
    expect(err?.message).toMatch(/"1234" looks like a graph Node ID/)
    expect(err?.message).toMatch(/pass the finding's `id` instead/)
  })

  test('a real finding id gets no Node ID hint', async () => {
    agentReturns({ updated: false, label: null })
    const err = await setFindingVerdict(ctx(), 'p1', 'nuclei-9cf6109e', 'confirmed')
      .then(() => null, (e: Error) => e)
    expect(err?.message).not.toMatch(/Node ID/)
  })

  test('the second failure shape, an invalid status, is reported too', async () => {
    agentReturns({ updated: false, reason: "invalid status 'x'" })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toThrow(/invalid status/)
  })

  test('an unreachable agent is an error, not a silent no-op', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpToolError)
  })

  test('a muted finding is refused by name, and the message says how a person gets it judged', async () => {
    agentReturns({ updated: false, reason: 'muted', label: 'Vulnerability' })
    const err = await setFindingVerdict(ctx(), 'p1', 'm1', 'likely_noise')
      .then(() => null, (e: McpToolError) => e)
    expect(err).toMatchObject({ code: 'muted' })
    expect(err?.message).toMatch(/^Refused \(muted\): a verdict is refused on a muted finding/)
    expect(err?.message).toMatch(/Nothing was written/)
    // The path is unmute-then-judge, behind its own permission: triage:write
    // alone must never be a way to release a rule mute.
    expect(err?.message).toMatch(/unmute it first with unmute_findings \(needs the triage:mute permission\)/)
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('nothing is audited when nothing was written', async () => {
    agentReturns({ updated: false, label: null })
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed').catch(() => {})
    expect(h.writeAudit).not.toHaveBeenCalled()
  })
})

// REGRESSION (plan 14.2), and its replacement. A run reads at step A and
// publishes minutes later; an agent that publishes the whole result blind would
// re-file a finding decided meanwhile. A LAYERED agent re-reads the decision
// under the node lock at publish, so during a live run a verdict is written only
// when the agent acknowledges that (`layered_publish`). Version skew fails closed.
describe('REGRESSION: an MCP verdict needs a layered agent, run or no run', () => {
  test('with no run live, an older agent still cannot take it (it would overwrite an app decision)', async () => {
    __setLayeredAgentConfirmed(false)
    h.fetch.mockResolvedValueOnce({ ok: false, status: 400,
                                    json: async () => ({ error: "unknown op 'finding_detail'" }) })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toMatchObject({ code: 'agent_outdated' })
    expect(h.fetch).toHaveBeenCalledOnce()
    expect(JSON.parse(h.fetch.mock.calls[0][1].body).op).toBe('finding_detail')
  })

  test('an agent that answers without the acknowledgement is refused too', async () => {
    __setLayeredAgentConfirmed(false)
    h.liveTriageRun.mockResolvedValue({ id: 'r1', status: 'publishing' })
    h.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ found: true }) })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toThrow(/rebuild the agent image/)
  })

  test('a layered agent takes the verdict during the run', async () => {
    __setLayeredAgentConfirmed(false)
    h.liveTriageRun.mockResolvedValue({ id: 'r1', status: 'running' })
    h.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ found: true, layered_publish: true }) })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')).resolves.toMatchObject({ recorded: true })
    expect(JSON.parse(h.fetch.mock.calls[1][1].body).op).toBe('human_verdict')
  })

  test('an agent that cannot be reached FAILS CLOSED', async () => {
    __setLayeredAgentConfirmed(false)
    h.fetch.mockRejectedValueOnce(new TypeError('fetch failed'))
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toMatchObject({ code: 'agent_outdated' })
    expect(h.fetch).toHaveBeenCalledOnce()
  })
})

describe('the verdict is audited', () => {
  test('a successful write records the finding, the status and the token', async () => {
    // Before this, a verdict was audited NOWHERE: the webapp route wrote no
    // audit row and the agent logged only mute and unmute. A durable decision
    // that suppresses future AI review was invisible to reconstruction.
    await setFindingVerdict(ctx(), 'p1', 'v1', 'likely_noise', 'duplicate of CVE-1')
    expect(h.writeAudit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'owner',
      action: 'mcp.set_finding_verdict',
      targetType: 'finding',
      targetId: 'v1',
      source: 'mcp',
    }))
    expect(h.writeAudit.mock.calls[0][0].after).toMatchObject({
      projectId: 'p1', status: 'likely_noise', channel: 'mcp', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    })
  })

  test('the reason is bounded before it is sent', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed', 'x'.repeat(5000))
    expect(sentBody().reason.length).toBe(500)
  })
})
