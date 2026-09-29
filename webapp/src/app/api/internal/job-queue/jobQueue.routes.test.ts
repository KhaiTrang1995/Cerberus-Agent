/**
 * Scan Queue — the dispatcher's internal API (plan Phase 2). Internal-key only, so
 * each route rejects non-internal first. Beyond that the DISPATCH route is the
 * fail-closed core: project gone -> failed, settings fingerprint changed ->
 * needs_review with NO start call (C-4), another job for the project -> busy,
 * agent running + full_recon -> deferred (C-5), else the same start path a button
 * uses. The RECONCILE route closes finished 'running' rows even with no browser
 * (C-6), and never closes a still-active one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { settingsFingerprint } from '@/lib/jobQueue'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  jqFindUnique: vi.fn(),
  jqUpdateMany: vi.fn(),
  jqFindFirst: vi.fn(),
  jqUpdate: vi.fn(),
  jqFindMany: vi.fn(),
  jqCount: vi.fn(),
  sjFindMany: vi.fn(),
  // Set in beforeEach: routes a row set to one of the two sweeps.
  sweep: (() => {}) as (rows: unknown[], runKeyed?: boolean) => void,
  sjUpdateMany: vi.fn(),
  projectFindUnique: vi.fn(),
  agentState: vi.fn(),
  dispatchStart: vi.fn(),
  stopScan: vi.fn(),
  orchFetch: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: (...a: unknown[]) => h.jqFindUnique(...a),
      updateMany: (...a: unknown[]) => h.jqUpdateMany(...a),
      findFirst: (...a: unknown[]) => h.jqFindFirst(...a),
      update: (...a: unknown[]) => h.jqUpdate(...a),
      findMany: (...a: unknown[]) => h.jqFindMany(...a),
      count: (...a: unknown[]) => h.jqCount(...a),
    },
    scanJob: {
      findMany: (...a: unknown[]) => h.sjFindMany(...a),
      updateMany: (...a: unknown[]) => h.sjUpdateMany(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
  },
}))
vi.mock('@/lib/startScan', () => ({
  dispatchStart: (...a: unknown[]) => h.dispatchStart(...a),
  stopScan: (...a: unknown[]) => h.stopScan(...a),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchFetch(...a) }))
vi.mock('@/lib/agentSessions', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/agentSessions')>()),
  checkAgentSessions: (...a: unknown[]) => h.agentState(...a),
}))

import { POST as dispatch } from './[id]/dispatch/route'
import { GET as candidates } from './candidates/route'
import { POST as reconcile } from './reconcile/route'

const PROJECT = {
  id: 'p1', userId: 'u1', targetDomain: 'example.com', ipMode: false,
  targetIps: [], scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}
const HASH = settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>)

function baseRow(over: Record<string, unknown> = {}) {
  return {
    id: 'j1', projectId: 'p1', userId: 'u1', kind: 'full_recon', payload: {},
    settingsHash: HASH, status: 'queued', attempts: 0, maxAttempts: 20, ...over,
  }
}

const post = (url: string, body: unknown = {}) => new NextRequest(url, {
  method: 'POST', headers: { 'x-internal-key': 'k' }, body: JSON.stringify(body),
})
const get = (url: string) => new NextRequest(url, { method: 'GET', headers: { 'x-internal-key': 'k' } })
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.jqFindUnique.mockResolvedValue(baseRow())
  h.jqUpdateMany.mockResolvedValue({ count: 1 })
  h.jqFindFirst.mockResolvedValue(null)
  h.jqUpdate.mockResolvedValue({})
  h.jqFindMany.mockResolvedValue([])
  h.jqCount.mockResolvedValue(0)
  h.sjFindMany.mockResolvedValue([])
  // Two sweeps now run per tick (one-per-project kinds, then run-keyed kinds).
  // A helper that answers only the sweep a test cares about keeps rows from
  // being returned to BOTH and double-counted.
  h.sweep = (rows: unknown[], runKeyed = false) =>
    h.sjFindMany.mockImplementation((args: { where: { kind: { in: string[] } } }) =>
      Promise.resolve(args.where.kind.in.includes('trufflehog') === runKeyed ? rows : []))
  h.sjUpdateMany.mockResolvedValue({ count: 1 })
  h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.agentState.mockResolvedValue('idle')
  h.dispatchStart.mockResolvedValue({ ok: true, runId: 'r1', scanJobId: 'sj1' })
  h.stopScan.mockResolvedValue(undefined)
})

describe('dispatch route auth', () => {
  test('rejects a non-internal caller', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(401)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route fail-closed checks', () => {
  test('a changed settings fingerprint -> needs_review and NO start call (C-4)', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ settingsHash: 'stale-hash' }))
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.needsReview).toBe(true)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    // Guarded on status='dispatching' (Finding 1b) so a racing cancel is not overwritten.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'dispatching' }),
      data: expect.objectContaining({ status: 'needs_review', blockedCode: 'settings_changed' }),
    }))
  })

  test('a deleted project -> failed, never dispatches (C-7)', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  test('another running job for the project -> busy, no start (C-12)', async () => {
    h.jqFindFirst.mockResolvedValue({ id: 'other' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('busy')
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })

  test('agent running + full_recon -> deferred, no start (C-5)', async () => {
    h.agentState.mockResolvedValue('running')
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('agent_running')
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        status: 'queued',
        blockedCode: 'agent_running',
        blockedReason: 'an agent session is running for this project; a full recon would wipe its graph',
      }),
    }))
  })

  test('a session flag the agent could not confirm also defers, saying so (C-8)', async () => {
    h.agentState.mockResolvedValue('unverified')
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect((await res.json()).blocked).toBe('agent_running')
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ blockedReason: expect.stringMatching(/could not be reached to confirm it/) }),
    }))
  })

  test('a stale flag the agent disowns does not block the dispatch (C-8)', async () => {
    // checkAgentSessions cleared it and answered idle.
    h.agentState.mockResolvedValue('idle')
    await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(h.agentState).toHaveBeenCalledWith(PROJECT.id)
    expect(h.dispatchStart).toHaveBeenCalled()
  })

  test('a claim lost to a concurrent dispatch -> 409, no start', async () => {
    h.jqUpdateMany.mockResolvedValue({ count: 0 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route happy + failure paths', () => {
  test('all checks pass -> running (conditional on still dispatching), start called, ids recorded', async () => {
    // claim updateMany -> {count:1}; success updateMany -> {count:1} (won the race)
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(h.dispatchStart).toHaveBeenCalledWith('full_recon', 'p1', expect.objectContaining({ actorUserId: 'u1' }))
    // The success write is guarded on status='dispatching' so a concurrent cancel wins.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'dispatching' }),
      data: expect.objectContaining({ status: 'running', runId: 'r1', scanJobId: 'sj1' }),
    }))
    expect(h.stopScan).not.toHaveBeenCalled()
  })

  test('regression F1: a cancel during dispatch is NOT resurrected; the started scan is stopped', async () => {
    // claim wins (count 1); the success write loses because a cancel flipped the row
    // out of 'dispatching' (count 0).
    h.jqUpdateMany
      .mockResolvedValueOnce({ count: 1 })   // claim
      .mockResolvedValueOnce({ count: 0 })   // success write lost to the cancel
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.canceledDuringDispatch).toBe(true)
    // The scan already started, so it must be stopped rather than left orphaned.
    expect(h.stopScan).toHaveBeenCalledWith('full_recon', 'p1', 'r1')
  })

  test('a RAM capacity wait requeues WITHOUT spending an attempt (guarded on dispatching)', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.temporary).toBe(true)
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')
    expect(call[0].where).toMatchObject({ id: 'j1', status: 'dispatching' })
    expect(call[0].data).toMatchObject({ status: 'queued', blockedCode: 'ram' })
    // A capacity wait must NOT consume the attempt budget (that would delay the
    // eventual promotion and eventually fail a job that only waited its turn).
    expect(call[0].data.attempts).toBeUndefined()
    expect(call[0].data.notBefore).toBeInstanceOf(Date)
  })

  test('a hard concurrency-cap refusal also requeues without spending an attempt', async () => {
    h.dispatchStart.mockResolvedValue({
      ok: false, status: 409, error: '2 of 2 concurrent scans allowed per user',
      limit: { limitType: 'hard' },
    })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect((await res.json()).blocked).toBe('hard')
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')
    expect(call[0].data).toMatchObject({ status: 'queued', blockedCode: 'hard' })
    expect(call[0].data.attempts).toBeUndefined()
  })

  // The regression that this stress test surfaced: a job waiting behind long-running
  // scans must NOT be failed just because it was bounced many times on capacity.
  test('a capacity wait NEVER fails, even at a high attempt count', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ attempts: 19, maxAttempts: 20 }))
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBeUndefined()
    expect(body.temporary).toBe(true)
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')
    expect(call[0].data.status).toBe('queued')
  })

  test('a permanent refusal fails the job', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 400, error: 'bad config' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBe(true)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })
})

describe('candidates route', () => {
  test('returns ordered ready rows + activeCount from the in-flight set', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }, { projectId: 'pBusy' }]) // in-flight (2 rows, 1 project)
      .mockResolvedValueOnce([
        { id: 'a', projectId: 'p1', userId: 'u1', kind: 'gvm', envelopeBytes: BigInt(2684354560), priority: 10, enqueuedAt: new Date('2026-08-09T00:00:00Z'), attempts: 0, maxAttempts: 20 },
      ])
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    const body = await res.json()
    expect(body.activeCount).toBe(2)
    expect(body.candidates[0]).toMatchObject({ id: 'a', kind: 'gvm', envelopeBytes: 2684354560 })
  })

  test('regression F2: queued jobs of an already-busy project are excluded from candidates', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }]) // in-flight for pBusy
      .mockResolvedValueOnce([])
    await candidates(get('http://x/api/internal/job-queue/candidates'))
    // The queued query must exclude pBusy, so its big head job can't trip the
    // dispatcher's head-of-line RAM break and starve other tenants.
    expect(h.jqFindMany).toHaveBeenLastCalledWith(expect.objectContaining({
      where: expect.objectContaining({ projectId: { notIn: ['pBusy'] } }),
    }))
  })

  test('rejects non-internal', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    expect(res.status).toBe(401)
  })
})

describe('reconcile route (C-6)', () => {
  test('closes a running row whose project is no longer active and past grace', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p2'] }))
    const body = await res.json()
    expect(body.closed).toBe(1)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'done' }),
    }))
  })

  test('does NOT close a row whose project is still active', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })

  test('does NOT close a freshly-started row inside the grace window', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date() },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
  })

  test('the close is guarded on status=running, so a repeat reconcile is idempotent', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    // The WHERE clause re-checks status='running', so a concurrent close (or a
    // second reconcile pass) can never double-transition the same row.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'running' }),
    }))
  })

  test('a malformed body (activeProjects absent / not an array) is treated as no active projects', async () => {
    h.jqFindMany.mockResolvedValue([{ id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) }])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: 'oops' }))
    expect((await res.json()).closed).toBe(1) // nothing active -> the stale row closes
  })
})

describe('reconcile route - stuck ScanJob rows (phantom "running")', () => {
  const old = () => new Date(Date.now() - 5 * 60_000)

  // The core symptom: a scheduled scan that finished with nobody viewing its project
  // leaves a 'running' ScanJob forever, and a 15-min schedule piles them up. The
  // reaper's reconcile now closes them server-side, using the orchestrator's real
  // outcome for the row (completed here).
  test('closes a stuck ScanJob using the orchestrator outcome (completed)', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'completed' }) })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect((await res.json()).scansClosed).toBe(1)
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 's1', status: 'running' }),
      data: expect.objectContaining({ status: 'completed' }),
    }))
    // Queried the recon status path for this kind.
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/recon\/p1\/status$/)
  })

  test('an orchestrator error maps to failed', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'gvm' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'error' }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  // A scan the orchestrator has forgotten (restart, or reaped) -> we cannot confirm
  // how it ended, so 'canceled' rather than a stuck 'running'.
  test('a scan the orchestrator no longer knows about is canceled', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  // The pile: several stuck rows for the same project+kind. The newest takes the
  // real outcome; the older, superseded runs are canceled. One status fetch per group.
  test('a pile of stuck rows: newest takes the outcome, older are canceled', async () => {
    // Route orders newest-first within a group; mirror that here.
    h.sweep([
      { id: 'newest', projectId: 'p1', kind: 'full_recon' },
      { id: 'older1', projectId: 'p1', kind: 'full_recon' },
      { id: 'older2', projectId: 'p1', kind: 'full_recon' },
    ])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'completed' }) })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect((await res.json()).scansClosed).toBe(3)
    expect(h.orchFetch).toHaveBeenCalledTimes(1) // one fetch for the group
    const byId = Object.fromEntries(h.sjUpdateMany.mock.calls.map(c => [c[0].where.id, c[0].data.status]))
    expect(byId).toEqual({ newest: 'completed', older1: 'canceled', older2: 'canceled' })
  })

  test('a ScanJob whose project IS active is left running', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect((await res.json()).scansClosed).toBe(0)
    expect(h.sjUpdateMany).not.toHaveBeenCalled()
  })

  // Only kinds that WRITE a ScanJob per project are swept. partial_recon / ai_attack
  // are run-keyed (own reconcile); supply_chain_repo is queue-dispatched and writes
  // no ScanJob (its history is the JobQueue row, closed by the queue reconcile).
  test('sweeps only the one-ScanJob-per-project kinds', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    const where = h.sjFindMany.mock.calls[0][0].where
    for (const k of ['full_recon', 'supply_chain', 'gvm', 'github_hunt']) {
      expect(where.kind.in).toContain(k)
    }
    // trufflehog is run-keyed since the multi-source migration: sweeping it here
    // would force-cancel all but the newest row per (project, kind), i.e. every
    // parallel source but one, while their containers were still running.
    for (const k of ['partial_recon', 'ai_attack', 'supply_chain_repo', 'trufflehog']) {
      expect(where.kind.in).not.toContain(k)
    }
  })

  test('trufflehog rows are swept run-granularly against /all', async () => {
    h.sweep([
      { id: 'r-docker', projectId: 'p1', kind: 'trufflehog', runId: 'docker' },
      { id: 'r-hf', projectId: 'p1', kind: 'trufflehog', runId: 'huggingface' },
    ], true)
    h.orchFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ runs: [
        { run_id: 'docker', status: 'completed' },
        { run_id: 'huggingface', status: 'error' },
      ] }),
    })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    // Each row takes ITS OWN run's outcome; neither cancels the other.
    const byId = Object.fromEntries(h.sjUpdateMany.mock.calls.map(c => [c[0].where.id, c[0].data.status]))
    expect(byId).toEqual({ 'r-docker': 'completed', 'r-hf': 'failed' })
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/trufflehog\/p1\/all$/)
  })

  test('a trufflehog row whose run vanished from /all is canceled, not left running', async () => {
    h.sweep([{ id: 'r1', projectId: 'p1', kind: 'trufflehog', runId: 'docker' }], true)
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ runs: [] }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  test('one /all fetch serves every stuck run of a project', async () => {
    h.sweep([
      { id: 'a', projectId: 'p1', kind: 'trufflehog', runId: 'docker' },
      { id: 'b', projectId: 'p1', kind: 'trufflehog', runId: 's3' },
      { id: 'c', projectId: 'p1', kind: 'trufflehog', runId: 'gcs' },
    ], true)
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ runs: [] }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.orchFetch).toHaveBeenCalledTimes(1)
  })

  // Active projects are excluded at the DB level, so a genuinely-running scan never
  // consumes the per-tick budget and starves the stale rows behind it.
  test('active projects are excluded in the ScanJob query, not just after', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['pa', 'pb'] }))
    const where = h.sjFindMany.mock.calls[0][0].where
    expect(where.projectId).toEqual({ notIn: ['pa', 'pb'] })
  })

  test('with no active projects the ScanJob query carries no project filter', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjFindMany.mock.calls[0][0].where.projectId).toBeUndefined()
  })
})
