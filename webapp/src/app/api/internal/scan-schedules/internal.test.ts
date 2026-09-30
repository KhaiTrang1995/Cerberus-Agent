/**
 * Scan Timeline — the scheduler's internal API (Section 7.2, F3).
 *
 * These three endpoints are reachable ONLY with the internal key (the orchestrator
 * worker), so the first thing each must do is reject anything else. Beyond that:
 * `/run` must go through the SAME start path a manual scan uses, and `/defer`
 * must record why nothing ran and push the schedule out so the worker cannot
 * hot-loop.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  findScheduleMany: vi.fn(),
  projectFindMany: vi.fn(),
  findSchedule: vi.fn(),
  updateSchedule: vi.fn(),
  countJobs: vi.fn(),
  start: vi.fn(),
  createJob: vi.fn(),
  enqueue: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: {
      findMany: (...a: unknown[]) => h.findScheduleMany(...a),
      findUnique: (...a: unknown[]) => h.findSchedule(...a),
      update: (...a: unknown[]) => h.updateSchedule(...a),
    },
    scanJob: { count: (...a: unknown[]) => h.countJobs(...a) },
    project: { findMany: (...a: unknown[]) => h.projectFindMany(...a) },
  },
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => h.start(...a) }))
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.enqueue(...a) }))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  createScanJob: (...a: unknown[]) => h.createJob(...a),
}))

import { GET as due } from './due/route'
import { POST as run } from './[scheduleId]/run/route'

const req = (url: string, body?: unknown) => new NextRequest(url, {
  method: body === undefined ? 'GET' : 'POST',
  ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
})
const sp = (scheduleId: string) => ({ params: Promise.resolve({ scheduleId }) })

const SCHEDULE = {
  id: 's1', projectId: 'p1', userId: 'u1', mode: 'interval', scanMode: 'new',
  intervalMinutes: 60, cronExpr: null, enabled: true, lastRunAt: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.findScheduleMany.mockResolvedValue([])
  h.findSchedule.mockResolvedValue(SCHEDULE)
  h.updateSchedule.mockResolvedValue({})
  h.countJobs.mockResolvedValue(0)
  h.projectFindMany.mockResolvedValue([])
  h.start.mockResolvedValue({ ok: true, versionId: 'v3', versionSeq: 3, scanJobId: 'job1', frozenVersionId: 'v2' })
  h.createJob.mockResolvedValue({ id: 'job1' })
  h.enqueue.mockResolvedValue({ ok: true, status: 201, id: 'jq1' })
})

describe('authentication', () => {
  test.each([
    ['due', () => due(req('http://x/api/internal/scan-schedules/due'))],
    ['run', () => run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))],
  ])('%s rejects a non-internal caller with 401 and does no work', async (_name, call) => {
    h.isInternal.mockReturnValue(false)
    const res = await call()
    expect(res.status).toBe(401)
    expect(h.start).not.toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
    expect(h.findScheduleMany).not.toHaveBeenCalled()
  })
})

describe('GET /due', () => {
  test('returns enabled schedules whose next run has passed', async () => {
    await due(req('http://x/api/internal/scan-schedules/due'))
    const where = h.findScheduleMany.mock.calls[0][0].where
    expect(where.enabled).toBe(true)
    expect(where.nextRunAt.lte).toBeInstanceOf(Date)
  })

  test('resolves activation state for N projects in ONE query, not N (no N+1)', async () => {
    // The worker polls this every tick; one lock query per due project turned a
    // 25-schedule tick into 25 sequential round-trips.
    h.findScheduleMany.mockResolvedValue(
      Array.from({ length: 8 }, (_, i) => ({
        id: `s${i}`, projectId: `p${i}`, userId: 'u1', mode: 'cron', scanMode: 'new',
        nextRunAt: new Date(), estimatedEnvelopeBytes: null,
      }))
    )
    await due(req('http://x/api/internal/scan-schedules/due'))
    expect(h.projectFindMany).toHaveBeenCalledTimes(1)
    expect(h.projectFindMany.mock.calls[0][0].where.id.in).toHaveLength(8)
  })

  test('flags projects whose graph is mid-activation (F3)', async () => {
    h.findScheduleMany.mockResolvedValue([
      { id: 's1', projectId: 'p1', userId: 'u1', mode: 'cron', scanMode: 'new', nextRunAt: new Date(), estimatedEnvelopeBytes: null },
      { id: 's2', projectId: 'p2', userId: 'u1', mode: 'cron', scanMode: 'new', nextRunAt: new Date(), estimatedEnvelopeBytes: null },
    ])
    h.projectFindMany.mockResolvedValue([
      { id: 'p2', activationState: 'activating', activationStartedAt: new Date() },
    ])
    const body = await (await due(req('http://x/api/internal/scan-schedules/due'))).json()
    expect(body.schedules.map((s: { activationInProgress: boolean }) => s.activationInProgress))
      .toEqual([false, true])
  })
})

describe('POST /run', () => {
  test('starts through the shared start path, tagged as scheduled', async () => {
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect(h.start).toHaveBeenCalledWith({
      projectId: 'p1', mode: 'new', trigger: 'scheduled', actorUserId: 'u1', scheduleId: 's1',
    })
    expect((await res.json()).ok).toBe(true)
  })

  test('advances nextRunAt after a run', async () => {
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data.lastRunAt).toBeInstanceOf(Date)
    expect(data.nextRunAt).toBeInstanceOf(Date)
  })

  test('a run never writes enabled back, so a pause made while it started survives', async () => {
    // update_project_scope pauses the schedules when a batch gains hosts. Writing
    // back the `enabled: true` read before the multi-second start re-enabled a
    // schedule paused in between, and its next run reached the new hosts unwatched.
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data).not.toHaveProperty('enabled')
  })

  test('a one-off schedule is spent after firing', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, mode: 'once', intervalMinutes: null })
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data.enabled).toBe(false)
    expect(data.nextRunAt).toBeNull()
  })

  test('a RAM refusal ENQUEUES the occurrence instead of burning it (Phase 4)', async () => {
    h.start.mockResolvedValue({ ok: false, status: 429, error: 'no memory', limit: { limitType: 'ram' }, scanJobId: 'job9' })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.queued).toBe(true)
    expect(body.jobId).toBe('jq1')
    // The schedule still rolls forward (the occurrence became a queue row).
    expect(h.updateSchedule).toHaveBeenCalled()
    expect(h.enqueue).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'p1', kind: 'full_recon', scheduleId: 's1', priority: 0,
    }))
    // No duplicate failed ScanJob for a temporary refusal.
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('a busy 409 refusal enqueues rather than recording a failed run', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 409,
      error: 'Cannot start a scan while a full recon scan is running for this project. Stop it first.',
      busy: 'a full recon scan is running',
    })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect((await res.json()).queued).toBe(true)
    expect(h.enqueue).toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
    expect(h.updateSchedule).toHaveBeenCalled()
  })

  test('an activation in progress enqueues (F3 preserved: nothing spawns)', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 409, error: 'A version activation is in progress', activationInProgress: true,
    })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect((await res.json()).queued).toBe(true)
    expect(h.enqueue).toHaveBeenCalled()
  })

  test('a PERMANENT failure records a failed ScanJob and does not enqueue', async () => {
    h.start.mockResolvedValue({ ok: false, status: 400, error: 'Project has no target domain configured' })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed', scheduleId: 's1' }))
  })

  test('a disabled schedule is not run', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, enabled: false })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(409)
    expect(h.start).not.toHaveBeenCalled()
  })

  test('an unknown schedule is a 404', async () => {
    h.findSchedule.mockResolvedValue(null)
    expect((await run(req('http://x/api/internal/scan-schedules/nope/run', {}), sp('nope'))).status).toBe(404)
    expect(h.start).not.toHaveBeenCalled()
  })
})

