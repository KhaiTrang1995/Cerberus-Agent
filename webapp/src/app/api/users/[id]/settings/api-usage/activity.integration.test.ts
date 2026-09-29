/** @vitest-environment node */
/**
 * Strategy rows 1-3 (L4, real Postgres): what the unit tests cannot see because
 * their prisma is a mock that returns whatever it is told.
 *
 * 1. The "scans are running" guard is scoped through `project.userId` in SQL.
 *    Another user's running scan or agent run must never appear in (or block)
 *    this user's check.
 * 2. The report is ONE row per user: a second run replaces it, it never adds one.
 * 3. Deleting a user deletes their report (the FK cascades).
 *
 * Only the session and the providers are stubbed: the route, the job building,
 * the runner, the Shodan parser and the upsert all run for real.
 *
 * Auto-skips unless DATABASE_URL is set. Against the stack's Postgres:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://redamon:<pw>@postgres:5432/redamon' \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run "src/app/api/users/[id]/settings/api-usage/activity.integration.test.ts"'
 */
import { describe, test, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const auth = vi.hoisted(() => ({ userId: '' }))
vi.mock('@/lib/session', () => ({
  getEffectiveUser: async () => (auth.userId ? { userId: auth.userId } : null),
  getSession: async () => (auth.userId ? { userId: auth.userId, role: 'user' } : null),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
}))

import prisma from '@/lib/prisma'
import { GET, POST } from './route'
import { resetRunState } from '@/lib/apiUsage/state'
import type { ApiUsageReportV1, UserActivity } from '@/lib/apiUsage/types'

const HAS_DB = process.env.DATABASE_URL !== undefined
const SHODAN_KEY = 'TESTKEY0000shodanINTEGRATION0001'

const ids = { a: '', b: '', c: '', d: '', projectA: '', projectB: '' }

function call(method: 'GET' | 'POST', userId: string, body?: unknown) {
  auth.userId = userId
  const req = new NextRequest(`http://localhost/api/users/${userId}/settings/api-usage`, {
    method,
    ...(body !== undefined ? { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } } : {}),
  })
  return (method === 'GET' ? GET : POST)(req, { params: Promise.resolve({ id: userId }) })
}

/** The one provider the run may reach; any other URL is an unexpected egress. */
function stubShodan() {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (!String(url).startsWith('https://api.shodan.io/api-info?')) throw new Error(`unexpected egress: ${url}`)
    return new Response(JSON.stringify({
      plan: 'dev', query_credits: 80, scan_credits: 90,
      usage_limits: { query_credits: 100, scan_credits: 100, monitored_ips: 16 },
    }), { status: 200, headers: { 'content-type': 'application/json' } })
  }))
}

async function user(tag: string) {
  const u = await prisma.user.create({
    data: { email: `api-usage-${tag}-${Date.now()}@example.invalid`, name: `api-usage ${tag}`, password: 'x' },
  })
  return u.id
}

beforeAll(async () => {
  if (!HAS_DB) return
  ids.a = await user('a')
  ids.b = await user('b')
  ids.c = await user('c')
  ids.d = await user('d')
  ids.projectA = (await prisma.project.create({ data: { name: 'usage-int A', userId: ids.a } })).id
  ids.projectB = (await prisma.project.create({ data: { name: 'usage-int B', userId: ids.b } })).id
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
  resetRunState()
})

afterAll(async () => {
  if (!HAS_DB) return
  const users = Object.values(ids).filter(Boolean)
  await prisma.auditLog.deleteMany({ where: { targetId: { in: users } } }).catch(() => {})
  await prisma.user.deleteMany({ where: { id: { in: users } } })
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('ROW 1: running scans and agent runs are scoped to the user in SQL', () => {
  test('another user\'s running scan and agent run are absent from activity and do not block the check', async () => {
    const scanA = await prisma.scanJob.create({ data: { projectId: ids.projectA, kind: 'gvm', status: 'running', startedAt: new Date() } })
    await prisma.scanJob.create({ data: { projectId: ids.projectB, kind: 'full_recon', status: 'running', startedAt: new Date() } })
    await prisma.scanJob.create({ data: { projectId: ids.projectA, kind: 'full_recon', status: 'completed' } })
    await prisma.conversation.create({ data: { projectId: ids.projectB, userId: ids.b, sessionId: `usage-int-b-${Date.now()}`, agentRunning: true } })

    // A sees its own scan (so the scoping is not vacuous) and nothing of B's.
    const a = await (await call('GET', ids.a)).json() as { activity: UserActivity }
    expect(a.activity.runningScans).toEqual([
      { projectId: ids.projectA, projectName: 'usage-int A', kind: 'gvm', startedAt: scanA.startedAt!.toISOString() },
    ])
    expect(a.activity.agentRuns).toEqual([])

    // B sees its own scan and agent run.
    const b = await (await call('GET', ids.b)).json() as { activity: UserActivity }
    expect(b.activity.runningScans.map(s => s.projectId)).toEqual([ids.projectB])
    expect(b.activity.agentRuns).toEqual([{ projectId: ids.projectB, projectName: 'usage-int B' }])

    // The POST guard runs the same lookup: A is blocked by its own scan only...
    const blocked = await call('POST', ids.a, {})
    expect(blocked.status).toBe(409)
    expect(await blocked.json()).toMatchObject({ error: 'scans_running', scans: [{ projectId: ids.projectA }], agentRuns: [] })

    // ...and once it finishes, B's scan and agent run no longer block A (no keys -> 400, past the guard).
    await prisma.scanJob.update({ where: { id: scanA.id }, data: { status: 'completed' } })
    const free = await call('POST', ids.a, {})
    expect(free.status).toBe(400)
    expect(await free.json()).toEqual({ error: 'no_keys' })
  })
})

describe.skipIf(!HAS_DB)('ROW 2: one report row per user', () => {
  test('a second run replaces the saved report; the user still has exactly one row', async () => {
    await prisma.userSettings.create({ data: { userId: ids.c, shodanApiKey: SHODAN_KEY } })
    stubShodan()
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-09-28T10:00:00.000Z'))

    const first = await call('POST', ids.c, {})
    expect(first.status).toBe(200)
    const firstBody = await first.json() as { report: ApiUsageReportV1; saved: boolean }
    expect(firstBody.saved).toBe(true)
    expect(firstBody.report.results.map(r => [r.serviceId, r.outcome])).toEqual([['shodan', 'usage']])

    // Past the cooldown. Without overwrite the saved report is protected...
    vi.setSystemTime(new Date('2026-09-28T10:05:00.000Z'))
    const refused = await call('POST', ids.c, {})
    expect(refused.status).toBe(409)
    expect(await refused.json()).toMatchObject({ error: 'report_exists', finishedAt: '2026-09-28T10:00:00.000Z' })

    // ...with it, the run replaces the row instead of adding one.
    const second = await call('POST', ids.c, { overwrite: true })
    expect(second.status).toBe(200)
    const secondBody = await second.json() as { report: ApiUsageReportV1; saved: boolean }
    expect(secondBody.saved).toBe(true)

    const rows = await prisma.apiUsageReport.findMany({ where: { userId: ids.c } })
    expect(rows).toHaveLength(1)
    expect(rows[0].finishedAt.toISOString()).toBe('2026-09-28T10:05:00.000Z')
    expect((rows[0].report as unknown as ApiUsageReportV1).finishedAt).toBe(secondBody.report.finishedAt)
    expect(rows[0]).toMatchObject({ createdById: ids.c, updatedById: ids.c })

    // The row never holds the key, only its last-4 hint.
    expect(JSON.stringify(rows[0].report)).not.toContain(SHODAN_KEY)
    expect((rows[0].report as unknown as ApiUsageReportV1).results[0].keyHint).toBe('••••••••0001')

    // GET returns the saved row.
    const got = await (await call('GET', ids.c)).json() as { report: ApiUsageReportV1 }
    expect(got.report.finishedAt).toBe('2026-09-28T10:05:00.000Z')
  })
})

describe.skipIf(!HAS_DB)('ROW 3: the report goes with its user', () => {
  test('deleting the user deletes their report row', async () => {
    await prisma.apiUsageReport.create({
      data: {
        userId: ids.d, schemaVersion: 1, startedAt: new Date(), finishedAt: new Date(),
        report: { schemaVersion: 1, results: [] }, createdById: ids.d, updatedById: ids.d,
      },
    })
    expect(await prisma.apiUsageReport.count({ where: { userId: ids.d } })).toBe(1)

    await prisma.user.delete({ where: { id: ids.d } })

    expect(await prisma.apiUsageReport.count({ where: { userId: ids.d } })).toBe(0)
    ids.d = ''
  })
})
