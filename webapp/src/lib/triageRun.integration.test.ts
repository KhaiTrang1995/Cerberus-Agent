/** @vitest-environment node */
/**
 * L4, real Postgres: retention never deletes a run that is still in use.
 *
 * `trimTriageRuns` runs after every finish and deletes rows. The unit tests
 * would have to mock the very `deleteMany` filter that decides what survives,
 * so the claim is checked against a real table: a live run, the run the board
 * treats as its latest (a partial publish counts), and the newest 50 all
 * survive; older surplus rows go.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://redamon:<pw>@postgres:5432/redamon' \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/triageRun.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { latestPublishedRunId, trimTriageRuns, TRIAGE_RUN_KEEP_NEWEST } from './triageRun'

const HAS_DB = process.env.DATABASE_URL !== undefined
const DAY = 24 * 60 * 60 * 1000
const NOW = Date.now()

let prisma: PrismaClient
let userId = ''
let projectId = ''

async function run(id: string, status: string, daysAgo: number) {
  const at = new Date(NOW - daysAgo * DAY)
  await prisma.triageRun.create({
    data: { id: `${projectId}-${id}`, projectId, actorUserId: userId, status,
            startedAt: at, heartbeatAt: at,
            finishedAt: status === 'running' ? null : at },
  })
}

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const user = await prisma.user.create({
    data: { email: `triage-trim-int-${Date.now()}@example.invalid`, name: 'triage trim int', password: 'x' },
  })
  userId = user.id
  const project = await prisma.project.create({
    data: { name: 'triage trim integration', userId, targetDomain: 'example.invalid' },
  })
  projectId = project.id
}, 60_000)

afterAll(async () => {
  if (!HAS_DB || !prisma) return
  try { await prisma.project.delete({ where: { id: projectId } }) } catch { /* cascade */ }
  try { await prisma.user.delete({ where: { id: userId } }) } catch { /* ignore */ }
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('trimming finished triage runs', () => {
  test('keeps the live run, the board\'s latest published run and the newest 50; deletes older surplus', async () => {
    await run('old-completed', 'completed', 12)
    await run('surplus-1', 'failed', 11)
    await run('surplus-2', 'stopped', 10)
    await run('live', 'running', 9)                   // a run whose heartbeat the trim must not judge
    await run('latest-published', 'completed_partial', 8)
    for (let i = 0; i < TRIAGE_RUN_KEEP_NEWEST; i++) {
      await run(`newer-${i}`, i % 2 ? 'failed' : 'stopped', 7 - i / 10)
    }
    expect(await latestPublishedRunId(projectId)).toBe(`${projectId}-latest-published`)

    const deleted = await trimTriageRuns(projectId, NOW)

    const left = new Set((await prisma.triageRun.findMany({
      where: { projectId }, select: { id: true },
    })).map((r) => r.id.slice(projectId.length + 1)))
    expect(left.has('live')).toBe(true)
    // A partial publish is the board's latest run too; keeping only the newest
    // `completed` one deleted it, and every row then read as stale.
    expect(left.has('latest-published')).toBe(true)
    for (let i = 0; i < TRIAGE_RUN_KEEP_NEWEST; i++) expect(left.has(`newer-${i}`)).toBe(true)
    expect(left.has('surplus-1')).toBe(false)
    expect(left.has('surplus-2')).toBe(false)
    expect(left.has('old-completed')).toBe(false)
    expect(deleted).toBe(3)
    expect(await latestPublishedRunId(projectId)).toBe(`${projectId}-latest-published`)
  }, 60_000)
})
