/**
 * The spacing and the daily cap on triage runs an MCP agent starts.
 *
 * `start_triage_run` refuses on what this returns, so an off-by-one or the
 * wrong end timestamp either lets an agent spend the owner's model budget
 * faster than documented, or locks a project out for hours after a crash.
 * Prisma is stubbed with the rows the two queries would return.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  today: [] as Array<{ startedAt: Date }>,
  last: null as null | { finishedAt: Date | null; heartbeatAt: Date; startedAt: Date;
                         errorClass: string },
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    triageRun: {
      findMany: async () => h.today,
      findFirst: async () => h.last,
    },
  },
}))

import { mcpRunBudget, MCP_RUN_COOLDOWN_MS, MCP_RUNS_PER_DAY } from './triageRun'

const NOW = Date.parse('2026-09-29T12:00:00Z')
const minutesAgo = (m: number) => new Date(NOW - m * 60_000)

function lastRun(over: Partial<NonNullable<typeof h.last>>) {
  h.last = { finishedAt: null, heartbeatAt: minutesAgo(600), startedAt: minutesAgo(600),
             errorClass: '', ...over }
  h.today = [{ startedAt: h.last.startedAt }]
}

beforeEach(() => {
  h.today = []
  h.last = null
})

describe('the 30-minute spacing', () => {
  test('no MCP run yet: allowed', async () => {
    expect(await mcpRunBudget('p1', NOW)).toEqual({ runsToday: 0, nextAllowedAt: null, reason: null })
  })

  test('counts from finishedAt, and reopens exactly 30 minutes after it', async () => {
    lastRun({ startedAt: minutesAgo(40), heartbeatAt: minutesAgo(35), finishedAt: minutesAgo(10) })
    const out = await mcpRunBudget('p1', NOW)
    expect(out.reason).toBe('cooldown')
    expect(out.nextAllowedAt).toEqual(new Date(NOW - 10 * 60_000 + MCP_RUN_COOLDOWN_MS))
    expect((await mcpRunBudget('p1', NOW + 20 * 60_000)).reason).toBeNull()
  })

  test('with no finishedAt (still running), counts from the last heartbeat', async () => {
    lastRun({ startedAt: minutesAgo(40), heartbeatAt: minutesAgo(5), finishedAt: null })
    const out = await mcpRunBudget('p1', NOW)
    expect(out.reason).toBe('cooldown')
    expect(out.nextAllowedAt).toEqual(new Date(NOW - 5 * 60_000 + MCP_RUN_COOLDOWN_MS))
  })

  test('a lost run counts from its last heartbeat, not from when the loss was noticed', async () => {
    // The sweep stamps `finishedAt = now` when it finds the dead run, which
    // can be hours after the agent died; that pushed the next start away.
    lastRun({ startedAt: minutesAgo(360), heartbeatAt: minutesAgo(355),
              finishedAt: minutesAgo(1), errorClass: 'agent_lost' })
    expect((await mcpRunBudget('p1', NOW)).reason).toBeNull()
  })
})

describe('the daily cap', () => {
  test(`${MCP_RUNS_PER_DAY} runs in the last 24 hours refuse the next, reopening as the oldest ages out`, async () => {
    h.today = Array.from({ length: MCP_RUNS_PER_DAY }, (_, i) => ({ startedAt: minutesAgo(1400 - i * 60) }))
    h.last = { finishedAt: minutesAgo(100), heartbeatAt: minutesAgo(100),
               startedAt: minutesAgo(110), errorClass: '' }
    const out = await mcpRunBudget('p1', NOW)
    expect(out).toMatchObject({ runsToday: MCP_RUNS_PER_DAY, reason: 'daily_cap' })
    expect(out.nextAllowedAt).toEqual(new Date(NOW - 1400 * 60_000 + 24 * 60 * 60_000))
  })

  test(`${MCP_RUNS_PER_DAY - 1} runs leave room for one more`, async () => {
    h.today = Array.from({ length: MCP_RUNS_PER_DAY - 1 }, (_, i) => ({ startedAt: minutesAgo(1400 - i * 60) }))
    h.last = { finishedAt: minutesAgo(100), heartbeatAt: minutesAgo(100),
               startedAt: minutesAgo(110), errorClass: '' }
    expect((await mcpRunBudget('p1', NOW)).reason).toBeNull()
  })
})
