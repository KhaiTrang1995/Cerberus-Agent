/**
 * Scan Timeline — project activation lock (Section 4A.3).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const prismaMock = vi.hoisted(() => ({
  project: { findUnique: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
}))
vi.mock('@/lib/prisma', () => ({ default: prismaMock }))

import {
  isActivationInProgress,
  assertGraphNotActivating,
  activationBusy,
  acquireActivationLock,
  releaseActivationLock,
  activationLockTtlMs,
  ACTIVATION_STATE_ACTIVATING,
  ACTIVATION_STATE_IDLE,
} from './activationLock'

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACTIVATION_LOCK_TTL_MS
})
afterEach(() => { delete process.env.ACTIVATION_LOCK_TTL_MS })

describe('isActivationInProgress', () => {
  test('idle project → false', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('freshly activating project → true', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    expect(await isActivationInProgress('p1')).toBe(true)
  })

  test('a lock older than the TTL is stale, so the project is not wedged forever', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING,
      activationStartedAt: new Date(Date.now() - activationLockTtlMs() - 1000),
    })
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('missing project → false', async () => {
    prismaMock.project.findUnique.mockResolvedValue(null)
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('TTL is configurable and falls back on garbage', () => {
    process.env.ACTIVATION_LOCK_TTL_MS = '60000'
    expect(activationLockTtlMs()).toBe(60000)
    process.env.ACTIVATION_LOCK_TTL_MS = 'nope'
    expect(activationLockTtlMs()).toBe(15 * 60 * 1000)
  })
})

describe('assertGraphNotActivating', () => {
  test('returns null when the graph is free', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await assertGraphNotActivating('p1')).toBeNull()
  })

  test('returns a 409 the caller must return', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    const res = await assertGraphNotActivating('p1')
    expect(res).toBeInstanceOf(NextResponse)
    expect(res!.status).toBe(409)
    expect((await res!.json()).activationInProgress).toBe(true)
  })

  test('a failed lock read allows the operation rather than blocking all work', async () => {
    prismaMock.project.findUnique.mockRejectedValue(new Error('db down'))
    expect(await assertGraphNotActivating('p1')).toBeNull()
  })
})

describe('activationBusy (the fail-closed form, for mutes and unmutes)', () => {
  test('false when the graph is free, true while activating', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await activationBusy('p1')).toBe(false)
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    expect(await activationBusy('p1')).toBe(true)
  })

  test('a failed lock read is BUSY: activation would swallow a mute written now', async () => {
    // The opposite of assertGraphNotActivating, deliberately.
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    prismaMock.project.findUnique.mockRejectedValue(new Error('db down'))
    expect(await activationBusy('p1')).toBe(true)
  })
})

describe('acquireActivationLock', () => {
  test('takes the lock with a conditional update on idle-or-stale', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    const handle = await acquireActivationLock('p1', 'v2')
    expect(handle.acquired).toBe(true)
    const arg = prismaMock.project.updateMany.mock.calls[0][0]
    expect(arg.where.id).toBe('p1')
    // Only an idle (or expired) project matches — that is what makes it atomic.
    expect(arg.where.OR).toEqual([
      { activationState: ACTIVATION_STATE_IDLE },
      { activationStartedAt: null },
      { activationStartedAt: { lt: expect.any(Date) } },
    ])
    expect(arg.data).toMatchObject({
      activationState: ACTIVATION_STATE_ACTIVATING, activationVersionId: 'v2',
    })
  })

  test('a second concurrent activation loses (no rows matched)', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    const handle = await acquireActivationLock('p1', 'v2')
    expect(handle.acquired).toBe(false)
    expect(handle.reason).toMatch(/already in progress/i)
  })
})

describe('releaseActivationLock', () => {
  test('clears the flag', async () => {
    prismaMock.project.update.mockResolvedValue({})
    await releaseActivationLock('p1')
    expect(prismaMock.project.update).toHaveBeenCalledWith({
      where: { id: 'p1' },
      data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
    })
  })

  test('never throws — the TTL is the backstop', async () => {
    prismaMock.project.update.mockRejectedValue(new Error('db down'))
    await expect(releaseActivationLock('p1')).resolves.toBeUndefined()
  })
})
