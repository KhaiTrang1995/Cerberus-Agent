/**
 * C-10: a project's "Preset applied" badge follows a rename of the user preset
 * it names and is cleared when that preset is deleted.
 *
 * What must not happen: a badge for a DIFFERENT preset moving (a built-in with
 * the same id string, a badge written before badges carried an id), or a badge
 * a preset load wrote meanwhile being overwritten.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { Prisma } from '@prisma/client'

const h = vi.hoisted(() => ({ findMany: vi.fn(), updateMany: vi.fn() }))
const db = { project: { findMany: h.findMany, updateMany: h.updateMany } }
vi.mock('@/lib/prisma', () => ({ default: db }))

import { clearPresetBadges, renamePresetBadges } from './badges'

const T = new Date('2026-09-29T10:00:00.000Z')
const badge = (over: Record<string, unknown> = {}) =>
  ({ name: 'Old', fingerprint: 'v2:abc', presetId: 'up1', source: 'user', ...over })

const ROWS = [
  { id: 'mine', updatedAt: T, loadedPreset: badge() },
  { id: 'other-preset', updatedAt: T, loadedPreset: badge({ presetId: 'up2' }) },
  { id: 'builtin-same-id', updatedAt: T, loadedPreset: badge({ source: 'builtin' }) },
  { id: 'unversioned', updatedAt: T, loadedPreset: { name: 'Old', fingerprint: '123abc' } },
  { id: 'none', updatedAt: T, loadedPreset: null },
]

beforeEach(() => {
  vi.clearAllMocks()
  h.findMany.mockResolvedValue(ROWS)
  h.updateMany.mockResolvedValue({ count: 1 })
})

describe('renamePresetBadges', () => {
  test('reads only this user\'s projects', async () => {
    await renamePresetBadges(db as never, 'u1', 'up1', 'New')
    expect(h.findMany.mock.calls[0][0].where).toEqual({ userId: 'u1' })
  })

  test('renames only the badges naming this user preset, keeping the rest of the badge', async () => {
    expect(await renamePresetBadges(db as never, 'u1', 'up1', 'New')).toBe(1)
    expect(h.updateMany).toHaveBeenCalledTimes(1)
    expect(h.updateMany).toHaveBeenCalledWith({
      where: { id: 'mine', updatedAt: T },
      data: { loadedPreset: badge({ name: 'New' }) },
    })
  })

  test('a project written since it was read keeps its badge, and is not counted', async () => {
    h.updateMany.mockResolvedValue({ count: 0 })
    expect(await renamePresetBadges(db as never, 'u1', 'up1', 'New')).toBe(0)
  })
})

describe('clearPresetBadges', () => {
  test('clears only the badges naming this user preset', async () => {
    h.findMany.mockResolvedValue([...ROWS, { id: 'mine-too', updatedAt: T, loadedPreset: badge() }])
    expect(await clearPresetBadges(db as never, 'u1', 'up1')).toBe(2)
    expect(h.updateMany.mock.calls.map(c => c[0].where.id)).toEqual(['mine', 'mine-too'])
    expect(h.updateMany.mock.calls[0][0]).toEqual({
      where: { id: 'mine', updatedAt: T },
      data: { loadedPreset: Prisma.DbNull },
    })
  })

  test('nothing names it: no write at all', async () => {
    expect(await clearPresetBadges(db as never, 'u1', 'up9')).toBe(0)
    expect(h.updateMany).not.toHaveBeenCalled()
  })
})
