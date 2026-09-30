/**
 * Keep projects' "Preset applied" badge naming a user preset that exists.
 *
 * A badge that carries its preset's id follows a rename and is cleared by a
 * delete. One written before the badge carried an id holds only a name and is
 * left alone: a name can also belong to a built-in or to another preset.
 *
 * A preset's SETTINGS changing leaves its badges as they are. The badge says the
 * project still holds what loading that preset produced, which stays true.
 *
 * Each project is rewritten conditionally on its updatedAt, so a preset load
 * that lands meanwhile keeps its own badge. The write moves updatedAt like any
 * other, so a settings form left open on that project gets the stale-save
 * refusal instead of writing the old badge back. Server-side only.
 */
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { readLoadedPreset } from '@/lib/project-preset-utils'

type Db = Prisma.TransactionClient | typeof prisma

/** The user's projects whose badge names this user preset. */
async function projectsBadgedWith(db: Db, userId: string, presetId: string) {
  // Filtered here rather than with a JSON path query: a user has tens of
  // projects, and this reads the column exactly as the badge does.
  const rows = await db.project.findMany({
    where: { userId },
    select: { id: true, loadedPreset: true, updatedAt: true },
  })
  return rows.flatMap(r => {
    const loaded = readLoadedPreset(r.loadedPreset)
    return loaded?.source === 'user' && loaded.presetId === presetId
      ? [{ id: r.id, updatedAt: r.updatedAt, loaded }]
      : []
  })
}

/** Renames the badge on every project that loaded this preset. Returns how many moved. */
export async function renamePresetBadges(db: Db, userId: string, presetId: string, name: string): Promise<number> {
  let renamed = 0
  for (const p of await projectsBadgedWith(db, userId, presetId)) {
    const { count } = await db.project.updateMany({
      where: { id: p.id, updatedAt: p.updatedAt },
      data: { loadedPreset: { ...p.loaded, name } },
    })
    renamed += count
  }
  return renamed
}

/** Clears the badge on every project that loaded this preset. Returns how many cleared. */
export async function clearPresetBadges(db: Db, userId: string, presetId: string): Promise<number> {
  let cleared = 0
  for (const p of await projectsBadgedWith(db, userId, presetId)) {
    const { count } = await db.project.updateMany({
      where: { id: p.id, updatedAt: p.updatedAt },
      data: { loadedPreset: Prisma.DbNull },
    })
    cleared += count
  }
  return cleared
}
