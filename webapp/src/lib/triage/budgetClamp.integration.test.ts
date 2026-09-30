/** @vitest-environment node */
/**
 * L4, real Postgres: the boot-time review budget clamp does what the SQL says,
 * and a second boot changes nothing.
 *
 * Everything runs inside one transaction that is always rolled back, so the
 * test never alters a real project, even one whose budget is out of range: the
 * entrypoint is what fixes those.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://redamon:<pw>@postgres:5432/redamon' \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/triage/budgetClamp.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { clampTriageReviewBudgets } from '../../../scripts/clamp-triage-review-budget.mjs'

const HAS_DB = process.env.DATABASE_URL !== undefined
const ROLLBACK = new Error('rollback')

let prisma: PrismaClient

beforeAll(() => {
  if (HAS_DB) prisma = new PrismaClient()
})

afterAll(async () => {
  if (prisma) await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('clampTriageReviewBudgets', () => {
  test('brings out-of-range budgets into 0..1000, leaves the rest, and is a no-op the second time', async () => {
    const seen: Record<string, number | undefined> = {}
    let secondRun = -1
    await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { email: `budget-clamp-${Date.now()}@example.invalid`, name: 'budget clamp', password: 'x' },
      })
      const make = (name: string, triageReviewBudget: number) =>
        tx.project.create({ data: { name, userId: user.id, targetDomain: 'example.invalid', triageReviewBudget } })
      const rows = {
        over: await make('budget over', 5000),
        under: await make('budget under', -5),
        inRange: await make('budget in range', 150),
        atMax: await make('budget at max', 1000),
      }

      const first = await clampTriageReviewBudgets(tx)
      expect(first).toBeGreaterThanOrEqual(2)
      for (const [key, row] of Object.entries(rows)) {
        seen[key] = (await tx.project.findUnique({ where: { id: row.id } }))?.triageReviewBudget
      }
      secondRun = await clampTriageReviewBudgets(tx)
      throw ROLLBACK
    }).catch((err) => {
      if (err !== ROLLBACK) throw err
    })

    expect(seen).toEqual({ over: 1000, under: 0, inRange: 150, atMax: 1000 })
    expect(secondRun).toBe(0)
  }, 60_000)
})
