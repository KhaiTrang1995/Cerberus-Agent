/**
 * Bring every stored Priority Board review budget inside 0..1000.
 *
 * Every writer now refuses a budget above 1000, but MCP and the settings API
 * once accepted up to 10000, and existing rows are never migrated by an update.
 * A run already clamps to 1000 when it reads the value, so a larger stored
 * number changed nothing at run time; it did leave the project form showing a
 * value its own input `max` rejects, which blocks saving ANY setting on that
 * project until someone finds the field.
 *
 * Runs from the webapp entrypoint AFTER `db push` (the column must exist), on
 * install and on every update. Idempotent: rows already in range are not
 * touched, so every boot after the first updates nothing. Never fatal: if it
 * fails, the run-time clamp still holds and the webapp still boots.
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

// MAX_REVIEW_BUDGET in src/lib/triage/limits.ts and the triageReviewBudget
// bound in recon_settings/registry.yaml; a test holds all three equal.
export const MAX_REVIEW_BUDGET = 1000

/** Clamp out-of-range budgets; returns how many projects it changed. */
export async function clampTriageReviewBudgets(prisma) {
  return prisma.$executeRawUnsafe(`
    UPDATE projects
       SET triage_review_budget = LEAST(GREATEST(triage_review_budget, 0), ${MAX_REVIEW_BUDGET})
     WHERE triage_review_budget < 0 OR triage_review_budget > ${MAX_REVIEW_BUDGET}
  `)
}

async function main() {
  const prisma = new PrismaClient()
  try {
    const changed = await clampTriageReviewBudgets(prisma)
    if (changed > 0) {
      console.log(`[triage] ${changed} project review budget(s) brought into 0..${MAX_REVIEW_BUDGET}.`)
    }
  } catch (err) {
    console.error('[triage] could not normalise review budgets:', err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}
