/**
 * The settings rules that span fields, shared by every path that writes them.
 *
 * Per-field bounds live in the registry and `validateValue`. What they cannot
 * express is a rule over SEVERAL fields - fireteam's concurrency may not exceed
 * its team size - or one that needs the operator's own configuration - a
 * supply-chain repository may only be on github.com or a GitHub Enterprise host
 * the operator registered. Those ran only inside the project form's PUT, so an
 * MCP write skipped them: `fireteamPropensity` 9 passed the registry's 0-10
 * bound while the form's own schema allows 1-5.
 *
 * `nextRow` is whatever the caller is about to hold: the PUT passes its body,
 * exactly as it always validated; the MCP tools pass the stored row with their
 * change applied, so a rule over two fields sees both.
 */
import prisma from '@/lib/prisma'
import { allowedGithubHosts } from '@/lib/github/ownerTarget'
import { validateFireteamSettings } from '@/lib/validation/fireteamSettings'
import { validateSupplyChainInput } from '@/lib/validation/supplyChainInput'

export const FIRETEAM_FIELDS = [
  'fireteamEnabled', 'fireteamMaxConcurrent', 'fireteamMaxMembers',
  'fireteamMemberMaxIterations', 'fireteamTimeoutSec', 'fireteamAllowedPhases',
  'fireteamPropensity',
] as const

/** The supply-chain fields that become a `git clone` argument or an account to enumerate. */
export const SUPPLY_CHAIN_INPUT_FIELDS = [
  'supplyChainRepoUrl', 'supplyChainInputMode', 'supplyChainRepoRef', 'supplyChainOrgName',
] as const

function pick(row: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of keys) if (Object.prototype.hasOwnProperty.call(row, key)) out[key] = row[key]
  return out
}

/**
 * The first cross-field rule `nextRow` breaks, or null. A rule runs only when
 * a key it covers is in `touchedKeys`, so an unrelated write is never refused
 * over a value it did not change.
 *
 * `actorUserId` decides which GitHub Enterprise host is allowed: the allowlist
 * comes from that user's settings, never from the request.
 */
export async function validateCrossFieldRules(
  nextRow: Record<string, unknown>,
  touchedKeys: Iterable<string>,
  actorUserId: string,
): Promise<string | null> {
  const touched = new Set(touchedKeys)

  if (SUPPLY_CHAIN_INPUT_FIELDS.some(k => touched.has(k))) {
    const settings = await prisma.userSettings.findUnique({
      where: { userId: actorUserId }, select: { githubEnterpriseHost: true },
    }).catch(() => null)
    const problem = validateSupplyChainInput(
      pick(nextRow, SUPPLY_CHAIN_INPUT_FIELDS),
      allowedGithubHosts(settings?.githubEnterpriseHost),
    )
    if (problem) return problem
  }

  if (FIRETEAM_FIELDS.some(k => touched.has(k))) {
    const problem = validateFireteamSettings(pick(nextRow, FIRETEAM_FIELDS))
    if (problem) return problem
  }

  return null
}

/**
 * One `FireteamSettingsAudit` row per fireteam field `after` changes.
 * Best-effort: an audit failure must not roll back a write that already landed.
 */
export async function writeFireteamAudit(
  projectId: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  actor: { userId: string | null; source: string },
): Promise<void> {
  try {
    const rows = FIRETEAM_FIELDS
      .filter(field => field in after && JSON.stringify(before[field]) !== JSON.stringify(after[field]))
      .map(field => ({
        projectId,
        userId: actor.userId,
        field,
        oldValue: (before[field] ?? null) as never,
        newValue: (after[field] ?? null) as never,
        source: actor.source,
      }))
    if (rows.length > 0) await prisma.fireteamSettingsAudit.createMany({ data: rows })
  } catch (e) {
    console.warn('Fireteam settings audit write failed:', e)
  }
}
