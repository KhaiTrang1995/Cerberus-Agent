/**
 * Censys Platform credits (catalogue A10). Both endpoints are documented "This
 * endpoint does not cost any credits to execute":
 *   - Organization ID saved (Starter / Enterprise): the organization's balance.
 *   - No Organization ID (Free): the user's monthly balance.
 * A Starter/Enterprise user without the org ID saved hits the Free endpoint and
 * gets a 404 or a misleading balance, so the row says to set it.
 */
import { isPlainObject, isoOrNull, num } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const API = 'https://api.platform.censys.io/v3/accounts'
/** "Free = 100 credits per month" (docs), not in the response. */
const FREE_MONTHLY_CREDITS = 100

export function request(token: string, orgId: string): ProbeRequest {
  const url = orgId ? `${API}/organizations/${encodeURIComponent(orgId)}/credits` : `${API}/users/credits`
  return { method: 'GET', url, headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
}

export function parse(res: ProbeResponse, orgMode: boolean): ProbeResult {
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status === 403) {
    return errorResult('forbidden', orgMode
      ? "your Censys role cannot read the organization's credits"
      : 'Censys refused the credit lookup for this token', { httpStatus: 403 })
  }
  if (res.status === 404 || res.status === 422) {
    return errorResult('invalid_key', orgMode
      ? 'the Censys Organization ID is wrong (or this token is not a member of it)'
      : "Censys found no Free account for this token. A Starter or Enterprise account needs its Organization ID saved to read the organization's credits",
    { httpStatus: res.status })
  }
  if (res.status !== 200) return statusError(res)

  const r = body(res).result
  if (!isPlainObject(r) || num(r.balance) == null) return shapeError(res)
  const balance = num(r.balance)!

  if (orgMode) {
    const lots = (Array.isArray(r.credit_expirations) ? r.credit_expirations : [])
      .filter(isPlainObject)
      .map(l => ({ balance: num(l.balance), expiresAt: isoOrNull(l.expires_at) }))
      .filter(l => l.expiresAt)
      .sort((a, z) => a.expiresAt!.localeCompare(z.expiresAt!))
    const soonest = lots[0]
    const auto = isPlainObject(r.auto_replenish_config) ? r.auto_replenish_config : undefined
    return usageResult([meter({
      id: 'balance', label: 'Credits', unit: 'credits', window: 'balance',
      remaining: balance, primary: true,
      note: soonest ? `${soonest.balance ?? '?'} expire on ${soonest.expiresAt!.slice(0, 10)}` : undefined,
    })], {
      account: {
        plan: 'Starter / Enterprise (organization)',
        label: auto?.enabled === true && num(auto.threshold) != null ? `auto top-up below ${num(auto.threshold)}` : undefined,
      },
    })
  }

  // A Free user who bought credits becomes Starter: a balance above the Free
  // allowance cannot be read against it.
  const withinFree = balance <= FREE_MONTHLY_CREDITS
  const resets = isoOrNull(r.resets_at)
  return usageResult([meter({
    id: 'balance', label: 'Credits (month)', unit: 'credits', window: 'month',
    used: withinFree ? Math.max(0, FREE_MONTHLY_CREDITS - balance) : null,
    limit: withinFree ? FREE_MONTHLY_CREDITS : null,
    remaining: balance,
    resetsAt: resets, primary: true,
    note: withinFree ? 'Free plan: 100 credits/month (allowance from the Censys docs)' : undefined,
  })], {
    account: { plan: 'Free' },
    notes: withinFree ? undefined : ['Balance above the Free allowance: save the Censys Organization ID to read the organization\'s credits'],
  })
}

export const censysProbe: ProbeDef = {
  id: 'censys',
  service: 'censys',
  label: 'Censys',
  group: 'keys',
  field: 'censysApiToken',
  companions: [{ field: 'censysOrgId', required: false }],
  kind: 'usage',
  costNote: 'Free: Censys documents the credit endpoints as costing no credits',
  docsUrl: 'https://docs.censys.com/reference/v3-accountmanagement-org-credits',
  dashboardUrl: 'https://platform.censys.io/',
  verifiedOn: '2026-09-27',
  endpoint: 'GET api.platform.censys.io/v3/accounts/…/credits',
  run: async (ctx: ProbeContext) => {
    const orgId = (ctx.companions.censysOrgId ?? '').trim()
    return parse(await ctx.http(request(ctx.key, orgId)), !!orgId)
  },
}
