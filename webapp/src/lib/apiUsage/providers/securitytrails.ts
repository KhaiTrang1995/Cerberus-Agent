/**
 * SecurityTrails: `GET api.securitytrails.com/v1/account/usage` with the
 * `APIKEY` header recon sends (catalogue A17). Whether this call itself counts
 * toward the monthly quota is undocumented. A bad key is a 401 in PLAIN TEXT
 * ("Please check user credentials", no Content-Type), not the JSON the docs
 * show. No plan name and no reset date come back: the reset is taken as the 1st
 * of the month, when SecurityTrails bills.
 */
import { clampRemaining, firstOfNextMonthUtc, num } from '../parse'
import { body, errorResult, messageOf, meter, shapeError, statusError, usageResult } from '../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

/** The Free plan's documented allowance; the response names no plan. */
const FREE_MONTHLY_QUERIES = 50

export function request(key: string): ProbeRequest {
  return {
    method: 'GET',
    url: 'https://api.securitytrails.com/v1/account/usage',
    headers: { APIKEY: key, Accept: 'application/json' },
  }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status === 429) {
    // The per-second throttle says "rate limit"; the monthly quota answers with other text.
    const msg = messageOf(res)
    return errorResult(/rate limit/i.test(msg) ? 'rate_limited' : 'quota_exhausted', msg || 'the monthly quota is used up', { httpStatus: 429 })
  }
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  const allowed = num(b.allowed_monthly_usage)
  if (allowed == null) return shapeError(res)
  const used = num(b.current_monthly_usage)
  return usageResult([meter({
    id: 'monthly_queries', label: 'API queries (month)', unit: 'queries', window: 'month',
    // A soft quota: `used` can pass `allowed`.
    used, limit: allowed, remaining: clampRemaining(allowed, used),
    resetsAt: firstOfNextMonthUtc(now), resetsAtSource: 'computed', primary: true,
  })], {
    account: { plan: allowed === FREE_MONTHLY_QUERIES ? 'Free (50/month)' : undefined },
  })
}

export const securitytrailsProbe: ProbeDef = {
  id: 'securitytrails',
  service: 'securitytrails',
  label: 'SecurityTrails',
  group: 'keys',
  field: 'securitytrailsApiKey',
  rotationTool: 'securitytrails',
  kind: 'usage',
  costNote: 'Cost undocumented: the check may count as 1 query of the monthly quota',
  docsUrl: 'https://docs.securitytrails.com/reference/usage-old-1',
  dashboardUrl: 'https://securitytrails.com/app/account/credentials',
  verifiedOn: null,
  endpoint: 'GET api.securitytrails.com/v1/account/usage',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
