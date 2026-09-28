/**
 * SerpAPI: `GET serpapi.com/account.json?api_key=` (catalogue A4). "Account API
 * is free of charge, and using it will not be counted toward your monthly
 * quota." The body echoes the key and the account email: neither is read.
 */
import { clampRemaining, isoOrNull, num, str } from '../parse'
import { body, errorResult, messageOf, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `https://serpapi.com/account.json?api_key=${encodeURIComponent(key)}` }
}

function byMessage(res: ProbeResponse): ProbeResult {
  const msg = messageOf(res)
  if (/run out of searches/i.test(msg)) return errorResult('quota_exhausted', msg, { httpStatus: res.status })
  if (/invalid api key/i.test(msg)) return errorResult('invalid_key', msg, { httpStatus: res.status })
  if (res.status === 200) return errorResult('unexpected_response', msg, { httpStatus: res.status })
  return statusError(res)
}

export function parse(res: ProbeResponse): ProbeResult {
  const b = body(res)
  if (typeof b.error === 'string' && b.error) return byMessage(res)
  if (res.status !== 200) return statusError(res)
  if (num(b.searches_per_month) == null && num(b.plan_searches_left) == null) return shapeError(res)

  // Searches reset at the start of the BILLING cycle, not the calendar month:
  // use the provider's own date. The roadmap renamed it plan_next_renewal_date.
  const renew = str(b.plan_renewal_date) ?? str(b.plan_next_renewal_date)
  const meters: Meter[] = [meter({
    id: 'monthly', label: 'Searches this cycle', unit: 'searches', window: 'month',
    used: num(b.this_month_usage), limit: num(b.searches_per_month), remaining: num(b.plan_searches_left),
    resetsAt: renew ? isoOrNull(renew) : null, primary: true,
  })]
  const extra = num(b.extra_credits)
  if (extra != null && extra > 0) {
    meters.push(meter({ id: 'extra', label: 'Extra credits', unit: 'searches', window: 'balance', remaining: extra, primary: false }))
  }
  const hourly = num(b.account_rate_limit_per_hour)
  if (hourly != null) {
    const thisHour = num(b.this_hour_searches)
    meters.push(meter({
      id: 'hourly', label: 'Searches this hour', unit: 'searches', window: 'hour',
      used: thisHour, limit: hourly, remaining: clampRemaining(hourly, thisHour), primary: false,
    }))
  }

  const notes: string[] = []
  const status = str(b.account_status)
  if (status && status !== 'Active') notes.push(`Account status: ${status}`)
  // total_searches_left = plan_searches_left + extra_credits: plan searches can
  // be 0 while extra credits still carry the account.
  const planLeft = num(b.plan_searches_left)
  const totalLeft = num(b.total_searches_left) ?? (planLeft != null && extra != null ? planLeft + extra : null)
  const onExtra = planLeft != null && planLeft <= 0 && totalLeft != null && totalLeft > 0
  if (onExtra) notes.push(`Plan searches are used up; searches now spend the ${totalLeft} extra credits`)
  return usageResult(meters, {
    account: { plan: str(b.plan_name) ?? str(b.plan_id) },
    notes: notes.length ? notes : undefined,
    healthOverride: totalLeft != null && totalLeft <= 0 ? 'exhausted' : onExtra ? 'low' : undefined,
  })
}

export const serpapiProbe: ProbeDef = {
  id: 'serpapi',
  service: 'serpapi',
  label: 'SerpAPI',
  group: 'keys',
  field: 'serpApiKey',
  rotationTool: 'serp',
  kind: 'usage',
  costNote: 'Free: the Account API is not counted toward the monthly quota',
  docsUrl: 'https://serpapi.com/account-api',
  dashboardUrl: 'https://serpapi.com/dashboard',
  verifiedOn: null,
  endpoint: 'GET serpapi.com/account.json',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
