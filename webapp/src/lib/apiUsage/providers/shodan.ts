/**
 * Shodan: `GET api.shodan.io/api-info?key=` (catalogue A3). Reading the plan
 * spends no credits (the official CLI validates keys with it), but EVERY Shodan
 * method is limited to 1 request/second, so pool keys run 1.1 s apart.
 */
import { firstOfNextMonthUtc, isPlainObject, num, str } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

// No official code->name map exists; these are the codes Shodan's own pages use.
const PLAN_NAMES: Record<string, string> = {
  oss: 'Free (oss)',
  dev: 'Membership (dev)',
  edu: 'Academic (edu)',
}

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `https://api.shodan.io/api-info?key=${encodeURIComponent(key)}` }
}

function byMessage(message: string, status: number): ProbeResult {
  if (/rate limit|slow down/i.test(message)) return errorResult('rate_limited', message, { httpStatus: status })
  if (/invalid api key|access denied|unauthori/i.test(message)) return errorResult('invalid_key', message, { httpStatus: status })
  return errorResult('unexpected_response', message, { httpStatus: status })
}

/**
 * `remaining` + the plan cap -> a meter's numbers. A cap of -1 (or no
 * `usage_limits`, as before 2021) means no fixed limit: remaining only.
 */
function credit(remaining: number | null, cap: number | null) {
  if (cap != null && cap >= 0) {
    return { limit: cap, remaining, used: remaining == null ? null : Math.max(0, cap - remaining) }
  }
  return { limit: null, remaining, used: null }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  const b = body(res)
  // The SDK checks `error` on a 200 too.
  if (typeof b.error === 'string' && b.error) return byMessage(b.error, res.status)
  // A missing or bad key gets an nginx HTML 401, never JSON.
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status !== 200) return statusError(res)
  if (typeof b.plan !== 'string' && num(b.query_credits) == null) return shapeError(res)

  const limits = isPlainObject(b.usage_limits) ? b.usage_limits : {}
  const plan = str(b.plan)
  // The free plan is legitimately 0/0: "not in plan", not exhausted.
  const noCreditsPlan = plan === 'oss' && !isPlainObject(b.usage_limits)
  const resetsAt = firstOfNextMonthUtc(now)

  const meters: Meter[] = []
  const query = credit(num(b.query_credits) ?? num(b.unlocked_left), num(limits.query_credits))
  meters.push(meter({
    id: 'query_credits', label: 'Query credits', unit: 'credits', window: 'month',
    ...query,
    ...(noCreditsPlan && !query.remaining ? { limit: 0, used: 0, note: 'no credits included in this plan' } : {}),
    resetsAt, resetsAtSource: 'computed', primary: true,
  }))
  const scan = credit(num(b.scan_credits), num(limits.scan_credits))
  meters.push(meter({
    id: 'scan_credits', label: 'Scan credits', unit: 'credits', window: 'month',
    ...scan,
    ...(noCreditsPlan && !scan.remaining ? { limit: 0, used: 0, note: 'no credits included in this plan' } : {}),
    resetsAt, resetsAtSource: 'computed', primary: false,
  }))
  const monitored = num(b.monitored_ips)
  if (monitored != null) {
    const cap = num(limits.monitored_ips)
    meters.push(meter({
      id: 'monitored_ips', label: 'Monitored IPs', unit: 'count', window: 'lifetime',
      used: monitored,
      limit: cap != null && cap >= 0 ? cap : null,
      remaining: cap != null && cap >= 0 ? Math.max(0, cap - monitored) : null,
      primary: false,
    }))
  }
  return usageResult(meters, { account: { plan: plan ? PLAN_NAMES[plan] ?? plan : undefined } })
}

export const shodanProbe: ProbeDef = {
  id: 'shodan',
  service: 'shodan',
  label: 'Shodan',
  group: 'keys',
  field: 'shodanApiKey',
  rotationTool: 'shodan',
  kind: 'usage',
  costNote: 'Free: reading the plan spends no query or scan credits',
  docsUrl: 'https://developer.shodan.io/api',
  dashboardUrl: 'https://account.shodan.io/',
  verifiedOn: '2026-09-27',
  endpoint: 'GET api.shodan.io/api-info',
  minIntervalMs: 1100,
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
