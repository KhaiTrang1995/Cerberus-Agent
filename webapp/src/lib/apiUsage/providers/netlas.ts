/**
 * Netlas: two calls, in this order (catalogue A13). `/api/users/current/`
 * enforces auth, so it is the validity check and carries the plan.
 * `/api/users/profile_data/` holds the counters but is public in the OpenAPI
 * (`security: []`): it never rejects a bad key, so it is only asked once the
 * first call has proven the key. Neither is a search, and "requests left" only
 * moves on search methods. `X-API-Key` is the header recon's scans already send
 * successfully (the SDK sends `X-Api-Key`, the OpenAPI documents Bearer).
 */
import { isPlainObject, isoOrNull, num, str } from '../parse'
import { body, errorResult, isHtml, messageOf, meter, shapeError, statusError, usageResult, validResult } from '../results'
import type { AccountInfo, ErrorKind, Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const API = 'https://app.netlas.io/api/users'
/** Every Netlas counter uses -1 for "unlimited". */
const UNLIMITED = -1

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `${API}/current/`, headers: { 'X-API-Key': key } }
}

export function countersRequest(key: string): ProbeRequest {
  return { method: 'GET', url: `${API}/profile_data/`, headers: { 'X-API-Key': key } }
}

/** Call 1: an error, or `valid_no_usage` with the account the counters belong to. */
export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 400) {
    // A bad key is a 400 here, not a 401; any other 400 is a malformed request.
    const msg = messageOf(res)
    return /API key not found/i.test(msg)
      ? errorResult('invalid_key', msg, { httpStatus: 400 })
      : statusError(res, 'unexpected_response')
  }
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status !== 200) return statusError(res)

  const u = body(res)
  if (!isPlainObject(u.plan) && !('plan_active_until' in u) && !isPlainObject(u.api_key)) return shapeError(res)
  const plan = isPlainObject(u.plan) ? u.plan : {}
  // The profile also echoes the key (`api_key.customer_api_key`) and the email: never read.
  return validResult({
    account: {
      plan: str(plan.name),
      expiresAt: isoOrNull(u.plan_active_until ?? plan.active_until) ?? undefined,
    },
  })
}

function counterNumbers(cap: number | null, left: number | null) {
  return {
    limit: cap === UNLIMITED ? null : cap,
    remaining: left === UNLIMITED ? null : left,
    used: cap == null || left == null || cap === UNLIMITED || left === UNLIMITED ? null : Math.max(0, cap - left),
  }
}

/** Call 2, asked only after call 1 proved the key: a failure here is never read as a bad key. */
export function parseCounters(res: ProbeResponse, account: AccountInfo): ProbeResult {
  if (res.status !== 200) {
    const kind: ErrorKind = res.status === 429 ? 'rate_limited' : res.status >= 500 ? 'provider_error' : 'unexpected_response'
    const detail = isHtml(res) ? '' : messageOf(res)
    return errorResult(kind, `the key works, but Netlas did not return its counters${detail ? `: ${detail}` : ` (HTTP ${res.status})`}`, {
      httpStatus: res.status, account,
    })
  }
  const c = body(res)
  if (!isPlainObject(c.requests_left) || !isPlainObject(c.coins)) {
    return { ...shapeError(res, 'Netlas returned its counters in an unexpected format'), account }
  }

  const rl = c.requests_left
  const requestCap = num(rl.limit)
  const meters: Meter[] = [meter({
    id: 'requests', label: 'Requests', unit: 'requests',
    // The schema gives only a refresh date; paid quotas are daily.
    window: 'day',
    ...counterNumbers(requestCap, num(rl.remained)),
    resetsAt: isoOrNull(rl.will_be_updated),
    primary: requestCap !== UNLIMITED,
    note: requestCap === UNLIMITED ? 'unlimited' : undefined,
  })]

  const coins = c.coins
  const coinCap = num(coins.plan_coins_amount)
  meters.push(meter({
    id: 'coins', label: 'Netlas Coins', unit: 'coins', window: 'month',
    ...counterNumbers(coinCap, num(coins.left)),
    resetsAt: isoOrNull(coins.next_time_coins_will_be_updated),
    primary: true,
    note: coinCap === UNLIMITED ? 'unlimited' : undefined,
  }))

  const scan = isPlainObject(c.scan_coins) ? c.scan_coins : undefined
  const scanCap = scan ? num(scan.plan_scan_coins_amount) : null
  // A plan without scanner coins reports 0: nothing to show.
  if (scan && scanCap !== 0) {
    const { limit, remaining } = counterNumbers(scanCap, num(scan.left))
    meters.push(meter({
      id: 'scan_coins', label: 'Scan coins', unit: 'coins', window: 'month',
      limit, remaining, primary: false,
      note: scanCap === UNLIMITED ? 'unlimited' : undefined,
    }))
  }
  return usageResult(meters, { account })
}

export const netlasProbe: ProbeDef = {
  id: 'netlas',
  service: 'netlas',
  label: 'Netlas',
  group: 'keys',
  field: 'netlasApiKey',
  rotationTool: 'netlas',
  kind: 'usage',
  // Undocumented by Netlas; checked live 2026-09-27: repeated reads left every counter unchanged.
  costNote: 'Free: two account reads, neither of them a search (the counters do not move)',
  docsUrl: 'https://docs.netlas.io/',
  dashboardUrl: 'https://app.netlas.io/profile/',
  verifiedOn: '2026-09-27',
  endpoint: 'GET app.netlas.io/api/users/current/',
  run: async ctx => {
    const profile = parse(await ctx.http(request(ctx.key)))
    if (profile.outcome !== 'valid_no_usage') return profile
    return parseCounters(await ctx.http(countersRequest(ctx.key)), profile.account ?? {})
  },
}
