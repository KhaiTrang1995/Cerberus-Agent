/**
 * 360 Quake: `GET quake.360.net/api/v3/user/info` with `X-QuakeToken`
 * (catalogue A19). Free: Quake charges per returned asset and this returns
 * none. A bad token is the only HTTP error, a 401 whose body is the bare text
 * `/quake/login`; everything else is an HTTP 200 whose `code` is the number 0 on
 * success and a STRING (q3005, ...) on failure. The body echoes the token, the
 * email and the phone number: only credits, roles and the ban flag are read.
 */
import { firstOfNextMonth, isPlainObject, isoOrNull, num, str } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

/** Monthly credits are "overwritten on the 1st at 00:00", Beijing time assumed. */
const SHANGHAI = '+08:00'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://quake.360.net/api/v3/user/info', headers: { 'X-QuakeToken': key } }
}

/**
 * q3007 reads "用户 <name> 积分不足，当前积分：<n>": keep the balance, never the
 * name, which may be the phone number or email the account signed up with.
 */
function balanceIn(message: string): string {
  const m = message.match(/当前积分[：:]\s*(-?\d+)/)
  return m ? ` (balance ${m[1]})` : ''
}

function codeError(code: string, message: string, httpStatus: number): ProbeResult {
  const opts = { httpStatus, providerCode: code }
  switch (code) {
    case 'q3005':
      return errorResult('rate_limited', '360 Quake rate-limited the check (API called too often)', opts)
    case 'q3007':
      return errorResult('quota_exhausted', `not enough credits${balanceIn(message)}`, opts)
    case 'q3011':
    case 'q1001':
      return errorResult('forbidden', 'the account may not use this API (no permission, or not logged in)', opts)
    case 'q2001':
      return /积分不足/.test(message)
        ? errorResult('quota_exhausted', `not enough credits${balanceIn(message)}`, opts)
        : errorResult('forbidden', 'the account hit a 360 Quake limit', opts)
    default:
      return errorResult('unexpected_response', `360 Quake error ${code}`, opts)
  }
}

/** The earliest end of a time-limited role; a null entry is a permanent role. */
function roleExpiry(validity: unknown): string | undefined {
  if (!isPlainObject(validity)) return undefined
  return Object.values(validity)
    .filter(isPlainObject)
    .map(v => isoOrNull(v.end_time))
    .filter((v): v is string => v != null)
    .sort()[0]
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (res.status === 401 || res.text.trim() === '/quake/login') {
    return errorResult('invalid_key', '360 Quake rejected the token', { httpStatus: res.status })
  }
  const b = body(res)
  if (typeof b.code === 'string') return codeError(b.code, str(b.message) ?? '', res.status)
  if (res.status !== 200) return statusError(res)
  if (b.code !== 0) {
    return typeof b.code === 'number'
      ? errorResult('unexpected_response', `360 Quake error ${b.code}`, { httpStatus: res.status, providerCode: String(b.code) })
      : shapeError(res)
  }

  const d = isPlainObject(b.data) ? b.data : {}
  // `baned` is the API's own spelling.
  if (d.baned === true) {
    return errorResult('forbidden', `account banned (${str(d.ban_status) ?? 'no reason given'})`, { httpStatus: res.status })
  }
  // The field set varies between accounts; the newer `month_remaining_credit` wins over `credit`.
  const monthlyLeft = num(d.month_remaining_credit) ?? num(d.credit)
  const longTerm = num(d.constant_credit) ?? num(d.persistent_credit)
  if (monthlyLeft == null && longTerm == null) return shapeError(res)

  const roles = Array.isArray(d.role) ? d.role.filter(isPlainObject) : []
  const monthlyCap = Math.max(0, ...roles.map(r => num(r.credit) ?? 0)) || null
  const resetsAt = firstOfNextMonth(SHANGHAI, now)
  const meters: Meter[] = [
    meter({
      id: 'monthly', label: 'Monthly credits', unit: 'credits', window: 'month',
      remaining: monthlyLeft,
      limit: monthlyCap,
      used: monthlyCap != null && monthlyLeft != null ? Math.max(0, monthlyCap - monthlyLeft) : null,
      resetsAt, resetsAtSource: 'computed', primary: true,
    }),
    meter({ id: 'long_term', label: 'Long-term credits', unit: 'credits', window: 'balance', remaining: longTerm, primary: false }),
  ]
  const free = num(d.free_query_api_count) ?? num(d.f_query_api_count)
  if (free != null) {
    meters.push(meter({
      id: 'free_queries', label: 'Free API queries (month)', unit: 'queries', window: 'month',
      remaining: free, resetsAt, resetsAtSource: 'computed', primary: false,
    }))
  }
  const plan = roles.map(r => str(r.fullname)).filter(Boolean).join(', ') || undefined
  return usageResult(meters, { account: { plan, expiresAt: roleExpiry(d.role_validity) } })
}

export const quakeProbe: ProbeDef = {
  id: 'quake',
  service: 'quake',
  label: '360 Quake',
  group: 'uncover',
  field: 'quakeApiKey',
  rotationTool: 'quake',
  kind: 'usage',
  costNote: 'Free: Quake charges per returned asset, and user info returns none',
  docsUrl: 'https://quake.360.net/quake/#/help?id=5e77423bcb9954d2f8a01656',
  dashboardUrl: 'https://quake.360.net/quake/#/index',
  verifiedOn: null,
  endpoint: 'GET quake.360.net/api/v3/user/info',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
