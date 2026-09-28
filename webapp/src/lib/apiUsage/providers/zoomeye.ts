/**
 * ZoomEye: `POST api.zoomeye.ai/v2/userinfo` (catalogue A15), sent exactly like
 * the official curl: `API-KEY` header, no body, no Content-Type (a GET is a
 * 405). `api.zoomeye.ai` is the international host recon uses; `.org` serves
 * mainland China only. `code` 60000 is the only success, even on HTTP 200, and
 * JSON may arrive as application/octet-stream: the sniffed body decides, never
 * the Content-Type. The body carries the email and phone: only the username
 * and the subscription are read.
 */
import { firstOfNextMonth, isPlainObject, isoOrNull, num, str } from '../parse'
import { body, errorResult, isHtml, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const SUCCESS = 60000

/** Monthly Basic-points allotment per plan: ZoomEye's plan table, not in the response. */
const MONTHLY_POINTS = new Map([
  ['free', 3_000],
  ['personal', 100_000],
  ['professional', 800_000],
  ['business', 10_000_000],
  ['corporate', 50_000_000],
])

/** A username for `account.label`; an email-shaped value is dropped. */
function handle(v: unknown): string | undefined {
  const s = str(v)
  return s && !s.includes('@') ? s : undefined
}

export function request(key: string): ProbeRequest {
  return { method: 'POST', url: 'https://api.zoomeye.ai/v2/userinfo', headers: { 'API-KEY': key } }
}

function failure(res: ProbeResponse): ProbeResult {
  const b = body(res)
  const err = str(b.error)
  const msg = str(b.message)
  const code = num(b.code)
  const opts = { httpStatus: res.status, providerCode: err ?? (code != null ? String(code) : undefined) }

  if (res.json === undefined && res.headers['x-via-jsl'] !== undefined) {
    return errorResult('provider_error', "ZoomEye's firewall (Jiasule) answered instead of the API", opts)
  }
  if (res.json === undefined && isHtml(res)) return statusError(res, 'provider_error')
  // Missing and invalid keys get the same 401 "login required, missing Authorization header".
  if (res.status === 401 || err === 'login_required') return errorResult('invalid_key', 'ZoomEye rejected the key', opts)
  if (res.status === 402 || err === 'credits_insufficient') {
    return errorResult('quota_exhausted', msg ?? 'ZoomEye reports the points are used up', opts)
  }
  if (res.status === 429 || err === 'rate_limit') return errorResult('rate_limited', msg ?? 'ZoomEye rate-limited the check', opts)
  // The regional host answers 403 "this service not aviliable in your area" (sic).
  if (msg && /not av\w*able in your area/i.test(msg)) {
    return errorResult('provider_error', 'ZoomEye refused this host for the region (use api.zoomeye.ai)', opts)
  }
  if (res.status === 403 || err === 'forbidden' || err === 'suspended') {
    return errorResult('forbidden', err === 'suspended' ? 'the ZoomEye account is suspended' : msg ?? 'the ZoomEye plan may not call this endpoint', opts)
  }
  if (res.status >= 500) return statusError(res)
  return errorResult('unexpected_response', msg ? `ZoomEye error: ${msg}` : 'ZoomEye answered without its success code', opts)
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  const b = body(res)
  if (num(b.code) !== SUCCESS) return failure(res)
  const d = isPlainObject(b.data) ? b.data : undefined
  if (!d) return shapeError(res)
  const s = isPlainObject(d.subscription) ? d.subscription : {}
  // Both balances arrive as strings or ints depending on the account.
  const points = num(s.points)
  const topUp = num(s.zoomeye_points)
  if (points == null && topUp == null) return shapeError(res, 'ZoomEye returned no point balances')

  const plan = str(s.plan)
  const cap = plan ? MONTHLY_POINTS.get(plan.toLowerCase()) ?? null : null
  const meters: Meter[] = [meter({
    id: 'points', label: 'Basic points (month)', unit: 'points', window: 'month',
    remaining: points,
    limit: cap,
    used: cap != null && points != null ? Math.max(0, cap - points) : null,
    // "Reset on the 1st of each month", zone unstated: ZoomEye's own UTC+8 assumed.
    resetsAt: firstOfNextMonth('+08:00', now), resetsAtSource: 'computed',
    primary: true,
    note: cap != null ? 'allotment from the plan table' : undefined,
  })]
  if (topUp != null) {
    meters.push(meter({
      id: 'zoomeye_points', label: 'ZoomEye-Points', unit: 'points', window: 'balance',
      remaining: topUp, primary: false, note: 'expire 12 months after purchase',
    }))
  }
  // ZoomEye-Points are spent once the Basic Points are gone.
  const onTopUp = points != null && points <= 0 && topUp != null && topUp > 0
  return usageResult(meters, {
    account: {
      plan: plan ?? 'Free',
      label: handle(d.username),
      // "" means no subscription.
      expiresAt: isoOrNull(s.end_date) ?? undefined,
    },
    ...(onTopUp ? { notes: ['Basic points are used up; queries now spend ZoomEye-Points'], healthOverride: 'low' as const } : {}),
  })
}

export const zoomeyeProbe: ProbeDef = {
  id: 'zoomeye',
  service: 'zoomeye',
  label: 'ZoomEye',
  group: 'keys',
  field: 'zoomEyeApiKey',
  rotationTool: 'zoomeye',
  kind: 'usage',
  // Undocumented by ZoomEye; checked live 2026-09-27: repeated reads left the points unchanged.
  costNote: 'Free: reading the account does not spend points',
  docsUrl: 'https://www.zoomeye.ai/static/public/apiv2_doc_en.md',
  dashboardUrl: 'https://www.zoomeye.ai/profile',
  verifiedOn: '2026-09-27',
  endpoint: 'POST api.zoomeye.ai/v2/userinfo',
  // The Free plan allows 0.5 requests/second.
  minIntervalMs: 2100,
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
