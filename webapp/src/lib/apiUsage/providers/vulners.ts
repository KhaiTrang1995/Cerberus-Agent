/**
 * Vulners (catalogue A8): validity only. There is no credits or plan endpoint
 * (the balance is dashboard-only, or a header of a CHARGED call), so the check
 * lists the account's subscriptions. The key goes in `X-Api-Key` only: since
 * 2025-10-02 a key in the query string is ignored and gets the same Cloudflare
 * challenge as no key at all. Errors are matched on `errorCode`, never on the
 * text, which differs between the API ("Unknown api key") and the SDK fixtures
 * ("Wrong API key"). Messages come from known fields only: v4 validation errors
 * echo their `input`.
 */
import { isPlainObject, num, str } from '../parse'
import { body, errorResult, isHtml, kindForStatus, meter, shapeError, validResult } from '../results'
import type { ErrorKind, Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const UNKNOWN_KEY = 157
const SCOPE_VIOLATION = 158

const FALLBACK: Partial<Record<ErrorKind, string>> = {
  forbidden: 'the key was accepted but may not call this endpoint',
  rate_limited: 'rate limited while checking; try again later',
  provider_error: 'Vulners returned a server error',
}

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://vulners.com/api/v4/subscriptions/list/', headers: { 'X-Api-Key': key } }
}

/** v3 `data.error`, or v4 `detail` (a string, an object or a list of them). */
function messageIn(b: Record<string, unknown>): string | undefined {
  if (isPlainObject(b.data)) return str(b.data.error)
  const detail = Array.isArray(b.detail) ? b.detail[0] : b.detail
  return isPlainObject(detail) ? str(detail.msg) : str(detail)
}

export function parse(res: ProbeResponse): ProbeResult {
  const b = body(res)
  const errorCode = isPlainObject(b.data) ? num(b.data.errorCode) : null
  const msg = messageIn(b)
  const opts = { httpStatus: res.status, providerCode: errorCode != null ? String(errorCode) : undefined }

  // v3-dispatched routes (subscriptions/list among them) can report these on an HTTP 200.
  if (errorCode === UNKNOWN_KEY) return errorResult('invalid_key', msg ?? 'Vulners does not know this key', opts)
  if (errorCode === SCOPE_VIOLATION) return errorResult('forbidden', 'the key lacks the api scope', opts)
  if (res.headers['cf-mitigated'] === 'challenge') {
    return errorResult('invalid_key', 'Vulners did not receive the key (Cloudflare challenge)', opts)
  }
  if (res.status === 401) return errorResult('invalid_key', msg ?? 'Vulners rejected the key', opts)
  if (res.status === 402) return errorResult('quota_exhausted', msg ?? 'the Vulners wallet is empty', opts)
  if (res.status !== 200) {
    const kind = kindForStatus(res.status)
    const fallback = isHtml(res) ? 'Vulners returned an HTML page' : FALLBACK[kind] ?? `Vulners answered HTTP ${res.status}`
    return errorResult(kind, msg ?? fallback, opts)
  }
  if (b.result === 'error') return errorResult('unexpected_response', msg ?? 'Vulners reported an error', opts)
  if (!Array.isArray(b.result) && b.result !== 'OK') return shapeError(res)

  const meters: Meter[] = []
  // A float string, requests per minute.
  const perMinute = num(res.headers['x-vulners-ratelimit-reqlimit'])
  if (perMinute != null) {
    meters.push(meter({ id: 'rate', label: 'Request rate limit (minute)', unit: 'requests', window: 'minute', limit: perMinute, primary: false }))
  }
  return validResult({ meters, notes: ['Monthly credits: Free 100 · Basic 600 · Pro 3,000 (dashboard only)'] })
}

export const vulnersProbe: ProbeDef = {
  id: 'vulners',
  service: 'vulners',
  label: 'Vulners',
  group: 'keys',
  field: 'vulnersApiKey',
  rotationTool: 'vulners',
  kind: 'validity',
  costNote: 'Cost undocumented: an account-level listing, not a vulnerability lookup',
  docsUrl: 'https://docs.vulners.com/',
  dashboardUrl: 'https://vulners.com/userinfo',
  verifiedOn: null,
  endpoint: 'GET vulners.com/api/v4/subscriptions/list/',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
