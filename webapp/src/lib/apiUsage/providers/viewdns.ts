/**
 * ViewDNS: `GET api.viewdns.info/account/?action=balance` (catalogue A18). The
 * key rides in the query string, the only way ViewDNS takes it (recon does the
 * same), so the URL is never logged. A bad key is an HTTP 200 with
 * `response.error`; the newer tool endpoints answer `{success:false,
 * error:{code}}` instead. Every number is a string. Whether a balance check
 * uses a query, and when the monthly count resets, are both undocumented.
 */
import { isPlainObject, num, str } from '../parse'
import { errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `https://api.viewdns.info/account/?action=balance&apikey=${encodeURIComponent(key)}&output=json` }
}

function envelopeError(e: Record<string, unknown>, httpStatus: number): ProbeResult {
  const code = num(e.code)
  const msg = str(e.message) ?? 'ViewDNS reported an error'
  const opts = { httpStatus, providerCode: code != null ? String(code) : undefined }
  if (code === 401) return errorResult('invalid_key', msg, opts)
  if (code === 403) return errorResult('forbidden', msg, opts)
  // "reached its monthly query limit and/or you have no prepaid queries remaining"
  if (code === 429) return errorResult('quota_exhausted', msg, opts)
  if (code != null && code >= 500) return errorResult('provider_error', msg, opts)
  return errorResult('unexpected_response', msg, opts)
}

export function parse(res: ProbeResponse): ProbeResult {
  const b = isPlainObject(res.json) ? res.json : undefined
  if (!b) {
    // The legacy limit answer is bare text.
    if (/Query limit reached/i.test(res.text)) {
      return errorResult('quota_exhausted', 'Query limit reached for the supplied API key', { httpStatus: res.status })
    }
    // A Cloudflare page on a 403 is a challenge, not the key.
    return res.status >= 500 ? statusError(res) : shapeError(res)
  }
  if (b.success === false) return envelopeError(isPlainObject(b.error) ? b.error : {}, res.status)

  const r = isPlainObject(b.response) ? b.response : {}
  if (typeof r.error === 'string') {
    const opts = { httpStatus: res.status }
    if (/Invalid API Key/i.test(r.error)) return errorResult('invalid_key', r.error, opts)
    if (/Query limit reached/i.test(r.error)) return errorResult('quota_exhausted', r.error, opts)
    return errorResult('unexpected_response', r.error, opts)
  }
  if (res.status !== 200) return statusError(res)

  const monthly = isPlainObject(r.monthly) ? r.monthly : {}
  const limit = num(monthly.limit)
  const used = num(monthly.usage)
  const prepaid = num(isPlainObject(r.prepaid) ? r.prepaid.balance : undefined)
  const subscribed = limit != null && limit > 0
  const meters: Meter[] = []
  if (limit != null) {
    meters.push(meter({
      id: 'monthly', label: 'Queries (month)', unit: 'queries', window: 'month',
      used, limit, remaining: Math.max(0, limit - (used ?? 0)), primary: subscribed,
    }))
  }
  if (prepaid != null) {
    meters.push(meter({ id: 'prepaid', label: 'Prepaid queries', unit: 'queries', window: 'balance', remaining: prepaid, primary: !subscribed }))
  }
  if (meters.length === 0) return shapeError(res)

  const plan = subscribed ? `Subscription ${limit}/mo` : prepaid != null && prepaid > 0 ? 'Prepaid / trial' : 'No credits'
  return usageResult(meters, { account: { plan } })
}

export const viewdnsProbe: ProbeDef = {
  id: 'viewdns',
  service: 'viewdns',
  label: 'ViewDNS',
  group: 'keys',
  field: 'viewdnsApiKey',
  rotationTool: 'viewdns',
  kind: 'usage',
  costNote: 'Cost undocumented: ViewDNS does not say whether a balance check uses a query',
  docsUrl: 'https://viewdns.info/api/account/',
  dashboardUrl: 'https://viewdns.info/api/',
  verifiedOn: null,
  endpoint: 'GET api.viewdns.info/account/',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
