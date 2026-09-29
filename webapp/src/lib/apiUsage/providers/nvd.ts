/**
 * NIST NVD (catalogue A7): validity only; NVD has no usage endpoint and sends
 * no rate-limit headers. The check is the smallest real query (one CVE), which
 * uses 1 of the 50 requests a key gets per rolling 30 s. Client errors are a
 * 404 with an EMPTY body and the reason in the `message` response header
 * ("Invalid apiKey."), so the header is read, never the body. A keyless request
 * succeeds, so a blank key is never sent: it would prove nothing (and an empty
 * `apiKey` header is itself rejected as invalid).
 */
import { str } from '../parse'
import { body, errorResult, shapeError, statusError, validResult } from '../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const CVES_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: CVES_URL, headers: key.trim() ? { apiKey: key } : {} }
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 404) {
    const reason = str(res.headers.message)
    // An invalid, unactivated or superseded key (a new key for the same email voids the old one).
    if (reason && /invalid apikey/i.test(reason)) return errorResult('invalid_key', reason, { httpStatus: 404 })
    return errorResult('unexpected_response', reason ?? 'NVD answered 404 without a reason', { httpStatus: 404 })
  }
  // NVD throttles with a 403, often a Cloudflare page.
  if (res.status === 403) return statusError(res, 'rate_limited')
  if (res.status !== 200) return statusError(res)
  if (body(res).format !== 'NVD_CVE') return shapeError(res)
  return validResult({ notes: ['Limit: 50 requests per rolling 30 s with a key (documented; NVD does not report usage)'] })
}

export const nvdProbe: ProbeDef = {
  id: 'nvd',
  service: 'nvd',
  label: 'NVD',
  group: 'keys',
  field: 'nvdApiKey',
  rotationTool: 'nvd',
  kind: 'validity',
  costNote: 'Uses 1 of the 50 requests a key gets per rolling 30 s',
  docsUrl: 'https://nvd.nist.gov/developers/vulnerabilities',
  dashboardUrl: 'https://nvd.nist.gov/developers/request-an-api-key',
  verifiedOn: null,
  endpoint: 'GET services.nvd.nist.gov/rest/json/cves/2.0',
  run: async ctx => {
    if (!ctx.key.trim()) return errorResult('invalid_key', 'the saved NVD key is blank')
    return parse(await ctx.http(request(ctx.key)))
  },
}
