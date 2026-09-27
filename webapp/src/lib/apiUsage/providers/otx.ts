/**
 * AlienVault OTX (catalogue A12): validity only. `/api/v1/users/me` is the one
 * endpoint that proves a key: every public endpoint accepts a bad key with a
 * 200 (as "Anonymous"). A missing, empty or bad key is a 403 "Authentication
 * required"; the message stays neutral because some clients read an OTX 403 as
 * a monthly usage cap. One keyless request hung for over 30 s, which the
 * per-call timeout covers.
 */
import { str } from '../parse'
import { body, errorResult, isHtml, shapeError, statusError, validResult } from '../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://otx.alienvault.com/api/v1/users/me', headers: { 'X-OTX-API-KEY': key } }
}

export function parse(res: ProbeResponse): ProbeResult {
  // A CloudFront error page is the edge, not the key.
  if (res.status !== 200 && isHtml(res)) return errorResult('provider_error', 'OTX returned an error page', { httpStatus: res.status })
  if (res.status === 401 || res.status === 403) return errorResult('invalid_key', 'OTX rejected the key', { httpStatus: res.status })
  if (res.status !== 200) return statusError(res)

  const username = str(body(res).username)
  if (!username) return shapeError(res)
  // `member_since` is humanized ("1343 days ago "), not a date: never read.
  return validResult({
    account: { label: username.includes('@') ? undefined : username },
    notes: ['OTX has no quota API; ~10,000 requests/hour with a key'],
  })
}

export const otxProbe: ProbeDef = {
  id: 'otx',
  service: 'otx',
  label: 'AlienVault OTX',
  group: 'keys',
  field: 'otxApiKey',
  rotationTool: 'otx',
  kind: 'validity',
  costNote: 'Cost undocumented: OTX documents it as the call to validate a key',
  docsUrl: 'https://otx.alienvault.com/assets/static/external_api.html',
  dashboardUrl: 'https://otx.alienvault.com/settings',
  verifiedOn: '2026-09-27',
  endpoint: 'GET otx.alienvault.com/api/v1/users/me',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
