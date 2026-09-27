/**
 * WPScan: `GET wpscan.com/api/v3/status` (catalogue A5). The status endpoint
 * checks "your API token validity and API usage, without affecting your daily
 * API limit". Errors carry `status`, not `error`.
 */
import { epochToIso, num, str } from '../parse'
import { body, isHtml, meter, shapeError, statusError, usageResult } from '../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(token: string): ProbeRequest {
  return { method: 'GET', url: 'https://wpscan.com/api/v3/status', headers: { Authorization: `Token token=${token}` } }
}

export function parse(res: ProbeResponse): ProbeResult {
  // Older backends answer an invalid or empty token with 403 {"status":"forbidden"}.
  if (res.status === 401 || res.status === 403) return statusError(res, 'invalid_key')
  if (res.status !== 200) return statusError(res)
  // The bot check is an HTML page served with 200.
  if (isHtml(res)) return shapeError(res, 'WPScan served a browser check page instead of the status')

  const b = body(res)
  const remaining = num(b.requests_remaining)
  if (remaining == null) return shapeError(res)
  const plan = str(b.plan)
  const account = { plan: plan === 'free' ? 'Researcher (free)' : plan }

  if (remaining === -1) {
    return usageResult([meter({
      id: 'daily', label: 'API requests (day)', unit: 'requests', window: 'day',
      primary: true, note: 'unlimited',
    })], { account })
  }
  const limit = num(b.requests_limit)
  const reset = epochToIso(b.requests_reset)
  return usageResult([meter({
    id: 'daily', label: 'API requests (day)', unit: 'requests', window: 'day',
    used: limit != null ? Math.max(0, limit - remaining) : null, limit, remaining,
    resetsAt: reset, primary: true,
  })], { account })
}

export const wpscanProbe: ProbeDef = {
  id: 'wpscan',
  service: 'wpscan',
  label: 'WPScan',
  group: 'keys',
  field: 'wpscanApiToken',
  rotationTool: 'wpscan',
  kind: 'usage',
  costNote: 'Free: the status endpoint does not use the daily API limit',
  docsUrl: 'https://wpscan.com/docs/api/v3/',
  dashboardUrl: 'https://wpscan.com/profile/',
  verifiedOn: null,
  endpoint: 'GET wpscan.com/api/v3/status',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
