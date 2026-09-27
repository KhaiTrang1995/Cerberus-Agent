/**
 * urlscan.io: `GET urlscan.io/api/v1/quotas` with the `API-Key` header
 * (catalogue A9). The docs insist on that exact header name. Without a usable
 * key urlscan does NOT fail: it silently answers with the anonymous
 * `scope: "ip-address"` quotas, which must never be reported as the key's.
 */
import { isPlainObject, num, nextUtcBoundary, isoOrNull, humanize, str } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const ACTION_LABELS: Record<string, string> = {
  search: 'Search',
  retrieve: 'Result retrieval',
  public: 'Public scans',
  unlisted: 'Unlisted scans',
  private: 'Private scans',
  'files.public': 'Public file downloads',
  'files.unlisted': 'Unlisted file downloads',
  'files.private': 'Private file downloads',
  livescan: 'Live scans',
  malicious: 'Malicious verdicts',
  liveshot: 'Liveshots',
}
const PRIMARY_ACTIONS = new Set(['search', 'public', 'private'])
const WINDOWS = ['minute', 'hour', 'day'] as const

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://urlscan.io/api/v1/quotas', headers: { 'API-Key': key } }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  // 400 "Invalid API key format", 401 "API key supplied but not found in database!"
  if (res.status === 400 || res.status === 401) return statusError(res, 'invalid_key')
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  const scope = str(b.scope)
  if (scope === 'ip-address') {
    return errorResult('unexpected_response', 'urlscan answered with anonymous quotas: the key was not applied', { httpStatus: 200 })
  }
  if (!isPlainObject(b.limits)) return shapeError(res)

  const meters: Meter[] = []
  for (const [action, v] of Object.entries(b.limits)) {
    // Sibling entries (maxSearchResults, products, queryableFields, ...) are numbers or arrays.
    if (!isPlainObject(v)) continue
    for (const w of WINDOWS) {
      const p = v[w]
      if (!isPlainObject(p)) continue
      const limit = num(p.limit)
      if (limit == null) continue
      const reset = isoOrNull(p.reset)
      meters.push(meter({
        id: `${action}.${w}`,
        label: `${ACTION_LABELS[action] ?? humanize(action)} (${w})`,
        unit: 'requests',
        window: w,
        used: num(p.used),
        limit,
        remaining: num(p.remaining),
        // `reset` is present only once the window has been used.
        resetsAt: reset ?? nextUtcBoundary(w, now),
        resetsAtSource: reset ? 'provider' : 'computed',
        primary: w === 'day' && PRIMARY_ACTIONS.has(action) && limit > 0,
        note: limit === 0 ? 'not in plan' : undefined,
      }))
    }
  }
  if (meters.length === 0) return shapeError(res)

  const products = Array.isArray(b.products) ? b.products : []
  return usageResult(meters, {
    account: {
      plan: products.includes('pro') ? 'urlscan Pro' : 'Free / Standard',
      label: scope ? `quota scope: ${scope}` : undefined,
    },
  })
}

export const urlscanProbe: ProbeDef = {
  id: 'urlscan',
  service: 'urlscan',
  label: 'urlscan.io',
  group: 'keys',
  field: 'urlscanApiKey',
  rotationTool: 'urlscan',
  kind: 'usage',
  costNote: 'Free: reading the quotas is not a metered action',
  docsUrl: 'https://docs.urlscan.io/apis/urlscan-openapi/generic/getquotas',
  dashboardUrl: 'https://urlscan.io/user/profile/',
  verifiedOn: '2026-09-27',
  endpoint: 'GET urlscan.io/api/v1/quotas',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
