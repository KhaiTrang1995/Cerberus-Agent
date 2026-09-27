/**
 * Postman (catalogue B6): `GET api.getpostman.com/me`. The one source check
 * that is not free: Postman counts every API call, this one included, toward
 * the account's monthly Postman API usage (no exemption is documented), and
 * the cost note says so. The answer carries the account's operation quotas,
 * `api_usage` (Postman API calls this month) among them.
 */
import { clampRemaining, humanize, isPlainObject, num, str } from '../../parse'
import { body, errorResult, messageOf, meter, shapeError, statusError, usageResult, validResult } from '../../results'
import type { Meter, MeterUnit, MeterWindow, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

/** Postman's "no limit" sentinel. */
const UNLIMITED = 99_999_999

const OPERATIONS: Record<string, { label: string; unit: MeterUnit; window: MeterWindow }> = {
  api_usage: { label: 'Postman API calls', unit: 'requests', window: 'month' },
  mock_usage: { label: 'Mock server calls', unit: 'requests', window: 'month' },
  monitor_request_runs: { label: 'Monitor requests', unit: 'requests', window: 'month' },
  flow_requests: { label: 'Flow requests', unit: 'requests', window: 'month' },
  postbot_calls: { label: 'Postbot calls', unit: 'requests', window: 'month' },
  collection_run_limit: { label: 'Collection runs', unit: 'count', window: 'month' },
  performance_test_limit: { label: 'Performance test runs', unit: 'count', window: 'month' },
  test_data_retrieval: { label: 'Test data retrievals', unit: 'count', window: 'month' },
  // Capacities, not monthly allowances; storage is counted in GB.
  test_data_storage: { label: 'Test data storage (GB)', unit: 'count', window: 'lifetime' },
  file_storage_limit: { label: 'File storage (GB)', unit: 'count', window: 'lifetime' },
  reusable_packages: { label: 'Package library packages', unit: 'count', window: 'lifetime' },
  api_object_usage: { label: 'API objects', unit: 'count', window: 'lifetime' },
}

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.getpostman.com/me', headers: { 'X-API-Key': key } }
}

function cap(limit: number | null): number | null {
  return limit == null || limit >= UNLIMITED ? null : limit
}

function operationMeter(op: Record<string, unknown>): Meter | undefined {
  const name = str(op.name)
  if (!name) return undefined
  const spec = OPERATIONS[name] ?? { label: humanize(name), unit: 'count' as const, window: 'month' as const }
  const reported = num(op.limit)
  const limit = cap(reported)
  const used = num(op.usage)
  const overage = num(op.overage)
  const notes = [
    ...(reported != null && limit == null ? ['unlimited'] : []),
    ...(overage ? [`overage: ${overage}`] : []),
  ]
  return meter({
    id: name,
    label: spec.label,
    unit: spec.unit,
    window: spec.window,
    used,
    limit,
    remaining: clampRemaining(limit, used),
    primary: name === 'api_usage',
    note: notes.length ? notes.join(' · ') : undefined,
  })
}

/**
 * Guest and Partner roles get no `operations`; the monthly API-call headers
 * still describe the one quota this check spends.
 */
function monthlyHeaderMeter(headers: Record<string, string>): Meter | undefined {
  const reported = num(headers['ratelimit-limit-month'] ?? headers['x-ratelimit-limit-month'])
  const remaining = num(headers['ratelimit-remaining-month'] ?? headers['x-ratelimit-remaining-month'])
  if (reported == null || remaining == null) return undefined
  const limit = cap(reported)
  return meter({
    id: 'api_usage',
    label: 'Postman API calls',
    unit: 'requests',
    window: 'month',
    used: limit != null ? Math.max(0, limit - remaining) : null,
    limit,
    remaining: limit != null ? remaining : null,
    primary: true,
    note: limit == null ? 'unlimited' : undefined,
  })
}

export function parse(res: ProbeResponse): ProbeResult {
  const b = body(res)
  const errorName = isPlainObject(b.error) ? str(b.error.name) : undefined
  if (errorName === 'serviceLimitExhausted') {
    return errorResult('quota_exhausted', messageOf(res) || 'the monthly Postman API limit is used up', { httpStatus: res.status, providerCode: errorName })
  }
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status === 429) {
    return errorResult('rate_limited', messageOf(res) || 'rate limited while checking; try again later', { httpStatus: 429, providerCode: errorName })
  }
  if (res.status !== 200) return statusError(res)

  const user = isPlainObject(b.user) ? b.user : undefined
  if (!user) return shapeError(res)
  const account = { label: str(user.username), plan: str(user.teamName) ?? 'Personal' }

  const meters: Meter[] = []
  for (const op of Array.isArray(b.operations) ? b.operations : []) {
    const m = isPlainObject(op) ? operationMeter(op) : undefined
    if (m) meters.push(m)
  }
  if (!meters.some(m => m.id === 'api_usage')) {
    const fromHeaders = monthlyHeaderMeter(res.headers)
    if (fromHeaders) meters.unshift(fromHeaders)
  }
  if (meters.length === 0) return validResult({ account, notes: ['Postman reports no usage for this account role'] })
  return usageResult(meters, { account })
}

export const postmanProbe: ProbeDef = {
  id: 'postman',
  service: 'postman',
  label: 'Postman',
  group: 'sources',
  field: 'trufflehogPostmanToken',
  kind: 'usage',
  costNote: "Costs 1 Postman API call: /me counts toward the account's monthly Postman API usage",
  docsUrl: 'https://learning.postman.com/docs/developer/postman-api/postman-api-rate-limits/',
  dashboardUrl: 'https://go.postman.co/settings/me/api-keys',
  verifiedOn: null,
  endpoint: 'GET api.getpostman.com/me',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
