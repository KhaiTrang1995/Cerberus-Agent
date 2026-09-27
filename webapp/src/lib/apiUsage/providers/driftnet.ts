/**
 * Driftnet: `GET api.driftnet.io/v1/admin/user` with the Bearer header uncover
 * sends (catalogue A25). Two 403s mean opposite things: `{"code":403,"message":
 * "invalid token"}` is a bad token (observed, although the spec says 401),
 * while the spec's `{"error": ...}` 403 is an exhausted quota. The body echoes
 * the account's primary token and every additional one: they are compared in
 * memory only, to pick the quota of the token being checked, and never copied.
 */
import { clampRemaining, isPlainObject, isoOrNull, num, str } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(token: string): ProbeRequest {
  return {
    method: 'GET',
    url: 'https://api.driftnet.io/v1/admin/user',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  }
}

/** The quota of the checked token: the primary one, one of `additional_quota`, else the primary. */
function quotaFor(u: Record<string, unknown>, token: string): Record<string, unknown> | undefined {
  const primary = isPlainObject(u.quota) ? u.quota : undefined
  // The header value reaches the server trimmed.
  const wanted = token.trim()
  if (str(u.token) === wanted) return primary
  const extra = Array.isArray(u.additional_quota) ? u.additional_quota.filter(isPlainObject) : []
  return extra.find(a => str(a.token) === wanted) ?? primary
}

export function parse(res: ProbeResponse, token: string): ProbeResult {
  const b = body(res)
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status === 403) {
    const quotaError = str(b.error)
    if (quotaError) return errorResult('quota_exhausted', quotaError, { httpStatus: 403 })
    const message = str(b.message)
    if (message) return errorResult('invalid_key', message, { httpStatus: 403 })
    return statusError(res)
  }
  if (res.status !== 200) return statusError(res)

  const q = quotaFor(b, token)
  const limit = q ? num(q.api_limit) : null
  if (!q || limit == null) return shapeError(res)
  const used = num(q.api_usage)
  // `reset` is the last monthly anniversary, `next_reset` the coming one.
  const resetsAt = isoOrNull(q.next_reset)
  const meters: Meter[] = [meter({
    id: 'api', label: 'API operations', unit: 'requests', window: 'month',
    used, limit, remaining: clampRemaining(limit, used), resetsAt, primary: true,
  })]
  const priorityLimit = num(q.priority_limit)
  if (priorityLimit != null && priorityLimit > 0) {
    const priorityUsed = num(q.priority_usage)
    meters.push(meter({
      id: 'priority', label: 'Prioritizations', unit: 'count', window: 'month',
      used: priorityUsed, limit: priorityLimit, remaining: clampRemaining(priorityLimit, priorityUsed), resetsAt, primary: false,
    }))
  }
  const lifetime = num(q.lifetime_usage)
  if (lifetime != null) {
    meters.push(meter({ id: 'lifetime', label: 'Lifetime operations', unit: 'requests', window: 'lifetime', used: lifetime, primary: false }))
  }
  const userClass = str(b.user_class)
  return usageResult(meters, {
    account: { plan: `${b.paid === true ? 'Paid' : 'Free'}${userClass ? ` · ${userClass}` : ''}` },
  })
}

export const driftnetProbe: ProbeDef = {
  id: 'driftnet',
  service: 'driftnet',
  label: 'Driftnet',
  group: 'uncover',
  field: 'driftnetApiKey',
  rotationTool: 'driftnet',
  kind: 'usage',
  costNote: 'Cost undocumented: Driftnet states none for the account endpoint',
  docsUrl: 'https://api.driftnet.io/swagger.json',
  dashboardUrl: 'https://driftnet.io/',
  verifiedOn: null,
  endpoint: 'GET api.driftnet.io/v1/admin/user',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.key),
}
