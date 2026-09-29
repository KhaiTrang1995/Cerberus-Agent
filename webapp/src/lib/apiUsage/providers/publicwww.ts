/**
 * PublicWWW: `GET api.publicwww.com/v1/account` with a Bearer key (catalogue
 * A21): "/v1/account costs nothing", "spends no quota and works even on an
 * account with no plan". Never the legacy `api_status.xml?key=`, which answers
 * keyless with a 200 JS-challenge page. The API allows 2 requests / 30 s.
 */
import { clampRemaining, epochToIso, isPlainObject, num, nextMidnight, str } from '../parse'
import { body, errorResult, kindForStatus, meter, messageOf, shapeError, statusError, usageResult } from '../results'
import type { ErrorKind, Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.publicwww.com/v1/account', headers: { Authorization: `Bearer ${key}` } }
}

function errorCode(res: ProbeResponse): string | undefined {
  const b = body(res)
  return isPlainObject(b.error) && typeof b.error.code === 'string' ? b.error.code : undefined
}

function quotaMeter(id: 'searches' | 'snippets', used: number | null, limit: number | null, resetsAt: string | null, now: Date): Meter {
  return meter({
    id,
    label: id === 'searches' ? 'Searches (day)' : 'Snippets (day)',
    unit: 'requests',
    window: 'day',
    used,
    limit,
    remaining: clampRemaining(limit, used),
    resetsAt: resetsAt ?? nextMidnight('Z', now),
    resetsAtSource: resetsAt ? 'provider' : 'computed',
    primary: id === 'searches',
  })
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (res.status !== 200) {
    // Branch on the documented code: PublicWWW may reword its messages.
    const code = errorCode(res)
    if (!code) return statusError(res)
    const kind: ErrorKind =
      res.status === 401 || code === 'missing_key' || code === 'invalid_key' ? 'invalid_key'
        : code === 'quota_exceeded' || code === 'snippet_quota_exceeded' ? 'quota_exhausted'
          : code === 'too_many_requests' ? 'rate_limited'
            : kindForStatus(res.status)
    return errorResult(kind, messageOf(res) || code, { httpStatus: res.status, providerCode: code })
  }

  const b = body(res)
  const meters: Meter[] = []
  if (isPlainObject(b.quota)) {
    for (const id of ['searches', 'snippets'] as const) {
      const q = b.quota[id]
      if (!isPlainObject(q)) continue
      meters.push(quotaMeter(id, num(q.used), num(q.limit), epochToIso(q.resets_at), now))
    }
  } else {
    // Every authenticated response carries the counters as headers too.
    const limit = num(res.headers['x-ratelimit-limit'])
    const remaining = num(res.headers['x-ratelimit-remaining'])
    if (limit != null && remaining != null) {
      meters.push(quotaMeter('searches', Math.max(0, limit - remaining), limit, epochToIso(res.headers['x-ratelimit-reset']), now))
    }
    const sLimit = num(res.headers['x-snippets-limit'])
    const sRemaining = num(res.headers['x-snippets-remaining'])
    if (sLimit != null && sRemaining != null) {
      meters.push(quotaMeter('snippets', Math.max(0, sLimit - sRemaining), sLimit, null, now))
    }
  }
  if (meters.length === 0 && !('plan' in b)) return shapeError(res)

  return usageResult(meters, {
    account: { plan: str(b.plan) ?? 'No plan', expiresAt: epochToIso(b.plan_until) ?? undefined },
  })
}

export const publicwwwProbe: ProbeDef = {
  id: 'publicwww',
  service: 'publicwww',
  label: 'PublicWWW',
  group: 'uncover',
  field: 'publicWwwApiKey',
  rotationTool: 'publicwww',
  kind: 'usage',
  costNote: 'Free: /v1/account spends no quota',
  docsUrl: 'https://publicwww.com/docs/api/',
  dashboardUrl: 'https://publicwww.com/profile/',
  verifiedOn: null,
  endpoint: 'GET api.publicwww.com/v1/account',
  // 2 requests per 30 s.
  minIntervalMs: 15_000,
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
