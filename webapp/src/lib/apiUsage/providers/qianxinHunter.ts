/**
 * Qianxin Hunter: `GET hunter.qianxin.com/openApi/userInfo?api-key=` (catalogue
 * A20). EXPERIMENTAL: the endpoint is in no reachable official doc; two
 * independent, current clients use it. So only the recognised answers count:
 * anything else is "not checked", never an error, and the probe never falls
 * back to `/openApi/search`, which spends points. Hunter's WAF fingerprints TLS
 * and geo-blocks many servers outside China: an HTML page, a `WZWS-RAY` header
 * or a dropped connection is the firewall, not the key. Numbers may arrive as
 * numeric strings.
 */
import { ProbeTransportError } from '../http'
import { isPlainObject, nextMidnight, num, str } from '../parse'
import { body, errorResult, isHtml, meter, notCheckedResult, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

/** Daily allowances are taken to reset at midnight Beijing time (unstated). */
const SHANGHAI = '+08:00'
const BLOCKED = "blocked by Hunter's firewall (often outside mainland China)"
const NO_ACCOUNT_API = 'no documented account API; the search-based check costs points'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `https://hunter.qianxin.com/openApi/userInfo?api-key=${encodeURIComponent(key)}` }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (isHtml(res) || res.headers['wzws-ray'] !== undefined) return errorResult('provider_error', BLOCKED, { httpStatus: res.status })
  const b = body(res)
  const code = num(b.code)
  const message = str(b.message)
  const opts = { httpStatus: res.status, providerCode: code != null ? String(code) : undefined }
  // Errors are usually a `code` in an HTTP 200 body; the HTTP status can carry them too.
  if (code === 401 || res.status === 401) {
    return errorResult('invalid_key', `Hunter rejected the key${message ? ` (${message})` : ''}`, opts)
  }
  if (code === 429 || res.status === 429) return errorResult('rate_limited', 'Hunter rate-limited the check; try again later', opts)
  // "大牛，您的积分用完了，明天再试试": the points are used up.
  if (message && /积分(用完|不足)/.test(message)) return errorResult('quota_exhausted', 'Hunter reports the points are used up', opts)
  // Code 40205 is a notice that still carries `data`, so no success code is required.
  const d = isPlainObject(b.data) ? b.data : undefined
  if (res.status !== 200 || !d || (d.rest_free_point == null && d.rest_equity_point == null)) {
    return notCheckedResult('costs_credits', NO_ACCOUNT_API)
  }

  const free = num(d.rest_free_point)
  const daily = num(d.day_free_point)
  const resetsAt = nextMidnight(SHANGHAI, now)
  const meters: Meter[] = [
    meter({
      id: 'free', label: 'Free points (today)', unit: 'points', window: 'day',
      remaining: free, limit: daily, used: daily != null && free != null ? Math.max(0, daily - free) : null,
      resetsAt, resetsAtSource: 'computed', primary: true,
    }),
    meter({ id: 'equity', label: 'Equity points', unit: 'points', window: 'balance', remaining: num(d.rest_equity_point), primary: false }),
  ]
  if (d.day_export_quota != null) {
    meters.push(meter({
      id: 'export', label: 'Exports (today)', unit: 'count', window: 'day',
      remaining: num(d.rest_export_quota), limit: num(d.day_export_quota),
      resetsAt, resetsAtSource: 'computed', primary: false,
    }))
  }
  // `personal_info` carries the username and phone: never read.
  return usageResult(meters, { account: { plan: str(d.type) === '企业用户' ? 'Enterprise' : 'Personal' } })
}

export const qianxinHunterProbe: ProbeDef = {
  id: 'hunter',
  service: 'hunter',
  label: 'Qianxin Hunter',
  group: 'uncover',
  field: 'hunterApiKey',
  rotationTool: 'hunter',
  kind: 'usage',
  experimental: true,
  costNote: 'Cost undocumented (presumed free); never falls back to a search, which spends points',
  docsUrl: 'https://github.com/chaitin/OctoBus',
  dashboardUrl: 'https://hunter.qianxin.com/',
  verifiedOn: null,
  endpoint: 'GET hunter.qianxin.com/openApi/userInfo',
  // About 1 request / 2 s, enforced per source IP.
  minIntervalMs: 2000,
  limitScope: 'ip',
  run: async ctx => {
    let res: ProbeResponse
    try {
      res = await ctx.http(request(ctx.key))
    } catch (e) {
      // The firewall drops the connection outright after a couple of requests.
      if (e instanceof ProbeTransportError && e.kind === 'network') return errorResult('provider_error', BLOCKED)
      // A refused redirect is an answer this undocumented endpoint is not known to give.
      if (e instanceof ProbeTransportError && e.kind === 'unexpected_response') return notCheckedResult('costs_credits', NO_ACCOUNT_API)
      throw e
    }
    return parse(res, ctx.now)
  },
}
