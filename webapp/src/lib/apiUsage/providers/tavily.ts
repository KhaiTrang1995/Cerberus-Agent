/**
 * Tavily: `GET api.tavily.com/usage` (catalogue A2). Not credit-costing, but it
 * has its own limit (10 requests / 10 minutes per key); one call per key and
 * the 60 s report cooldown keep a check inside it. No `X-Project-ID`: without it
 * the numbers are the whole key's, not one project tag's.
 */
import { clampRemaining, firstOfNextMonthUtc, isPlainObject, num, str } from '../parse'
import { body, meter, shapeError, statusError, usageResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.tavily.com/usage', headers: { Authorization: `Bearer ${key}` } }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (res.status === 401) return statusError(res, 'invalid_key')
  // 432 = key/plan limit, 433 = pay-as-you-go limit (documented on /search).
  if (res.status === 432 || res.status === 433) return statusError(res, 'quota_exhausted')
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  if (!isPlainObject(b.key) && !isPlainObject(b.account)) return shapeError(res)
  const k = isPlainObject(b.key) ? b.key : {}
  const a = isPlainObject(b.account) ? b.account : {}

  const meters: Meter[] = []
  const planLimit = num(a.plan_limit)
  const planUsed = num(a.plan_usage)
  // The FAQ says credits reset on the 1st "regardless of the billing date"; the
  // OpenAPI says "billing cycle". The FAQ is the more specific of the two.
  meters.push(meter({
    id: 'plan', label: 'Plan credits', unit: 'credits', window: 'month',
    used: planUsed, limit: planLimit, remaining: planLimit == null ? null : clampRemaining(planLimit, planUsed ?? 0),
    resetsAt: firstOfNextMonthUtc(now), resetsAtSource: 'computed', primary: true,
  }))
  const paygoLimit = num(a.paygo_limit)
  const paygoUsed = num(a.paygo_usage)
  if (paygoLimit != null || (paygoUsed ?? 0) > 0) {
    meters.push(meter({
      id: 'paygo', label: 'Pay-as-you-go', unit: 'credits', window: 'month',
      used: paygoUsed, limit: paygoLimit, remaining: paygoLimit == null ? null : clampRemaining(paygoLimit, paygoUsed ?? 0),
      primary: false, note: paygoLimit == null ? 'no pay-as-you-go cap' : undefined,
    }))
  }
  const keyLimit = num(k.limit)
  const keyUsed = num(k.usage)
  meters.push(meter({
    id: 'key', label: 'This key', unit: 'credits', window: 'month',
    used: keyUsed, limit: keyLimit, remaining: keyLimit == null ? null : clampRemaining(keyLimit, keyUsed ?? 0),
    primary: keyLimit != null, note: keyLimit == null ? 'no per-key cap' : undefined,
  }))
  return usageResult(meters, { account: { plan: str(a.current_plan) } })
}

export const tavilyProbe: ProbeDef = {
  id: 'tavily',
  service: 'tavily',
  label: 'Tavily',
  group: 'keys',
  field: 'tavilyApiKey',
  rotationTool: 'tavily',
  kind: 'usage',
  costNote: 'Free: /usage spends no credits (it allows 10 calls per 10 minutes per key)',
  docsUrl: 'https://docs.tavily.com/documentation/api-reference/endpoint/usage',
  dashboardUrl: 'https://app.tavily.com/home',
  verifiedOn: null,
  endpoint: 'GET api.tavily.com/usage',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
