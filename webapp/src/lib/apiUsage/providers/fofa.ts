/**
 * FOFA: `GET fofa.info/api/v1/info/my` (catalogue A11), authenticated exactly
 * like recon's `_fofa_auth_params`: a stored `email:key` is split on the first
 * colon into `email` + `key`, anything else is sent as `key` alone, both
 * trimmed. Every FOFA error is an HTTP 200 with `error: true` and an errmsg
 * "[<code>] <message>" (often Chinese).
 */
import { isoOrNull, num, str } from '../parse'
import { body, errorResult, meter, shapeError, statusError, usageResult, validResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const VIP_LEVELS: Record<number, string> = {
  0: 'Registered',
  1: 'Member',
  2: 'Advanced member',
  3: 'Enterprise',
  5: 'Enterprise',
  11: 'Subscription (personal)',
  12: 'Subscription (professional)',
  13: 'Subscription (business)',
  20: 'Red team',
  22: 'Education',
}

const KNOWN_CODES: Record<string, string> = {
  '-700': 'Account invalid (wrong key or email)',
  '45012': 'Requests too fast',
  '820000': 'Query syntax error',
}

export function authParams(stored: string): URLSearchParams {
  const params = new URLSearchParams()
  const colon = stored.indexOf(':')
  if (colon >= 0) {
    params.set('email', stored.slice(0, colon).trim())
    params.set('key', stored.slice(colon + 1).trim())
  } else {
    params.set('key', stored.trim())
  }
  return params
}

export function request(stored: string): ProbeRequest {
  return { method: 'GET', url: `https://fofa.info/api/v1/info/my?${authParams(stored).toString()}` }
}

/** GoFOFA's rule: the code is the text between a leading '[' and the first ']'. */
export function fofaCode(errmsg: string): string | undefined {
  const m = errmsg.match(/^\[([^\]]+)\]/)
  return m ? m[1].trim() : undefined
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status !== 200) return statusError(res)
  const b = body(res)
  if (b.error === true) {
    const errmsg = str(b.errmsg) ?? ''
    const code = fofaCode(errmsg)
    const message = code && KNOWN_CODES[code] ? `${KNOWN_CODES[code]} (${errmsg})` : errmsg || 'FOFA reported an error'
    if (code === '-700') return errorResult('invalid_key', message, { httpStatus: 200, providerCode: code })
    if (code === '45012') return errorResult('rate_limited', message, { httpStatus: 200, providerCode: code })
    return errorResult('unexpected_response', message, { httpStatus: 200, providerCode: code })
  }
  if (b.error !== false && str(b.username) === undefined) return shapeError(res)

  const vip = num(b.vip_level)
  const account = {
    plan: (vip != null ? VIP_LEVELS[vip] : undefined) ?? (b.isvip === true ? 'VIP' : 'Registered'),
    label: str(b.username),
    expiresAt: isoOrNull(b.expiration) ?? undefined,
  }

  const queries = num(b.remain_api_query)
  const rows = num(b.remain_api_data)
  const balances: Meter[] = []
  const freePoints = num(b.remain_free_point)
  if (freePoints != null) balances.push(meter({ id: 'free_points', label: 'Free points', unit: 'points', window: 'balance', remaining: freePoints, primary: false }))
  const points = num(b.fofa_point)
  if (points) balances.push(meter({ id: 'fpoints', label: 'F-points', unit: 'points', window: 'balance', remaining: points, primary: false }))
  const coins = num(b.fcoin)
  if (coins) balances.push(meter({ id: 'fcoin', label: 'F-coins', unit: 'coins', window: 'balance', remaining: coins, primary: false }))

  // A Registered (non-VIP) account answers 0/0 or leaves the counters out: the
  // level carries no API quota at all, which is not a paid quota used up.
  const noQuotaLevel = (vip ?? 0) === 0 && b.isvip !== true && !queries && !rows
  if ((queries == null && rows == null) || noQuotaLevel) {
    return validResult({ account, meters: balances, notes: ['This FOFA membership level has no API query quota'] })
  }
  // Only balances exist here: no limit, so Health can say "exhausted", never "low".
  const meters: Meter[] = []
  if (queries != null) meters.push(meter({ id: 'queries', label: 'API queries left', unit: 'queries', window: 'month', remaining: queries, primary: true }))
  if (rows != null) meters.push(meter({ id: 'rows', label: 'API data rows left', unit: 'rows', window: 'month', remaining: rows, primary: true }))
  return usageResult([...meters, ...balances], { account })
}

export const fofaProbe: ProbeDef = {
  id: 'fofa',
  service: 'fofa',
  label: 'FOFA',
  group: 'keys',
  field: 'fofaApiKey',
  rotationTool: 'fofa',
  kind: 'usage',
  costNote: 'Free: account information returns no query data',
  docsUrl: 'https://en.fofa.info/api',
  dashboardUrl: 'https://en.fofa.info/userInfo',
  verifiedOn: '2026-09-27',
  endpoint: 'GET fofa.info/api/v1/info/my',
  // GoFOFA spaces requests 1 s apart and treats code 45012 as throttling.
  minIntervalMs: 1100,
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
