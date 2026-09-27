/**
 * Hugging Face (catalogue B3): `GET huggingface.co/api/whoami-v2`. Free, but it
 * counts one request in the account's "api" rate bucket (a fixed 5-minute
 * window), which the IETF RateLimit headers on every answer describe: that
 * headroom is the only meter. The body carries the account email; it is never read.
 */
import { isPlainObject, isoOrNull, num, str } from '../../parse'
import { body, errorResult, meter, shapeError, statusError, validResult } from '../../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

export function request(token: string): ProbeRequest {
  return { method: 'GET', url: 'https://huggingface.co/api/whoami-v2', headers: { Authorization: `Bearer ${token}` } }
}

/**
 * The parameters of one structured-field list item: `"api";r=992;t=184` ->
 * { r: '992', t: '184' }. A header may list several policies; the one naming
 * `name` wins, else the first.
 */
export function itemParams(header: string | undefined, name: string): Record<string, string> | undefined {
  if (!header) return undefined
  const items = header.split(',').map(s => s.trim()).filter(Boolean)
  const item = items.find(i => i.includes(`"${name}"`)) ?? items[0]
  if (!item) return undefined
  const params: Record<string, string> = {}
  for (const part of item.split(';').slice(1)) {
    const eq = part.indexOf('=')
    if (eq > 0) params[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim().replace(/^"|"$/g, '')
  }
  return params
}

function windowLabel(seconds: number | null): string {
  if (seconds == null || seconds <= 0) return 'HF API'
  return seconds % 60 === 0 ? `HF API (${seconds / 60} min)` : `HF API (${seconds} s)`
}

/** `RateLimit: "api";r=<remaining>;t=<s to reset>` + `RateLimit-Policy: …;q=<quota>;w=<window s>`. */
export function rateLimitMeter(headers: Record<string, string>, now: Date): Meter | undefined {
  const current = itemParams(headers['ratelimit'], 'api')
  const remaining = num(current?.r)
  if (remaining == null) return undefined
  const policy = itemParams(headers['ratelimit-policy'], 'api')
  const limit = num(policy?.q)
  const resetIn = num(current?.t)
  return meter({
    id: 'api',
    // The window is 5 minutes, which no MeterWindow names: the label carries it.
    label: windowLabel(num(policy?.w)),
    unit: 'requests',
    window: 'minute',
    used: limit != null ? Math.max(0, limit - remaining) : null,
    limit,
    remaining,
    resetsAt: resetIn != null ? new Date(now.getTime() + resetIn * 1000).toISOString() : null,
    primary: false,
  })
}

function planOf(b: Record<string, unknown>): string | undefined {
  if (str(b.type) !== 'user') return undefined
  const own = b.isPro === true ? 'PRO' : 'Free'
  const orgPlans = new Set<string>()
  for (const org of Array.isArray(b.orgs) ? b.orgs : []) {
    const plan = isPlainObject(org) ? str(org.plan) : undefined
    if (plan) orgPlans.add(plan)
  }
  return orgPlans.size ? `${own} · org plan: ${[...orgPlans].join(', ')}` : own
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  // HF answers every bad token with "Invalid username or password.", which misleads for a token.
  if (res.status === 401) return errorResult('invalid_key', 'Hugging Face rejected the token (invalid, revoked or expired)', { httpStatus: 401 })
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  const name = str(b.name)
  if (!name) return shapeError(res)

  const notes: string[] = []
  const type = str(b.type)
  if (type && type !== 'user') notes.push(`Account type: ${type}`)
  const auth = isPlainObject(b.auth) ? b.auth : {}
  const token = isPlainObject(auth.accessToken) ? auth.accessToken : undefined
  if (token) {
    const role = str(token.role)
    notes.push(`Token: ${str(token.displayName) ?? 'unnamed'}${role ? ` (${role})` : ''}`)
  }
  const m = rateLimitMeter(res.headers, now)
  return validResult({
    account: { label: name, plan: planOf(b), expiresAt: isoOrNull(auth.expiresAt) ?? undefined },
    notes: notes.length ? notes : undefined,
    meters: m ? [m] : [],
  })
}

export const huggingfaceProbe: ProbeDef = {
  id: 'huggingface',
  service: 'huggingface',
  label: 'Hugging Face',
  group: 'sources',
  field: 'trufflehogHuggingfaceToken',
  kind: 'validity',
  costNote: 'Free: counts one request in the 5-minute API rate window',
  docsUrl: 'https://huggingface.co/docs/hub/rate-limits',
  dashboardUrl: 'https://huggingface.co/settings/tokens',
  verifiedOn: null,
  endpoint: 'GET huggingface.co/api/whoami-v2',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
