/**
 * GitLab (catalogue B1): `GET gitlab.com/api/v4/personal_access_tokens/self`.
 * A scan picks its GitLab host per scan and Settings stores none, so the one
 * host checked is gitlab.com: a self-hosted token fails here without being
 * bad, and an invalid-key row says so. Personal, project and group access
 * tokens (glpat-) describe themselves; any other token type gets a 400 and is
 * proved on `/user` instead, without the token's own details.
 */
import { epochToIso, isoOrNull, num, str } from '../../parse'
import { body, errorResult, meter, messageOf, shapeError, statusError, validResult } from '../../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

const API = 'https://gitlab.com/api/v4'
export const SELF_HOSTED_NOTE = 'Checked against gitlab.com; a self-hosted GitLab token cannot be checked from Settings'

export function request(token: string): ProbeRequest {
  return { method: 'GET', url: `${API}/personal_access_tokens/self`, headers: { 'PRIVATE-TOKEN': token } }
}

export function userRequest(token: string): ProbeRequest {
  return { method: 'GET', url: `${API}/user`, headers: { 'PRIVATE-TOKEN': token } }
}

/** Every gitlab.com answer carries the per-minute window: headroom, not a plan quota. */
export function rateLimitMeter(headers: Record<string, string>): Meter | undefined {
  const limit = num(headers['ratelimit-limit'])
  const remaining = num(headers['ratelimit-remaining'])
  if (limit == null || remaining == null) return undefined
  return meter({
    id: 'api_minute',
    label: 'GitLab API (per minute)',
    unit: 'requests',
    window: 'minute',
    used: num(headers['ratelimit-observed']) ?? Math.max(0, limit - remaining),
    limit,
    remaining,
    resetsAt: epochToIso(headers['ratelimit-reset']),
    primary: false,
  })
}

/** GitLab gives invalid, missing, revoked and expired tokens the same 401. */
function unauthorized(res: ProbeResponse): ProbeResult {
  return errorResult('invalid_key', `GitLab rejected the token (${messageOf(res) || '401 Unauthorized'}). ${SELF_HOSTED_NOTE}`, { httpStatus: res.status })
}

/** The 400 GitLab gives a token that authenticates but is not an access token (OAuth). */
export function isNotAccessToken(res: ProbeResponse): boolean {
  return res.status === 400 && /requires token type to be a personal access token/i.test(messageOf(res))
}

function metersOf(res: ProbeResponse): Meter[] {
  const m = rateLimitMeter(res.headers)
  return m ? [m] : []
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 401) return unauthorized(res)
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  if (typeof b.active !== 'boolean' && typeof b.revoked !== 'boolean') return shapeError(res)
  const account = { label: str(b.name), expiresAt: isoOrNull(b.expires_at) ?? undefined }
  if (b.revoked === true || b.active === false) {
    return errorResult('invalid_key', 'GitLab reports this token as revoked or inactive', { httpStatus: 200, account })
  }
  const scopes = (Array.isArray(b.scopes) ? b.scopes : []).filter((s): s is string => typeof s === 'string')
  return validResult({
    account,
    notes: [scopes.length ? `Scopes: ${scopes.join(', ')}` : 'Scopes: none'],
    meters: metersOf(res),
  })
}

export function parseUser(res: ProbeResponse): ProbeResult {
  if (res.status === 401) return unauthorized(res)
  if (res.status !== 200) return statusError(res)
  const username = str(body(res).username)
  if (!username) return shapeError(res)
  return validResult({
    account: { label: username },
    notes: ['Not a personal, project or group access token: GitLab shows scopes and expiry only for those'],
    meters: metersOf(res),
  })
}

export const gitlabProbe: ProbeDef = {
  id: 'gitlab',
  service: 'gitlab',
  label: 'GitLab.com',
  group: 'sources',
  field: 'trufflehogGitlabToken',
  kind: 'validity',
  costNote: 'Free: a token reading its own details',
  docsUrl: 'https://docs.gitlab.com/api/personal_access_tokens/',
  dashboardUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
  verifiedOn: null,
  endpoint: 'GET gitlab.com/api/v4/personal_access_tokens/self',
  run: async ctx => {
    const res = await ctx.http(request(ctx.key))
    if (!isNotAccessToken(res)) return parse(res)
    return parseUser(await ctx.http(userRequest(ctx.key)))
  },
}
