/**
 * GitHub: `GET {api}/rate_limit` (catalogue A1). Calling it "does not count
 * against your primary rate limit". One probe, four settings fields: the three
 * github.com tokens and the GitHub Enterprise token, which only ever goes to the
 * saved, validated Enterprise host (never the other way round).
 */
import { apiBaseForHost, isValidGithubHost } from '@/lib/github/ownerTarget'
import { humanize, isPlainObject, num, epochToIso } from '../parse'
import { body, errorResult, meter, messageOf, shapeError, statusError, usageResult, validResult } from '../results'
import type { Meter, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const LABELS: Record<string, string> = {
  core: 'REST API (core)',
  search: 'Search',
  code_search: 'Code search',
  graphql: 'GraphQL',
  integration_manifest: 'App manifest conversions',
  source_import: 'Source imports',
  actions_runner_registration: 'Actions runner registration',
  scim: 'SCIM',
  dependency_snapshots: 'Dependency snapshots',
  dependency_sbom: 'Dependency SBOM',
  code_scanning_autofix: 'Code scanning autofix',
  code_scanning_upload: 'Code scanning uploads',
  audit_log: 'Audit log',
}

/** What kind of token the prefix says it is (GitHub's documented prefixes). */
export function tokenKind(token: string): string | undefined {
  if (token.startsWith('github_pat_')) return 'Fine-grained PAT'
  if (token.startsWith('ghp_')) return 'Classic PAT'
  if (token.startsWith('gho_')) return 'OAuth token'
  if (token.startsWith('ghu_')) return 'GitHub App user token'
  if (token.startsWith('ghs_')) return 'GitHub App installation token'
  if (token.startsWith('ghr_')) return 'Refresh token'
  return undefined
}

/** `github-authentication-token-expiration: 2027-09-06 12:00:00 UTC` (or `+0200`) -> ISO. */
export function parseGithubExpiry(value: string | undefined): string | undefined {
  const m = value?.trim().match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (UTC|[+-]\d{4})$/)
  if (!m) return undefined
  const zone = m[3] === 'UTC' ? 'Z' : `${m[3].slice(0, 3)}:${m[3].slice(3)}`
  const d = new Date(`${m[1]}T${m[2]}${zone}`)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

function headers(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  }
}

export function request(token: string, apiBase: string): ProbeRequest {
  // No trailing slash: `/rate_limit/` is a plain-text 404.
  return { method: 'GET', url: `${apiBase}/rate_limit`, headers: headers(token) }
}

function limitError(res: ProbeResponse): ProbeResult {
  const msg = messageOf(res)
  if (res.headers['x-ratelimit-remaining'] === '0') {
    return errorResult('quota_exhausted', msg || 'the primary rate limit is used up', { httpStatus: res.status })
  }
  if (/secondary rate limit/i.test(msg) || res.headers['retry-after']) {
    return errorResult('rate_limited', msg || 'secondary rate limit hit while checking', { httpStatus: res.status })
  }
  return statusError(res)
}

export function parse(res: ProbeResponse, token: string): ProbeResult {
  if (res.status === 401) return statusError(res, 'invalid_key', 'Bad credentials')
  if (res.status === 403 || res.status === 429) return limitError(res)
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  if (!isPlainObject(b.resources)) return shapeError(res)
  const core = isPlainObject(b.resources.core) ? b.resources.core : undefined
  // A token that is not applied gets the anonymous 60/h: never report that as the token's quota.
  if (core && num(core.limit) === 60) {
    return errorResult('invalid_key', 'the token was not applied (GitHub answered with anonymous limits)', { httpStatus: 200 })
  }

  const meters: Meter[] = []
  for (const [name, r] of Object.entries(b.resources)) {
    if (!isPlainObject(r)) continue
    const limit = num(r.limit)
    if (limit == null || limit === 0) continue
    const window = name === 'search' || name === 'code_search' ? 'minute' : 'hour'
    meters.push(meter({
      id: name,
      label: LABELS[name] ?? humanize(name),
      unit: name === 'graphql' ? 'points' : 'requests',
      window,
      used: num(r.used),
      limit,
      remaining: num(r.remaining),
      resetsAt: epochToIso(r.reset),
      primary: name === 'core',
    }))
  }
  if (meters.length === 0) return shapeError(res)

  const notes: string[] = []
  const scopes = res.headers['x-oauth-scopes']
  if (scopes !== undefined) notes.push(scopes ? `Scopes: ${scopes}` : 'Scopes: none')
  return usageResult(meters, {
    account: {
      plan: tokenKind(token),
      expiresAt: parseGithubExpiry(res.headers['github-authentication-token-expiration']),
    },
    notes: notes.length ? notes : undefined,
  })
}

/** GHES answers 404 "Rate limiting is not enabled." (its default): prove the token on /user instead. */
function rateLimitingDisabled(res: ProbeResponse): boolean {
  return res.status === 404 && /rate limiting is not enabled/i.test(messageOf(res))
}

async function run(ctx: ProbeContext, apiBase: string): Promise<ProbeResult> {
  const res = await ctx.http(request(ctx.key, apiBase))
  if (!rateLimitingDisabled(res)) return parse(res, ctx.key)
  const user = await ctx.http({ method: 'GET', url: `${apiBase}/user`, headers: headers(ctx.key) })
  if (user.status === 200) {
    return validResult({ account: { plan: tokenKind(ctx.key) }, notes: ['Rate limiting is disabled on this GitHub Enterprise server'] })
  }
  if (user.status === 401) return statusError(user, 'invalid_key', 'Bad credentials')
  return statusError(user)
}

const COMMON = {
  kind: 'usage' as const,
  costNote: 'Free: reading the rate limit does not count against it',
  docsUrl: 'https://docs.github.com/en/rest/rate-limit/rate-limit',
  verifiedOn: null,
  minIntervalMs: 500,
}

export const githubHuntProbe: ProbeDef = {
  ...COMMON,
  id: 'github-hunt',
  service: 'github',
  label: 'GitHub (Secret Hunt)',
  group: 'github',
  field: 'githubAccessToken',
  dashboardUrl: 'https://github.com/settings/tokens',
  endpoint: 'GET api.github.com/rate_limit',
  run: ctx => run(ctx, apiBaseForHost('github.com')),
}

export const githubSupplyChainProbe: ProbeDef = {
  ...COMMON,
  id: 'github-supply-chain',
  service: 'github',
  label: 'GitHub (Supply Chain)',
  group: 'github',
  field: 'supplyChainGithubToken',
  dashboardUrl: 'https://github.com/settings/tokens',
  endpoint: 'GET api.github.com/rate_limit',
  run: ctx => run(ctx, apiBaseForHost('github.com')),
}

/** A Multiscanner scan picks its GitHub endpoint per scan, so Settings can only ask github.com. */
export const MULTISCANNER_HOST_NOTE =
  'Checked against api.github.com; a token for a GitHub Enterprise endpoint set in a Multiscanner scan cannot be checked from Settings'

export const githubMultiscannerProbe: ProbeDef = {
  ...COMMON,
  id: 'github-multiscanner',
  service: 'github',
  label: 'GitHub (Secret Multiscanner)',
  group: 'github',
  field: 'trufflehogGithubToken',
  dashboardUrl: 'https://github.com/settings/tokens',
  endpoint: 'GET api.github.com/rate_limit',
  run: async ctx => {
    const r = await run(ctx, apiBaseForHost('github.com'))
    return r.error?.kind === 'invalid_key' ? { ...r, notes: [...(r.notes ?? []), MULTISCANNER_HOST_NOTE] } : r
  },
}

export const githubEnterpriseProbe: ProbeDef = {
  ...COMMON,
  id: 'github-enterprise',
  service: 'github-enterprise',
  label: 'GitHub Enterprise',
  group: 'github',
  field: 'githubEnterpriseToken',
  companions: [{ field: 'githubEnterpriseHost', required: true }],
  dashboardUrl: 'https://docs.github.com/en/enterprise-server@latest/rest/rate-limit/rate-limit',
  endpoint: 'GET <enterprise host>/api/v3/rate_limit',
  run: async ctx => {
    const host = (ctx.companions.githubEnterpriseHost ?? '').trim().toLowerCase()
    // The PUT validates the host on save; an older row may predate that, and an
    // unvalidated host is never fetched (it would carry the token to it).
    if (!isValidGithubHost(host)) {
      return errorResult('unexpected_response', 'the saved GitHub Enterprise host is not a valid hostname, so it was not contacted')
    }
    // The Enterprise token is never sent to github.com, whatever the host field says.
    if (host === 'github.com' || host.endsWith('.github.com')) {
      return errorResult('unexpected_response', 'the GitHub Enterprise host is set to github.com; the Enterprise token is never sent there')
    }
    return run(ctx, apiBaseForHost(host))
  },
}
