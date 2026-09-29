/**
 * VirusTotal: `GET /api/v3/users/{key}/overall_quotas` (catalogue A14). Listed
 * under "No quota consumption" in the quota docs. The key is in the URL PATH
 * here, which is why probe URLs are never logged. `/users/{id}` is not used: it
 * is not on that list and echoes the key and the email.
 */
import { isPlainObject, num, nextUtcBoundary, humanize } from '../parse'
import { body, errorResult, meter, messageOf, shapeError, statusError, usageResult } from '../results'
import type { Meter, MeterWindow, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

/** `allowed` values of 1e9 / 6e10 are VirusTotal's "no personal cap" sentinels. */
const NO_CAP = 1e9

// The quota names VirusTotal documents; any other one is humanized.
const QUOTA_LABELS: Record<string, string> = {
  api_requests_hourly: 'API requests (hour)',
  api_requests_daily: 'API requests (day)',
  api_requests_monthly: 'API requests (month)',
  intelligence_searches_monthly: 'Intelligence searches (month)',
  intelligence_downloads_monthly: 'Intelligence downloads (month)',
  intelligence_retrohunt_jobs_monthly: 'Retrohunt jobs (month)',
  intelligence_vtdiff_creation_monthly: 'VT Diff creations (month)',
  intelligence_hunting_rules: 'Hunting rules',
  intelligence_graphs_private: 'Private graphs',
  cases_creation_monthly: 'Cases created (month)',
  collections_creation_monthly: 'Collections created (month)',
  private_scans_monthly: 'Private scans (month)',
  private_urlscans_monthly: 'Private URL scans (month)',
  monitor_storage_bytes: 'Monitor storage',
  monitor_storage_files: 'Monitor files stored',
  monitor_uploaded_bytes: 'Monitor uploads',
  monitor_uploaded_files: 'Monitor files uploaded',
}

function quotaLabel(name: string): string {
  return QUOTA_LABELS[name] ?? humanize(name)
}

export function request(key: string): ProbeRequest {
  return {
    method: 'GET',
    url: `https://www.virustotal.com/api/v3/users/${encodeURIComponent(key)}/overall_quotas`,
    headers: { 'x-apikey': key },
  }
}

function windowOf(name: string): MeterWindow {
  if (name.endsWith('_hourly')) return 'hour'
  if (name.endsWith('_daily')) return 'day'
  if (name.endsWith('_monthly') || name === 'intelligence_graphs_private') return 'month'
  return 'balance'
}

function errorCode(res: ProbeResponse): string | undefined {
  const b = body(res)
  return isPlainObject(b.error) && typeof b.error.code === 'string' ? b.error.code : undefined
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  if (res.status !== 200) {
    const code = errorCode(res)
    const msg = messageOf(res)
    if (res.status === 401) {
      return errorResult('invalid_key', code === 'UserNotActiveError' ? 'the VirusTotal account is not activated' : msg || 'Wrong API key', { httpStatus: 401, providerCode: code })
    }
    if (res.status === 429) {
      return errorResult(code === 'QuotaExceededError' ? 'quota_exhausted' : 'rate_limited', msg || 'Quota exceeded', { httpStatus: 429, providerCode: code })
    }
    return statusError(res)
  }

  const data = body(res).data
  if (!isPlainObject(data)) return shapeError(res)

  const meters: Meter[] = []
  let groupName: string | undefined
  let dailyUserCap: number | null = null
  for (const [name, e] of Object.entries(data)) {
    if (!isPlainObject(e)) continue
    const user = isPlainObject(e.user) ? e.user : undefined
    const group = isPlainObject(e.group) ? e.group : undefined
    const pool = group ?? user
    if (!pool) continue
    const allowed = num(pool.allowed)
    const used = num(pool.used)
    if (allowed == null || (allowed === 0 && !used)) continue
    if (name === 'api_requests_daily' && user) dailyUserCap = num(user.allowed)
    const inherited = group && typeof group.inherited_from === 'string' ? group.inherited_from : undefined
    if (inherited) groupName = inherited
    const window = windowOf(name)
    const limit = allowed >= NO_CAP ? null : allowed
    meters.push(meter({
      id: name,
      label: quotaLabel(name),
      unit: name.endsWith('_bytes') ? 'bytes' : 'requests',
      window,
      used,
      limit,
      remaining: limit == null || used == null ? null : Math.max(0, limit - used),
      resetsAt: nextUtcBoundary(window, now),
      resetsAtSource: 'computed',
      primary: name === 'api_requests_daily' || name === 'api_requests_monthly',
      note: inherited ? `group: ${inherited}` : group ? 'group quota' : limit == null ? 'no personal cap' : undefined,
    }))
    // A personal cap tighter than the group's is the one that bites.
    const userAllowed = user ? num(user.allowed) : null
    if (group && userAllowed != null && userAllowed > 0 && userAllowed < Math.min(NO_CAP, allowed)) {
      const userUsed = num(user!.used)
      meters.push(meter({
        id: `${name}.user`,
        label: `${quotaLabel(name)}, your cap`,
        unit: name.endsWith('_bytes') ? 'bytes' : 'requests',
        window,
        used: userUsed,
        limit: userAllowed,
        remaining: userUsed == null ? null : Math.max(0, userAllowed - userUsed),
        resetsAt: nextUtcBoundary(window, now),
        resetsAtSource: 'computed',
        primary: name === 'api_requests_daily' || name === 'api_requests_monthly',
      }))
    }
  }
  if (meters.length === 0) return shapeError(res)

  // No response names the plan: a heuristic on the documented free daily cap.
  const plan = groupName
    ? `Premium via ${groupName}`
    : dailyUserCap != null && dailyUserCap <= 500 ? 'Public (free)' : 'Premium'
  return usageResult(meters, { account: { plan } })
}

export const virustotalProbe: ProbeDef = {
  id: 'virustotal',
  service: 'virustotal',
  label: 'VirusTotal',
  group: 'keys',
  field: 'virusTotalApiKey',
  rotationTool: 'virustotal',
  kind: 'usage',
  costNote: 'Free: VirusTotal lists overall_quotas under "no quota consumption"',
  docsUrl: 'https://docs.virustotal.com/reference/get-user-overall-quotas',
  dashboardUrl: 'https://www.virustotal.com/gui/my-apikey',
  verifiedOn: '2026-09-27',
  endpoint: 'GET www.virustotal.com/api/v3/users/{key}/overall_quotas',
  // A free key allows 4 requests/minute: pool keys run strictly one after another.
  minIntervalMs: 1000,
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}
