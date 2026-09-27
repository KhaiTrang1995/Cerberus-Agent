/**
 * ProjectDiscovery Cloud (catalogue A6): validity + plan, no quota. Call 1,
 * `GET /v1/user`, is the check projectdiscovery/utils' `ValidateAPIKey` makes.
 * Call 2 reads the vulnx per-minute window from the `x-ratelimit-*` headers of
 * `GET /v2/vulnerability/filters` (what `vulnx auth --test` calls; it uses 1
 * request of that window). Call 2 is headroom, not a quota: when it fails, the
 * key is still valid. Never `/v1/user/apikey`, which returns the key itself.
 */
import { ProbeTransportError } from '../http'
import { epochToIso, isPlainObject, num, str } from '../parse'
import { errorResult, meter, shapeError, statusError, validResult } from '../results'
import type { Meter, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const API = 'https://api.projectdiscovery.io'

/** The plan codes the first-party web app maps to names. */
const PLANS = new Map([
  ['FREE', 'Free'],
  ['VERIFIED_FREE', 'Verified Free'],
  ['PRO', 'Pro'],
  ['GROWTH', 'Growth'],
  ['TRIAL', 'Trial'],
  ['ENT', 'Enterprise'],
  ['ENT_TRIAL', 'Enterprise Trial'],
])

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `${API}/v1/user?utm_source=redamon`, headers: { 'X-Api-Key': key } }
}

export function headroomRequest(key: string): ProbeRequest {
  return { method: 'GET', url: `${API}/v2/vulnerability/filters`, headers: { 'X-Api-Key': key } }
}

/** Call 1: an error, or `valid_no_usage` with the plan and the account name. */
export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 401) return statusError(res, 'invalid_key')
  if (res.status !== 200) return statusError(res)
  if (!isPlainObject(res.json)) return shapeError(res)
  const u = res.json
  // The utils read a 200 without an email as an invalid key. The email is only tested, never copied.
  if (!str(u.email)) return errorResult('invalid_key', 'ProjectDiscovery returned no account for this key', { httpStatus: 200 })
  const plan = str(u.plan)
  const name = str(u.name)
  return validResult({
    account: {
      plan: plan ? PLANS.get(plan) : undefined,
      // The label is never an email, whatever the name field holds.
      label: name && !name.includes('@') ? name : undefined,
    },
  })
}

/** Call 2: the vulnx window, or null when the answer does not describe this key's window. */
export function parseHeadroom(res: ProbeResponse): Meter | null {
  // A 429 still carries the key's window; a 401/403 would be the keyless one.
  if (res.status !== 200 && res.status !== 429) return null
  const limit = num(res.headers['x-ratelimit-limit'])
  const remaining = num(res.headers['x-ratelimit-remaining'])
  if (limit == null || remaining == null) return null
  return meter({
    id: 'vulnx', label: 'vulnx requests (minute)', unit: 'requests', window: 'minute',
    used: Math.max(0, limit - remaining), limit, remaining,
    resetsAt: epochToIso(res.headers['x-ratelimit-reset']),
    primary: false,
  })
}

export const pdcpProbe: ProbeDef = {
  id: 'pdcp',
  service: 'pdcp',
  label: 'ProjectDiscovery Cloud',
  group: 'keys',
  field: 'pdcpApiKey',
  rotationTool: 'pdcp',
  kind: 'validity',
  costNote: 'Free: the account lookup spends nothing; reading the vulnx headroom uses 1 request of its per-minute window',
  docsUrl: 'https://github.com/projectdiscovery/utils/blob/main/auth/pdcp/creds.go',
  dashboardUrl: 'https://cloud.projectdiscovery.io',
  verifiedOn: null,
  endpoint: 'GET api.projectdiscovery.io/v1/user',
  run: async ctx => {
    const user = parse(await ctx.http(request(ctx.key)))
    if (user.outcome !== 'valid_no_usage') return user
    let headroom: Meter | null = null
    let missing: string | undefined
    try {
      const res = await ctx.http(headroomRequest(ctx.key))
      headroom = parseHeadroom(res)
      if (!headroom) missing = res.status === 200 || res.status === 429 ? 'no rate-limit headers' : `HTTP ${res.status}`
    } catch (e) {
      missing = e instanceof ProbeTransportError ? e.message : 'request failed'
    }
    return validResult({
      account: user.account,
      meters: headroom ? [headroom] : [],
      notes: missing ? [`vulnx rate headroom not read (${missing})`] : undefined,
    })
  },
}
