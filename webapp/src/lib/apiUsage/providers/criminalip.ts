/**
 * Criminal IP: `POST api.criminalip.io/v1/user/me` with the `x-api-key` header
 * recon sends and an empty body (catalogue A16). Free: it is in no credit-
 * consumption list. The docs gate it "starting with the Starter Plan", yet a
 * Free key was answered too when checked live (without a search cap). No
 * endpoint exposes the remaining credits, so the most a check can report is the
 * plan's search cap. The status lives in the BODY (the official integrations
 * read `status`, not the HTTP code). The body echoes the key, the email and the
 * name: only `max_search` and `last_access_date` are read.
 */
import { isPlainObject, num, str } from '../parse'
import { body, errorResult, meter, notCheckedResult, shapeError, statusError, validResult } from '../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

const STARTER_ONLY = "Criminal IP's account API needs a Starter plan"

export function request(key: string): ProbeRequest {
  return { method: 'POST', url: 'https://api.criminalip.io/v1/user/me', headers: { 'x-api-key': key } }
}

function bodyStatusError(status: number, message: string, httpStatus: number): ProbeResult {
  const opts = { httpStatus, providerCode: String(status) }
  if (status === 412 || status === 415) return errorResult('unexpected_response', message || 'Criminal IP rejected the request', opts)
  if (status === 413 || status === 414 || status >= 500) return errorResult('provider_error', message || 'Criminal IP reported a server error', opts)
  if (status === 429) return errorResult('rate_limited', message || 'rate limited while checking; try again later', opts)
  // What a Free key gets here is undocumented: any other answer is the Starter gate.
  return notCheckedResult('plan_restricted', STARTER_ONLY)
}

export function parse(res: ProbeResponse): ProbeResult {
  // Only the API's own JSON is read for its body status; anything else is the edge.
  if (!isPlainObject(res.json)) return res.status === 200 ? shapeError(res) : statusError(res)
  const b = body(res)
  const status = typeof b.status === 'number' ? b.status : res.status
  const message = str(b.message) ?? ''
  if (status === 401) return errorResult('invalid_key', message || 'invalid api key', { httpStatus: res.status, providerCode: '401' })
  if (status !== 200) {
    if (/plan|upgrade|permission|starter/i.test(message)) return notCheckedResult('plan_restricted', STARTER_ONLY)
    return bodyStatusError(status, message, res.status)
  }

  const d = isPlainObject(b.data) ? b.data : undefined
  if (!d) return shapeError(res)
  // `account_type` is the sign-in method (e.g. google_social), not the plan.
  const lastUse = str(d.last_access_date)
  // "20,000,000": a string with thousands separators. A Free account answers
  // without it (seen live), so the cap is shown only when there is one.
  const cap = num(d.max_search)
  return validResult({
    account: { label: lastUse ? `last API use ${lastUse}` : undefined },
    meters: cap == null ? [] : [meter({
      id: 'max_search', label: 'Plan search cap', unit: 'searches', window: 'month',
      limit: cap, primary: false,
    })],
    notes: ['Criminal IP does not expose remaining credits'],
  })
}

export const criminalipProbe: ProbeDef = {
  id: 'criminalip',
  service: 'criminalip',
  label: 'Criminal IP',
  group: 'keys',
  field: 'criminalIpApiKey',
  rotationTool: 'criminalip',
  kind: 'validity',
  costNote: "Free: not in Criminal IP's credit-consumption list",
  docsUrl: 'https://www.criminalip.io/developer/api/post-user-me',
  dashboardUrl: 'https://search.criminalip.io/mypage/information',
  verifiedOn: '2026-09-27',
  endpoint: 'POST api.criminalip.io/v1/user/me',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
