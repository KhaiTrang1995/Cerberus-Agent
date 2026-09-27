/**
 * Onyphe: `GET www.onyphe.io/api/v2/user` with `Authorization: bearer`, the
 * header uncover sends (catalogue A24). There is no api.onyphe.io and no v3
 * user endpoint. The envelope's `error`/`status` decide whatever the HTTP
 * status (v1 answered errors with 200, v2 with 400). Every envelope echoes the
 * caller's IP (`myip`) and the result echoes the key (`apikey`): messages come
 * from `text` only, never from the raw body. Onyphe limits 1 request/second
 * per source IP, hence the process-wide pacing.
 */
import { isPlainObject, isoOrNull, num, str } from '../parse'
import { errorResult, kindForStatus, meter, shapeError, statusError, usageResult } from '../results'
import type { ErrorKind, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../types'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://www.onyphe.io/api/v2/user', headers: { Authorization: `bearer ${key}` } }
}

function envelopeError(res: ProbeResponse, b: Record<string, unknown>): ProbeResult {
  const code = num(b.error)
  const text = str(b.text)
  const opts = { httpStatus: res.status, providerCode: code != null ? String(code) : undefined }
  // 2 = "No API key given", 3 = "Invalid API key format".
  if (code === 2 || code === 3) return errorResult('invalid_key', text ?? 'Onyphe rejected the key', opts)
  // pyonyphe: "credits exhausted, or API not in your license".
  if (res.status === 402) return errorResult('quota_exhausted', text ?? 'credits exhausted, or the API is not in the license', opts)
  const kind: ErrorKind = res.status === 200 || res.status === 400 ? 'unexpected_response' : kindForStatus(res.status)
  return errorResult(kind, text ?? 'Onyphe reported an error', opts)
}

export function parse(res: ProbeResponse): ProbeResult {
  const b = isPlainObject(res.json) ? res.json : undefined
  const code = b ? num(b.error) : null
  // Not Onyphe's envelope: an edge or proxy answered.
  if (!b || (code == null && b.status !== 'nok')) return res.status === 200 ? shapeError(res) : statusError(res)
  if (code !== 0 || b.status === 'nok') return envelopeError(res, b)

  const r = Array.isArray(b.results) && isPlainObject(b.results[0]) ? b.results[0] : undefined
  const credits = r ? num(r.credits) : null
  if (!r || (credits == null && str(r.view) == null)) return shapeError(res)
  // Plans are sold as "results per month", but the API returns only a balance, with no reset.
  return usageResult([meter({ id: 'credits', label: 'Credits', unit: 'credits', window: 'balance', remaining: credits, primary: true })], {
    account: {
      plan: str(r.view),
      // `enddate` 0 means no end date.
      expiresAt: num(r.enddate) === 0 ? undefined : isoOrNull(r.enddate) ?? undefined,
    },
  })
}

export const onypheProbe: ProbeDef = {
  id: 'onyphe',
  service: 'onyphe',
  label: 'Onyphe',
  group: 'uncover',
  field: 'onypheApiKey',
  rotationTool: 'onyphe',
  kind: 'usage',
  costNote: 'Cost undocumented: the official client calls this endpoint "cheap"',
  docsUrl: 'https://search.onyphe.io/docs/general-apis/user',
  dashboardUrl: 'https://search.onyphe.io/',
  verifiedOn: null,
  endpoint: 'GET www.onyphe.io/api/v2/user',
  minIntervalMs: 1100,
  limitScope: 'ip',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
