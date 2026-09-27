/**
 * Builders for the ProbeResult a provider returns, and the default mapping from
 * an HTTP answer to an ErrorKind. A provider overrides the mapping only where
 * its contract differs (Netlas answers a bad key with 400, NVD with 404, Driftnet
 * with 403): the defaults are the common case, not a guess about every API.
 */
import { isPlainObject, str } from './parse'
import type {
  AccountInfo, ErrorKind, Health, Meter, NotCheckedReason, ProbeResponse, ProbeResult,
} from './types'

const MAX_MESSAGE = 240

type MeterSpec = Pick<Meter, 'id' | 'label' | 'unit' | 'window'> & Partial<Omit<Meter, 'id' | 'label' | 'unit' | 'window'>>

/** A Meter with every unreported field null, and resetsAtSource tied to resetsAt. */
export function meter(spec: MeterSpec): Meter {
  const m: Meter = {
    used: null, limit: null, remaining: null, resetsAt: null, resetsAtSource: null, primary: false,
    ...spec,
  }
  if (m.resetsAt == null) m.resetsAtSource = null
  else if (m.resetsAtSource == null) m.resetsAtSource = 'provider'
  if (m.note === undefined) delete m.note
  return m
}

export function usageResult(
  meters: Meter[],
  extra: { account?: AccountInfo; notes?: string[]; healthOverride?: Health } = {},
): ProbeResult {
  if (meters.length === 0) return validResult({ account: extra.account, notes: extra.notes })
  return { outcome: 'usage', meters, ...extra }
}

/** The key works, and the provider reports no quota (or only rate headroom). */
export function validResult(extra: { account?: AccountInfo; notes?: string[]; meters?: Meter[] } = {}): ProbeResult {
  return { outcome: 'valid_no_usage', meters: extra.meters ?? [], account: extra.account, notes: extra.notes }
}

export function errorResult(
  kind: ErrorKind,
  message: string,
  opts: { httpStatus?: number; providerCode?: string; account?: AccountInfo } = {},
): ProbeResult {
  return {
    outcome: 'error',
    meters: [],
    account: opts.account,
    error: {
      kind,
      message: message.slice(0, MAX_MESSAGE),
      ...(opts.httpStatus != null ? { httpStatus: opts.httpStatus } : {}),
      ...(opts.providerCode != null ? { providerCode: opts.providerCode } : {}),
    },
  }
}

export function notCheckedResult(reason: NotCheckedReason, note?: string): ProbeResult {
  return { outcome: 'not_checked', meters: [], notCheckedReason: reason, notes: note ? [note] : undefined }
}

export function isHtml(res: ProbeResponse): boolean {
  return res.contentType.includes('html') || /^\s*<(!doctype|html|head|body)/i.test(res.text)
}

/** The body as an object, or {} (the parsers read optional fields from it). */
export function body(res: ProbeResponse): Record<string, unknown> {
  return isPlainObject(res.json) ? res.json : {}
}

/**
 * The provider's own error message: error.message -> error (string) ->
 * message / Message -> detail -> msg -> the raw text (when it is not HTML).
 * Truncated; the runner scrubs the key out of it.
 */
export function messageOf(res: ProbeResponse): string {
  const b = res.json
  if (isPlainObject(b)) {
    const e = b.error
    if (isPlainObject(e)) {
      const m = str(e.message) ?? str(e.msg)
      if (m) return m.slice(0, MAX_MESSAGE)
    }
    const direct = str(e) ?? str(b.message) ?? str(b.Message) ?? str(b.errmsg)
      ?? (isPlainObject(b.detail) ? str(b.detail.msg) ?? str(b.detail.error) : str(b.detail)) ?? str(b.msg)
    if (direct) return direct.slice(0, MAX_MESSAGE)
  }
  // Raw text only for a plain-text body (SecurityTrails' "Please check user
  // credentials"): a JSON body without a message field would otherwise be copied
  // whole, echoed IPs and inputs included.
  if (res.json === undefined && !isHtml(res)) {
    const t = res.text.trim()
    if (t) return t.slice(0, MAX_MESSAGE)
  }
  return ''
}

const DEFAULT_TEXT: Partial<Record<ErrorKind, string>> = {
  invalid_key: 'the provider rejected the key',
  forbidden: 'the key was accepted but may not call this endpoint',
  rate_limited: 'rate limited while checking; try again later',
  quota_exhausted: 'the provider reports the quota is used up',
  provider_error: 'the provider returned a server error',
  unexpected_response: 'the provider answered in an unexpected format',
}

export function kindForStatus(status: number): ErrorKind {
  if (status === 401) return 'invalid_key'
  if (status === 403) return 'forbidden'
  if (status === 429) return 'rate_limited'
  if (status >= 500) return 'provider_error'
  return 'unexpected_response'
}

/**
 * The default mapping for a non-success answer: 401 invalid key, 403 forbidden,
 * 429 rate limited, 5xx provider error, anything else unexpected.
 */
export function statusError(res: ProbeResponse, kind: ErrorKind = kindForStatus(res.status), fallback?: string): ProbeResult {
  const msg = isHtml(res) && kind === 'provider_error'
    ? 'the provider returned an error page'
    : messageOf(res) || fallback || DEFAULT_TEXT[kind] || 'request failed'
  return errorResult(kind, msg, { httpStatus: res.status })
}

/** A 2xx body that does not have the fields the parser needs: the API drifted. */
export function shapeError(res: ProbeResponse, what = 'the provider answered in an unexpected format'): ProbeResult {
  return errorResult('unexpected_response', isHtml(res) ? 'the provider returned an HTML page instead of JSON' : what, { httpStatus: res.status })
}
