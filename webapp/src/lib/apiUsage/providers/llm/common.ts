/**
 * Shared by the LLM provider probes (catalogue Part C). The providers speak
 * OpenAI-ish JSON but disagree on the details: DeepSeek, Together and xAI can
 * answer in plain text, xAI puts a string in `error`, Google nests its reason in
 * `details[]`. `messageOf` (results.ts) already reads the message in the
 * catalogue's order; this adds the provider's code and the rule the validity
 * probes share: a models listing that answers 2xx proves the key.
 */
import { isPlainObject } from '../../parse'
import { shapeError, statusError, validResult } from '../../results'
import type { ErrorKind, ProbeDef, ProbeResponse, ProbeResult } from '../../types'

/** One UserLlmProvider row is one job; its key is the row's `apiKey`. */
export const LLM_PROBE: Pick<ProbeDef, 'group' | 'field' | 'verifiedOn'> = {
  group: 'llm',
  field: 'apiKey',
  verifiedOn: null,
}

export function bearer(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}` }
}

/**
 * error.code -> error.type -> a top-level `code`, the first string set. Numbers
 * are skipped: where they appear (OpenRouter, Google) they repeat the HTTP status.
 */
export function providerCode(res: ProbeResponse): string | undefined {
  const b = res.json
  if (!isPlainObject(b)) return undefined
  const e = isPlainObject(b.error) ? b.error : {}
  for (const v of [e.code, e.type, b.code]) {
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return undefined
}

/** The default status mapping (statusError), carrying the provider's code. */
export function fail(res: ProbeResponse, kind?: ErrorKind, code: string | undefined = providerCode(res)): ProbeResult {
  const r = statusError(res, kind)
  if (code && r.error) r.error.providerCode = code
  return r
}

export function withNote(r: ProbeResult, note: string): ProbeResult {
  return { ...r, notes: [...(r.notes ?? []), note] }
}

/**
 * A 2xx from a models listing: the key works (valid, no usage API). Undefined
 * for any other status, left to the provider's own error mapping.
 */
export function listed(res: ProbeResponse): ProbeResult | undefined {
  if (res.status < 200 || res.status >= 300) return undefined
  if (res.json !== undefined) return validResult()
  // Together lists every model it serves in one answer, which can pass the
  // 256 KB read cap; http.ts then leaves `json` unset, but the key still worked.
  if (res.truncated && /^\s*[[{]/.test(res.text)) return validResult()
  return shapeError(res)
}
