/**
 * The one HTTP path every usage probe takes. It exists so no provider parser
 * has to remember the rules that keep a key where it belongs:
 *
 * - `redirect: 'error'`. Node's fetch drops `Authorization` on a cross-origin
 *   redirect but FORWARDS custom headers, and most providers here authenticate
 *   with one (`x-apikey`, `API-KEY`, `X-QuakeToken`, ...). A followed redirect
 *   would hand the key to whatever host the Location names.
 * - A hard timeout and a streamed read capped at MAX_BODY_BYTES, so a hanging
 *   or huge answer cannot pin the run.
 * - JSON is sniffed from the body, not trusted from Content-Type: SecurityTrails
 *   answers 401 as bare text, ZoomEye serves JSON as octet-stream, and several
 *   providers sit behind an HTML challenge page.
 * - A key with a control character (a pasted CR/LF) is never put in a header.
 *   Node would silently strip it at the edges and send a key the scans never
 *   send, and throw for one in the middle.
 * - The URL is never logged or put in a message: Shodan, SerpAPI, FOFA, ViewDNS
 *   and Qianxin Hunter take the key in the query string, VirusTotal in the path.
 */
import type { ErrorKind, ProbeRequest, ProbeResponse } from './types'

export const PROBE_TIMEOUT_MS = 10_000
export const MAX_BODY_BYTES = 256 * 1024
const TEXT_KEEP = 2048
export const PROBE_USER_AGENT = 'RedAmon-api-usage'

const KEEP_HEADERS = new Set([
  'content-type', 'retry-after', 'server', 'location', 'www-authenticate',
  'message', // NVD puts the error reason here, over an empty 404 body
  'github-authentication-token-expiration', 'x-oauth-scopes',
  'cf-mitigated', 'wzws-ray', 'x-via-jsl',
  'x-remote-user-name', 'x-otx-active',
  'x-amzn-errortype', 'x-error-message',
])
const KEEP_HEADER_PREFIXES = ['x-ratelimit-', 'ratelimit', 'x-rate-limit-', 'x-snippets-', 'x-vulners-']

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1f\x7f]/

export class ProbeTransportError extends Error {
  readonly kind: ErrorKind
  /** The key itself is unusable as stored (a control character). */
  readonly keyFormat: boolean
  constructor(kind: ErrorKind, message: string, keyFormat = false) {
    super(message)
    this.name = 'ProbeTransportError'
    this.kind = kind
    this.keyFormat = keyFormat
  }
}

export function hasControlChars(v: string): boolean {
  return CONTROL_CHARS.test(v)
}

/** Remove every secret (raw, trimmed and URL-encoded forms) from a string. */
export function scrub(text: string, secrets: readonly string[]): string {
  let out = text
  for (const s of secrets) {
    if (!s) continue
    const forms = new Set([s, s.trim(), encodeURIComponent(s), encodeURIComponent(s.trim())])
    for (const form of forms) {
      if (form.length >= 4) out = out.split(form).join('***')
    }
  }
  return out
}

function keepHeader(name: string): boolean {
  return KEEP_HEADERS.has(name) || KEEP_HEADER_PREFIXES.some(p => name.startsWith(p))
}

function pickHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  headers.forEach((value, name) => {
    const n = name.toLowerCase()
    if (keepHeader(n)) out[n] = value
  })
  return out
}

async function readCapped(res: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  if (!res.body) return { body: '', truncated: false }
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  let truncated = false
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (total + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - total))
      total = maxBytes
      truncated = true
      await reader.cancel().catch(() => {})
      break
    }
    chunks.push(value)
    total += value.byteLength
  }
  const joined = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) {
    joined.set(c, offset)
    offset += c.byteLength
  }
  return { body: new TextDecoder('utf-8', { fatal: false }).decode(joined), truncated }
}

function looksLikeJson(body: string): boolean {
  const t = body.trimStart()
  return t.startsWith('{') || t.startsWith('[')
}

function classifyFetchError(e: unknown, timeoutMs: number): ProbeTransportError {
  const err = e as { name?: string; message?: string; cause?: { message?: string; code?: string } } | undefined
  if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
    return new ProbeTransportError('timeout', `timed out after ${Math.round(timeoutMs / 1000)} s`)
  }
  if (err?.cause?.message === 'unexpected redirect') {
    return new ProbeTransportError('unexpected_response', 'the provider redirected; the redirect was not followed')
  }
  const detail = err?.cause?.code || err?.cause?.message || err?.message || 'request failed'
  return new ProbeTransportError('network', `could not reach the provider (${detail})`)
}

export interface ProbeFetchOptions {
  fetchImpl?: typeof fetch
  timeoutMs?: number
  maxBytes?: number
}

export async function probeFetch(req: ProbeRequest, opts: ProbeFetchOptions = {}): Promise<ProbeResponse> {
  const fetchImpl = opts.fetchImpl ?? fetch
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS
  const maxBytes = opts.maxBytes ?? MAX_BODY_BYTES
  const headers: Record<string, string> = { 'User-Agent': PROBE_USER_AGENT, ...(req.headers ?? {}) }
  for (const value of Object.values(headers)) {
    if (hasControlChars(value)) {
      throw new ProbeTransportError(
        'invalid_key',
        'the saved key contains a line break or control character, so it cannot be sent',
        true,
      )
    }
  }

  const started = Date.now()
  const signal = AbortSignal.timeout(timeoutMs)
  let res: Response
  try {
    res = await fetchImpl(req.url, {
      method: req.method,
      headers,
      body: req.body,
      redirect: 'error',
      signal,
      cache: 'no-store',
    })
  } catch (e) {
    throw classifyFetchError(e, timeoutMs)
  }

  let body: string
  let truncated: boolean
  try {
    ({ body, truncated } = await readCapped(res, maxBytes))
  } catch (e) {
    throw classifyFetchError(e, timeoutMs)
  }

  return {
    status: res.status,
    headers: pickHeaders(res.headers),
    json: looksLikeJson(body) && !truncated ? safeParse(body) : undefined,
    text: body.slice(0, TEXT_KEEP),
    contentType: (res.headers.get('content-type') ?? '').toLowerCase(),
    latencyMs: Date.now() - started,
    truncated,
  }
}

function safeParse(body: string): unknown {
  try {
    return JSON.parse(body)
  } catch {
    return undefined
  }
}
