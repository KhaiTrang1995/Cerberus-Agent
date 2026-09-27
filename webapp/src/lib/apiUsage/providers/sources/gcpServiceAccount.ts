/**
 * GCP service account (catalogue B5). The stored value is the key file (JSON);
 * the check is the OAuth JWT-bearer exchange Google's own libraries make: sign
 * an assertion with the file's private key and trade it for an access token.
 * Minting needs no IAM role and is not billed, and the token is thrown away
 * unused.
 *
 * The assertion always goes to Google's fixed token endpoint, never to the
 * file's own `token_uri`: the file is pasted by a user, and following it would
 * let a key file point the server at any URL (SSRF), carrying a signed assertion.
 */
import { signJwtBearerAssertion } from '../../sign/gcpJwt'
import { isPlainObject, str } from '../../parse'
import { body, errorResult, shapeError, statusError, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

const TOKEN_URL = 'https://oauth2.googleapis.com/token'
/** Read-only, since the token is never used; an empty scope is answered with invalid_scope. */
const SCOPE = 'https://www.googleapis.com/auth/cloud-platform.read-only'
const GOOGLE_TOKEN_HOSTS = new Set(['oauth2.googleapis.com', 'accounts.google.com', 'www.googleapis.com'])

export interface ServiceAccountKey {
  clientEmail: string
  privateKey: string
  privateKeyId?: string
  tokenUri: string
}

export type KeyFileParse = { ok: true; key: ServiceAccountKey } | { ok: false; reason: string }

/** Field names only in the reasons: nothing of the file's content is repeated. */
export function parseKeyFile(raw: string): KeyFileParse {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, reason: 'not a service-account key: the saved value is not JSON' }
  }
  if (!isPlainObject(parsed)) return { ok: false, reason: 'not a service-account key: the saved value is not a JSON object' }
  const v = parsed
  const missing = ['client_email', 'private_key', 'token_uri'].filter(f => !str(v[f]))
  if (missing.length) return { ok: false, reason: `not a service-account key: ${missing.join(', ')} missing` }
  return {
    ok: true,
    key: {
      clientEmail: str(v.client_email)!,
      privateKey: v.private_key as string,
      privateKeyId: str(v.private_key_id),
      tokenUri: str(v.token_uri)!,
    },
  }
}

export function isGoogleTokenUri(uri: string): boolean {
  try {
    const u = new URL(uri)
    return u.protocol === 'https:' && GOOGLE_TOKEN_HOSTS.has(u.hostname)
  } catch {
    return false
  }
}

/** Throws when the private key cannot sign (run() reports that without calling). */
export function request(key: ServiceAccountKey, now: Date): ProbeRequest {
  const assertion = signJwtBearerAssertion({
    issuer: key.clientEmail,
    scope: SCOPE,
    audience: TOKEN_URL,
    privateKeyPem: key.privateKey,
    keyId: key.privateKeyId,
    now,
  })
  return {
    method: 'POST',
    url: TOKEN_URL,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString(),
  }
}

/**
 * name@project.iam.gserviceaccount.com -> "name (project.iam.gserviceaccount.com)".
 * client_email names a robot account, not a person, but the report stores no
 * address-shaped string at all (the runner drops them), so it is reworded.
 */
export function serviceAccountLabel(clientEmail: string): string {
  const at = clientEmail.lastIndexOf('@')
  return at > 0 ? `${clientEmail.slice(0, at)} (${clientEmail.slice(at + 1)})` : clientEmail
}

export function parse(res: ProbeResponse, clientEmail: string): ProbeResult {
  const b = body(res)
  if (res.status === 200) {
    // The access token only proves the exchange worked: it is never copied.
    if (!str(b.access_token)) return shapeError(res)
    return validResult({ account: { label: serviceAccountLabel(clientEmail) } })
  }

  const code = str(b.error)
  const description = str(b.error_description) ?? ''
  const opts = { httpStatus: res.status, providerCode: code }
  if (code === 'invalid_grant') {
    if (/short-lived|reasonable timeframe/i.test(description)) {
      return errorResult('unexpected_response', `Google rejected the assertion's time window: this server's clock looks wrong (${description})`, opts)
    }
    if (/account not found/i.test(description)) {
      return errorResult('invalid_key', 'the service account no longer exists (Invalid grant: account not found)', opts)
    }
    if (/invalid jwt signature/i.test(description)) {
      return errorResult('invalid_key', 'Google rejected the key: it was deleted, disabled, or does not belong to this service account', opts)
    }
    return errorResult('invalid_key', description || 'invalid_grant', opts)
  }
  if (code === 'disabled_client') return errorResult('invalid_key', 'the service account is disabled', opts)
  if (code === 'invalid_client' || code === 'unauthorized_client') return errorResult('invalid_key', description || code, opts)
  // A scope Google refuses is a bug in this check, not in the key.
  if (code === 'invalid_scope') return errorResult('unexpected_response', `Google refused the requested scope (${description || code})`, opts)
  return statusError(res)
}

export const gcpProbe: ProbeDef = {
  id: 'gcp',
  service: 'gcp',
  label: 'GCP service account',
  group: 'sources',
  field: 'trufflehogGcpServiceAccount',
  kind: 'validity',
  costNote: 'Free: minting an access token needs no IAM role and is not billed; the token is discarded unused',
  docsUrl: 'https://developers.google.com/identity/protocols/oauth2/service-account',
  dashboardUrl: 'https://console.cloud.google.com/iam-admin/serviceaccounts',
  verifiedOn: null,
  endpoint: 'POST oauth2.googleapis.com/token',
  run: async ctx => {
    const parsed = parseKeyFile(ctx.key)
    if (!parsed.ok) return errorResult('unexpected_response', parsed.reason)
    let req: ProbeRequest
    try {
      req = request(parsed.key, ctx.now)
    } catch {
      return errorResult('unexpected_response', 'the private key in the service-account file cannot be read, so nothing was sent')
    }
    const result = parse(await ctx.http(req), parsed.key.clientEmail)
    if (isGoogleTokenUri(parsed.key.tokenUri)) return result
    return { ...result, notes: [...(result.notes ?? []), 'The key file names a different token endpoint; only Google\'s oauth2.googleapis.com is contacted'] }
  },
}
