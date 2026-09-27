/**
 * The RS256 JWT-bearer assertion (RFC 7523) a Google service account trades for
 * an access token: the same exchange Google's own client libraries make.
 * node:crypto only; RSASSA-PKCS1-v1_5 is deterministic, so one key and one
 * clock always give the same assertion.
 */
import { sign } from 'node:crypto'

/** Google refuses an assertion that lives longer than one hour. */
export const ASSERTION_LIFETIME_SEC = 3600

export interface JwtBearerInput {
  /** The service account's client_email. */
  issuer: string
  /** Never empty: Google answers an empty scope with invalid_scope. */
  scope: string
  audience: string
  /** The key file's private_key (PEM). */
  privateKeyPem: string
  /** The key file's private_key_id: tells Google which of the account's keys signed. */
  keyId?: string
  now: Date
}

/** Base64url without padding, as JWS requires. */
export function base64url(data: string | Buffer): string {
  return Buffer.from(data).toString('base64url')
}

/** Throws when the PEM is not a usable RSA private key. */
export function signJwtBearerAssertion(input: JwtBearerInput): string {
  const header = { alg: 'RS256', typ: 'JWT', ...(input.keyId ? { kid: input.keyId } : {}) }
  const iat = Math.floor(input.now.getTime() / 1000)
  const claims = { iss: input.issuer, scope: input.scope, aud: input.audience, iat, exp: iat + ASSERTION_LIFETIME_SEC }
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`
  const signature = sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), input.privateKeyPem)
  return `${signingInput}.${base64url(signature)}`
}
