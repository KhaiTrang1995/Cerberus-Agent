/**
 * GCP service-account probe (catalogue B5). The key file is synthetic and its
 * RSA key pair is generated inside the test run: no private key is committed.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { generateKeyPairSync, verify } from 'node:crypto'
import { gcpProbe, isGoogleTokenUri, parse, parseKeyFile, request, serviceAccountLabel } from './gcpServiceAccount'
import { signJwtBearerAssertion } from '../../sign/gcpJwt'
import { NOW, html, res, runProbe, allStrings } from '../../testUtils'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
const KEY_ID = 'TESTKEY-0000-gcp-private-key-id'
const CLIENT_EMAIL = 'scanner@example.test'
const TOKEN_URL = 'https://oauth2.googleapis.com/token'
const ACCESS_TOKEN = 'ya29.TESTKEY-0000-gcp-access-token'

const KEY_FILE = {
  type: 'service_account',
  project_id: 'example-project',
  private_key_id: KEY_ID,
  private_key: PEM,
  client_email: CLIENT_EMAIL,
  client_id: '000000000000000000000',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: TOKEN_URL,
  universe_domain: 'googleapis.com',
}
const RAW = JSON.stringify(KEY_FILE, null, 2)
const PARSED = { clientEmail: CLIENT_EMAIL, privateKey: PEM, privateKeyId: KEY_ID, tokenUri: TOKEN_URL }

const MINTED = { access_token: ACCESS_TOKEN, scope: 'https://www.googleapis.com/auth/cloud-platform.read-only', token_type: 'Bearer', expires_in: 3599 }

function assertionOf(body: string | undefined): string {
  return new URLSearchParams(body ?? '').get('assertion') ?? ''
}

function claimsOf(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'))
}

function tokenError(error: string, description?: string) {
  return res(400, description ? { error, error_description: description } : { error })
}

describe('parseKeyFile', () => {
  test('a key file -> the four fields the check needs', () => {
    expect(parseKeyFile(RAW)).toEqual({ ok: true, key: PARSED })
  })

  test('not JSON, not an object, or missing fields -> "not a service-account key", content never repeated', () => {
    expect(parseKeyFile('{"client_email": "x"')).toEqual({ ok: false, reason: 'not a service-account key: the saved value is not JSON' })
    expect(parseKeyFile('["a"]')).toMatchObject({ ok: false })
    const noKey = parseKeyFile(JSON.stringify({ ...KEY_FILE, private_key: undefined, token_uri: '' }))
    expect(noKey).toEqual({ ok: false, reason: 'not a service-account key: private_key, token_uri missing' })
  })

  test('an authorized_user file (no client_email / private_key) is not a service-account key', () => {
    const r = parseKeyFile(JSON.stringify({ type: 'authorized_user', client_id: 'x', client_secret: 'TESTKEY-0000-y', refresh_token: 'z' }))
    expect(r).toEqual({ ok: false, reason: 'not a service-account key: client_email, private_key, token_uri missing' })
  })
})

describe('request', () => {
  const req = request(PARSED, NOW)

  test('POST the fixed Google token URL, form-encoded jwt-bearer grant', () => {
    const jwt = signJwtBearerAssertion({
      issuer: CLIENT_EMAIL, scope: 'https://www.googleapis.com/auth/cloud-platform.read-only',
      audience: TOKEN_URL, privateKeyPem: PEM, keyId: KEY_ID, now: NOW,
    })
    expect(req).toEqual({
      method: 'POST',
      url: TOKEN_URL,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
    })
  })

  test('the assertion: kid = private_key_id, the catalogue claims, signed by the file\'s key', () => {
    const jwt = assertionOf(req.body)
    const [h, c, s] = jwt.split('.')
    expect(JSON.parse(Buffer.from(h, 'base64url').toString('utf8'))).toEqual({ alg: 'RS256', typ: 'JWT', kid: KEY_ID })
    const iat = Math.floor(NOW.getTime() / 1000)
    expect(claimsOf(jwt)).toEqual({
      iss: CLIENT_EMAIL, scope: 'https://www.googleapis.com/auth/cloud-platform.read-only', aud: TOKEN_URL, iat, exp: iat + 3600,
    })
    expect(verify('RSA-SHA256', Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, 'base64url'))).toBe(true)
  })

  test('the private key is never sent, only a signature made with it', () => {
    expect(allStrings(req).some(v => v.includes(PEM) || v.includes('PRIVATE KEY'))).toBe(false)
  })
})

describe('never the key file\'s token_uri (SSRF)', () => {
  test.each([
    'http://169.254.169.254/computeMetadata/v1/',
    'https://internal.example.test/token',
    'not a url',
  ])('token_uri %j: the request still goes to oauth2.googleapis.com, and the row says so', async uri => {
    const { result, requests } = await runProbe(gcpProbe, JSON.stringify({ ...KEY_FILE, token_uri: uri }), [res(200, MINTED)])
    expect(requests).toHaveLength(1)
    expect(requests[0].url).toBe(TOKEN_URL)
    expect(claimsOf(assertionOf(requests[0].body)).aud).toBe(TOKEN_URL)
    expect(result.outcome).toBe('valid_no_usage')
    expect(result.notes).toEqual(["The key file names a different token endpoint; only Google's oauth2.googleapis.com is contacted"])
  })

  test('Google\'s own token endpoints add no note', () => {
    expect(isGoogleTokenUri(TOKEN_URL)).toBe(true)
    expect(isGoogleTokenUri('https://accounts.google.com/o/oauth2/token')).toBe(true)
    expect(isGoogleTokenUri('http://oauth2.googleapis.com/token')).toBe(false)
    expect(isGoogleTokenUri('https://oauth2.googleapis.com.evil.test/token')).toBe(false)
  })
})

describe('parse: success', () => {
  test('200 -> valid, the service account id as label, the access token dropped', () => {
    const r = parse(res(200, MINTED), CLIENT_EMAIL)
    expect(r).toEqual({ outcome: 'valid_no_usage', meters: [], account: { label: serviceAccountLabel(CLIENT_EMAIL) } })
    expect(allStrings(r).some(s => s.includes(ACCESS_TOKEN))).toBe(false)
  })

  test('a 200 without an access token -> unexpected_response', () => {
    expect(parse(res(200, { token_type: 'Bearer' }), CLIENT_EMAIL).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), CLIENT_EMAIL).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: the catalogue error table', () => {
  test('invalid_grant "account not found" -> invalid_key', () => {
    expect(parse(tokenError('invalid_grant', 'Invalid grant: account not found'), CLIENT_EMAIL).error)
      .toMatchObject({ kind: 'invalid_key', httpStatus: 400, providerCode: 'invalid_grant' })
  })

  test('invalid_grant "Invalid JWT Signature." -> invalid_key', () => {
    const r = parse(tokenError('invalid_grant', 'Invalid JWT Signature.'), CLIENT_EMAIL)
    expect(r.error?.kind).toBe('invalid_key')
    expect(r.error?.message).toMatch(/deleted, disabled/)
  })

  test('invalid_grant "short-lived token" is clock skew -> unexpected_response', () => {
    const r = parse(tokenError('invalid_grant', 'Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe. Check your iat and exp values in the JWT claim.'), CLIENT_EMAIL)
    expect(r.error?.kind).toBe('unexpected_response')
    expect(r.error?.message).toMatch(/clock/)
  })

  test('disabled_client -> invalid_key "service account disabled"', () => {
    expect(parse(tokenError('disabled_client', 'The OAuth client was disabled.'), CLIENT_EMAIL).error)
      .toMatchObject({ kind: 'invalid_key', message: 'the service account is disabled', providerCode: 'disabled_client' })
  })

  test('invalid_scope is this check\'s bug -> unexpected_response', () => {
    expect(parse(tokenError('invalid_scope', 'Invalid OAuth scope or ID token audience provided.'), CLIENT_EMAIL).error?.kind).toBe('unexpected_response')
  })

  test('any other invalid_grant -> invalid_key with Google\'s description', () => {
    expect(parse(tokenError('invalid_grant', 'Invalid email or User ID'), CLIENT_EMAIL).error)
      .toMatchObject({ kind: 'invalid_key', message: 'Invalid email or User ID' })
  })

  test('429 -> rate_limited; 5xx page -> provider_error', () => {
    expect(parse(res(429, { error: 'rate_limit_exceeded' }), CLIENT_EMAIL).error?.kind).toBe('rate_limited')
    expect(parse(html(503), CLIENT_EMAIL).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; nothing secret reaches the result', async () => {
    const { result, requests } = await runProbe(gcpProbe, RAW, [res(200, MINTED)])
    expect(requests).toHaveLength(1)
    expect(result).toEqual({ outcome: 'valid_no_usage', meters: [], account: { label: serviceAccountLabel(CLIENT_EMAIL) } })
    const jwt = assertionOf(requests[0].body)
    const pemLine = PEM.split('\n')[1]
    for (const secret of [RAW, PEM, pemLine, KEY_ID, jwt, ACCESS_TOKEN]) {
      expect(allStrings(result).some(s => s.includes(secret))).toBe(false)
    }
  })

  test('a file that is not a service-account key: nothing is called', async () => {
    const { result, requests } = await runProbe(gcpProbe, '{"type":"service_account"}', [])
    expect(requests).toHaveLength(0)
    expect(result.error?.kind).toBe('unexpected_response')
    expect(result.error?.message).toMatch(/^not a service-account key/)
  })

  test('an unreadable private key: nothing is called, the key is not echoed', async () => {
    const broken = JSON.stringify({ ...KEY_FILE, private_key: '-----BEGIN PRIVATE KEY-----\nTESTKEY-0000-garbage\n-----END PRIVATE KEY-----\n' })
    const { result, requests } = await runProbe(gcpProbe, broken, [])
    expect(requests).toHaveLength(0)
    expect(result.error).toMatchObject({ kind: 'unexpected_response' })
    expect(allStrings(result).some(s => s.includes('TESTKEY-0000-garbage'))).toBe(false)
  })

  test('registry contract', () => {
    expect(gcpProbe).toMatchObject({ id: 'gcp', group: 'sources', field: 'trufflehogGcpServiceAccount', kind: 'validity', verifiedOn: null })
  })
})

describe('serviceAccountLabel', () => {
  test('keeps the robot identity without the address form the report never stores', () => {
    expect(serviceAccountLabel('scanner@acme-prod.iam.gserviceaccount.com')).toBe('scanner (acme-prod.iam.gserviceaccount.com)')
    expect(serviceAccountLabel('no-at-sign')).toBe('no-at-sign')
  })
})
