/**
 * RS256 JWT-bearer assertion. The RSA key pair is generated inside the test run
 * and never written anywhere: no private key is committed.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { generateKeyPairSync, verify } from 'node:crypto'
import { ASSERTION_LIFETIME_SEC, base64url, signJwtBearerAssertion } from './gcpJwt'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const PRIVATE_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
const NOW = new Date('2026-09-26T14:32:05.900Z')
const INPUT = {
  issuer: 'scanner@example.test',
  scope: 'https://www.googleapis.com/auth/cloud-platform.read-only',
  audience: 'https://oauth2.googleapis.com/token',
  privateKeyPem: PRIVATE_PEM,
  keyId: 'TESTKEY-0000-gcp-key-id',
  now: NOW,
}

function decode(part: string): unknown {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
}

describe('signJwtBearerAssertion', () => {
  const jwt = signJwtBearerAssertion(INPUT)
  const [h, c, s] = jwt.split('.')

  test('three base64url segments, no padding and no +/ characters', () => {
    expect(jwt.split('.')).toHaveLength(3)
    for (const part of [h, c, s]) expect(part).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  test('header: RS256, JWT, and the key id as kid', () => {
    expect(Buffer.from(h, 'base64url').toString('utf8')).toBe('{"alg":"RS256","typ":"JWT","kid":"TESTKEY-0000-gcp-key-id"}')
  })

  test('claims: iss, scope, aud, iat = now in whole seconds, exp one hour later', () => {
    const iat = Math.floor(NOW.getTime() / 1000)
    expect(decode(c)).toEqual({
      iss: 'scanner@example.test',
      scope: 'https://www.googleapis.com/auth/cloud-platform.read-only',
      aud: 'https://oauth2.googleapis.com/token',
      iat,
      exp: iat + 3600,
    })
    expect(ASSERTION_LIFETIME_SEC).toBe(3600)
  })

  test('the signature verifies with the public key (RSA-SHA256 over header.claims)', () => {
    expect(verify('RSA-SHA256', Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, 'base64url'))).toBe(true)
  })

  test('a tampered claim set no longer verifies', () => {
    const forged = base64url(JSON.stringify({ ...(decode(c) as object), iss: 'someone-else@example.test' }))
    expect(verify('RSA-SHA256', Buffer.from(`${h}.${forged}`), publicKey, Buffer.from(s, 'base64url'))).toBe(false)
  })

  test('deterministic for one key and one clock', () => {
    expect(signJwtBearerAssertion(INPUT)).toBe(jwt)
  })

  test('no kid when the key file has no private_key_id', () => {
    const [header] = signJwtBearerAssertion({ ...INPUT, keyId: undefined }).split('.')
    expect(decode(header)).toEqual({ alg: 'RS256', typ: 'JWT' })
  })

  test('a PKCS#1 PEM signs too', () => {
    const pkcs1 = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()
    const [ph, pc, ps] = signJwtBearerAssertion({ ...INPUT, privateKeyPem: pkcs1 }).split('.')
    expect(verify('RSA-SHA256', Buffer.from(`${ph}.${pc}`), publicKey, Buffer.from(ps, 'base64url'))).toBe(true)
  })

  test('an unusable PEM throws (the probe turns that into a result)', () => {
    expect(() => signJwtBearerAssertion({ ...INPUT, privateKeyPem: '-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n' })).toThrow()
  })
})

describe('base64url', () => {
  test('URL alphabet and no padding', () => {
    expect(base64url('>>>???')).toBe('Pj4-Pz8_')
    expect(base64url('a')).toBe('YQ')
  })
})
