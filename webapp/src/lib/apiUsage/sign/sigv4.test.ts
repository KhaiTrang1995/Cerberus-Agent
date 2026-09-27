/**
 * AWS Signature V4, pinned by published vectors: three cases of the AWS
 * aws-sig-v4-test-suite (credentials AKIDEXAMPLE /
 * wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, 2015-08-30 12:36:00Z, us-east-1,
 * service "service"; the expected strings are the suite's .creq / .sts / .authz
 * contents) and the signing-key example of the IAM "derive a signing key" docs.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { amzDate, sigV4, signAwsRequest, signingKey } from './sigv4'

const SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
const SUITE = {
  host: 'example.amazonaws.com',
  path: '/',
  region: 'us-east-1',
  service: 'service',
  accessKeyId: 'AKIDEXAMPLE',
  secretKey: SECRET,
  now: new Date('2015-08-30T12:36:00Z'),
}
const SCOPE = 'AKIDEXAMPLE/20150830/us-east-1/service/aws4_request'

describe('aws-sig-v4-test-suite: post-x-www-form-urlencoded', () => {
  const sig = sigV4({
    ...SUITE, method: 'POST', body: 'Param1=value1', contentType: 'application/x-www-form-urlencoded',
  })

  test('canonical request (.creq)', () => {
    expect(sig.canonicalRequest).toBe([
      'POST',
      '/',
      '',
      'content-type:application/x-www-form-urlencoded',
      'host:example.amazonaws.com',
      'x-amz-date:20150830T123600Z',
      '',
      'content-type;host;x-amz-date',
      '9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e',
    ].join('\n'))
  })

  test('string to sign (.sts)', () => {
    expect(sig.stringToSign).toBe([
      'AWS4-HMAC-SHA256',
      '20150830T123600Z',
      '20150830/us-east-1/service/aws4_request',
      '42a5e5bb34198acb3e84da4f085bb7927f2bc277ca766e6d19c73c2154021281',
    ].join('\n'))
  })

  test('Authorization header (.authz)', () => {
    expect(sig.signature).toBe('ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a')
    expect(sig.headers.Authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=${SCOPE}, SignedHeaders=content-type;host;x-amz-date, `
      + 'Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a',
    )
  })

  test('the headers to send: signed ones minus Host, never the secret', () => {
    expect(sig.headers).toEqual({
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Amz-Date': '20150830T123600Z',
      Authorization: expect.stringContaining('Signature=ff118979'),
    })
    expect(JSON.stringify(sig.headers)).not.toContain(SECRET)
  })

  test('header values are canonicalized (trimmed, spaces collapsed) before signing', () => {
    const padded = sigV4({
      ...SUITE, method: 'POST', body: 'Param1=value1', contentType: '  application/x-www-form-urlencoded ',
    })
    expect(padded.signature).toBe(sig.signature)
  })
})

describe('aws-sig-v4-test-suite: post-sts-token/post-sts-header-before', () => {
  // The suite's example session token, signed as a header (what STS requires).
  const TOKEN = 'AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=='
  const sig = sigV4({ ...SUITE, method: 'POST', body: '', sessionToken: TOKEN })

  test('the session token is a signed header', () => {
    expect(sig.signedHeaders).toBe('host;x-amz-date;x-amz-security-token')
    expect(sig.canonicalRequest).toContain(`\nx-amz-security-token:${TOKEN}\n`)
  })

  test('Authorization header (.authz)', () => {
    expect(sig.headers.Authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=${SCOPE}, SignedHeaders=host;x-amz-date;x-amz-security-token, `
      + 'Signature=85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead',
    )
  })

  test('the token is sent as X-Amz-Security-Token; no Content-Type when none is given', () => {
    expect(sig.headers).toEqual({
      'X-Amz-Date': '20150830T123600Z',
      'X-Amz-Security-Token': TOKEN,
      Authorization: expect.any(String),
    })
  })
})

describe('aws-sig-v4-test-suite: get-vanilla', () => {
  test('string to sign and signature', () => {
    const sig = sigV4({ ...SUITE, method: 'GET', body: '' })
    expect(sig.stringToSign.split('\n')[3]).toBe('bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63')
    expect(sig.signature).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31')
    expect(sig.signedHeaders).toBe('host;x-amz-date')
  })
})

describe('signingKey', () => {
  test('the IAM docs example (20120215 / us-east-1 / iam)', () => {
    expect(signingKey(SECRET, '20120215', 'us-east-1', 'iam').toString('hex'))
      .toBe('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d')
  })
})

describe('amzDate', () => {
  test('ISO time without separators or milliseconds', () => {
    expect(amzDate(new Date('2026-09-26T14:32:05.123Z'))).toBe('20260926T143205Z')
  })
})

describe('signAwsRequest', () => {
  test('returns exactly the headers of sigV4()', () => {
    const input = { ...SUITE, method: 'POST' as const, body: 'Param1=value1', contentType: 'application/x-www-form-urlencoded' }
    expect(signAwsRequest(input)).toEqual(sigV4(input).headers)
  })

  test('the region and service are part of the scope', () => {
    const h = signAwsRequest({ ...SUITE, method: 'POST', body: 'x', region: 'eu-west-1', service: 'sts' })
    expect(h.Authorization).toContain('Credential=AKIDEXAMPLE/20150830/eu-west-1/sts/aws4_request,')
  })
})
