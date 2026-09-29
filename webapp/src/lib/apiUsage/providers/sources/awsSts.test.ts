/**
 * AWS access key probe (catalogue B4): STS GetCallerIdentity, SigV4-signed.
 * Synthetic fixtures; the credentials are fake.
 *
 * @vitest-environment node
 */
import { afterEach, describe, test, expect, vi } from 'vitest'
import {
  awsError, awsProbe, hideEmails, isValidAwsRegion, parseCallerIdentity, stsGetCallerIdentity, stsRequest,
} from './awsSts'
import { sigV4 } from '../../sign/sigv4'
import { NOW, html, res, runProbe, allStrings } from '../../testUtils'
import type { ProbeRequest, ProbeResponse } from '../../types'

const AKID = 'AKIDEXAMPLE0000TEST1'
const SECRET = 'TESTKEY-0000-aws-secret-access-key-0000000'
const TOKEN = 'TESTKEY-0000-aws-session-token-0000'
const CREDS = { accessKeyId: AKID, secretKey: SECRET }
const COMPANIONS = { trufflehogAwsSecretKey: SECRET, trufflehogAwsSessionToken: '' }
const BODY = 'Action=GetCallerIdentity&Version=2011-06-15'

const IDENTITY = {
  GetCallerIdentityResponse: {
    GetCallerIdentityResult: {
      Account: '000000000000',
      Arn: 'arn:aws:iam::000000000000:user/redamon-scanner',
      UserId: 'AIDAEXAMPLE0000TEST1',
    },
    ResponseMetadata: { RequestId: '00000000-0000-0000-0000-000000000000' },
  },
}

function stsError(status: number, code: string, message: string): ProbeResponse {
  return res(status, { Error: { Code: code, Message: message, Type: 'Sender' }, RequestId: '00000000-0000-0000-0000-000000000000' })
}

afterEach(() => {
  vi.useRealTimers()
})

describe('stsRequest', () => {
  test('global endpoint: POST form body, SigV4 for us-east-1/sts, JSON asked for', () => {
    const r = stsRequest(CREDS, undefined, NOW)
    expect(r.method).toBe('POST')
    expect(r.url).toBe('https://sts.amazonaws.com/')
    expect(r.body).toBe(BODY)
    expect(r.headers).toEqual({
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Amz-Date': '20260926T143205Z',
      Accept: 'application/json',
      Authorization: expect.stringMatching(
        /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE0000TEST1\/20260926\/us-east-1\/sts\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/,
      ),
    })
  })

  test('the signature is the one SigV4 computes for exactly this host, body and time', () => {
    const expected = sigV4({
      method: 'POST', host: 'sts.amazonaws.com', path: '/', region: 'us-east-1', service: 'sts',
      body: BODY, contentType: 'application/x-www-form-urlencoded', accessKeyId: AKID, secretKey: SECRET, now: NOW,
    })
    expect(stsRequest(CREDS, undefined, NOW).headers?.Authorization).toBe(expected.headers.Authorization)
  })

  test('a session token is sent and signed', () => {
    const r = stsRequest({ ...CREDS, sessionToken: TOKEN }, undefined, NOW)
    expect(r.headers?.['X-Amz-Security-Token']).toBe(TOKEN)
    expect(r.headers?.Authorization).toContain('SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,')
  })

  test('an empty session token is not sent', () => {
    expect(stsRequest({ ...CREDS, sessionToken: '' }, undefined, NOW).headers).not.toHaveProperty('X-Amz-Security-Token')
  })

  test('a region selects its regional endpoint and signing scope', () => {
    const r = stsRequest(CREDS, 'eu-west-1', NOW)
    expect(r.url).toBe('https://sts.eu-west-1.amazonaws.com/')
    expect(r.headers?.Authorization).toContain('Credential=AKIDEXAMPLE0000TEST1/20260926/eu-west-1/sts/aws4_request,')
  })

  test('the secret key is never sent', () => {
    const r = stsRequest({ ...CREDS, sessionToken: TOKEN }, 'us-west-2', NOW)
    expect(allStrings(r).some(s => s.includes(SECRET))).toBe(false)
  })

  test('an invalid region never becomes a URL', () => {
    expect(() => stsRequest(CREDS, 'us-east-1.evil.test#', NOW)).toThrow(/invalid AWS region/)
  })
})

describe('isValidAwsRegion', () => {
  test.each(['us-east-1', 'eu-central-2', 'ap-southeast-7', 'us-gov-west-1', 'cn-northwest-1', 'us-isob-east-1'])('%s passes', r => {
    expect(isValidAwsRegion(r)).toBe(true)
  })

  test.each([
    '', 'us-east-1.evil.test#', 'x/..', 'us-east-1/', ' us-east-1', 'us-east-1\n', 'US-EAST-1',
    'us-east-1a', 'localhost', '169.254.169.254', 'us-east-1@evil.test', 'us-east',
  ])('%j is refused', r => {
    expect(isValidAwsRegion(r)).toBe(false)
  })
})

describe('parseCallerIdentity: success', () => {
  test('JSON answer -> valid, the ARN as label, no meters', () => {
    expect(parseCallerIdentity(res(200, IDENTITY))).toEqual({
      outcome: 'valid_no_usage',
      meters: [],
      account: { label: 'arn:aws:iam::000000000000:user/redamon-scanner' },
    })
  })

  test('the native XML answer is read too', () => {
    const xml = '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>'
      + '<Arn>arn:aws:iam::000000000000:user/redamon-scanner</Arn><UserId>AIDAEXAMPLE0000TEST1</UserId><Account>000000000000</Account>'
      + '</GetCallerIdentityResult></GetCallerIdentityResponse>'
    expect(parseCallerIdentity(res(200, xml, { contentType: 'text/xml' })).account?.label)
      .toBe('arn:aws:iam::000000000000:user/redamon-scanner')
  })

  test('an SSO session name (an email address) is hidden from the label', () => {
    const arn = 'arn:aws:sts::000000000000:assumed-role/AWSReservedSSO_Admin_0000/alice@example.test'
    const r = parseCallerIdentity(res(200, { GetCallerIdentityResponse: { GetCallerIdentityResult: { Arn: arn } } }))
    expect(r.account?.label).toBe('arn:aws:sts::000000000000:assumed-role/AWSReservedSSO_Admin_0000/(email hidden)')
    expect(allStrings(r).join(' ')).not.toContain('@example.test')
  })

  test('a 200 without an ARN -> unexpected_response', () => {
    expect(parseCallerIdentity(res(200, { GetCallerIdentityResponse: {} })).error?.kind).toBe('unexpected_response')
    expect(parseCallerIdentity(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parseCallerIdentity: the catalogue error table', () => {
  test('InvalidClientTokenId -> invalid_key', () => {
    const r = parseCallerIdentity(stsError(403, 'InvalidClientTokenId', 'The security token included in the request is invalid.'))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 403, providerCode: 'InvalidClientTokenId' })
  })

  test('SignatureDoesNotMatch -> invalid_key "secret does not match"', () => {
    const r = parseCallerIdentity(stsError(403, 'SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided.'))
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'SignatureDoesNotMatch' })
    expect(r.error?.message).toMatch(/secret access key does not match/)
  })

  test('SignatureDoesNotMatch "Signature expired" is the clock, not the key', () => {
    const r = parseCallerIdentity(stsError(403, 'SignatureDoesNotMatch', 'Signature expired: 20260926T142000Z is now earlier than 20260926T142705Z (20260926T143205Z - 5 min.)'))
    expect(r.error).toMatchObject({ kind: 'unexpected_response', providerCode: 'SignatureDoesNotMatch' })
    expect(r.error?.message).toMatch(/clock/)
  })

  test('ExpiredToken -> invalid_key "session token expired"', () => {
    const r = parseCallerIdentity(stsError(403, 'ExpiredToken', 'The security token included in the request is expired'))
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'ExpiredToken' })
    expect(r.error?.message).toMatch(/session token has expired/)
  })

  test('AccessDenied still proves the key -> valid, with a note', () => {
    const r = parseCallerIdentity(stsError(403, 'AccessDenied', 'User: arn:aws:iam::000000000000:user/x is not authorized to perform: sts:GetCallerIdentity'))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.error).toBeUndefined()
    expect(r.notes?.[0]).toMatch(/denies GetCallerIdentity/)
  })

  test('400 IncompleteSignature / ValidationError -> unexpected_response', () => {
    expect(parseCallerIdentity(stsError(400, 'IncompleteSignature', "Authorization header requires 'Credential' parameter.")).error)
      .toMatchObject({ kind: 'unexpected_response', httpStatus: 400, providerCode: 'IncompleteSignature' })
    expect(parseCallerIdentity(stsError(400, 'ValidationError', 'bad request')).error?.kind).toBe('unexpected_response')
  })

  test('Throttling -> rate_limited', () => {
    expect(parseCallerIdentity(stsError(400, 'Throttling', 'Rate exceeded')).error?.kind).toBe('rate_limited')
  })

  test('an XML error envelope is read like the JSON one', () => {
    const xml = '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type>'
      + '<Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message>'
      + '</Error><RequestId>0</RequestId></ErrorResponse>'
    const x = res(403, xml, { contentType: 'text/xml' })
    expect(awsError(x)).toEqual({ code: 'InvalidClientTokenId', message: 'The security token included in the request is invalid.' })
    expect(parseCallerIdentity(x).error?.kind).toBe('invalid_key')
  })

  test('an unknown 403 code keeps the default mapping with the AWS message', () => {
    const r = parseCallerIdentity(stsError(403, 'RegionDisabledException', 'STS is not activated in this region for account:000000000000.'))
    expect(r.error).toMatchObject({ kind: 'forbidden', providerCode: 'RegionDisabledException' })
    expect(r.error?.message).toMatch(/not activated/)
  })

  test('5xx page -> provider_error', () => {
    expect(parseCallerIdentity(html(503)).error?.kind).toBe('provider_error')
  })
})

describe('stsGetCallerIdentity: the SignatureDoesNotMatch retry', () => {
  function recorder(responses: ProbeResponse[]) {
    const requests: ProbeRequest[] = []
    const http = async (r: ProbeRequest) => {
      requests.push(r)
      const next = responses.shift()
      if (!next) throw new Error('unexpected extra request')
      return next
    }
    return { http, requests }
  }

  test('retried once, re-signed at the current time; a second mismatch -> invalid_key', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-09-26T14:32:09Z'))
    const mismatch = () => stsError(403, 'SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided.')
    const { http, requests } = recorder([mismatch(), mismatch()])
    const r = await stsGetCallerIdentity(http, CREDS, undefined, NOW)
    expect(requests).toHaveLength(2)
    expect(requests[0].headers?.['X-Amz-Date']).toBe('20260926T143205Z')
    expect(requests[1].headers?.['X-Amz-Date']).toBe('20260926T143209Z')
    expect(requests[1].headers?.Authorization).toBe(stsRequest(CREDS, undefined, new Date('2026-09-26T14:32:09Z')).headers?.Authorization)
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'SignatureDoesNotMatch' })
  })

  test('a mismatch that the retry cures -> valid', async () => {
    const { http, requests } = recorder([
      stsError(403, 'SignatureDoesNotMatch', 'Signature expired: 20260926T142000Z is now earlier than 20260926T142705Z'),
      res(200, IDENTITY),
    ])
    const r = await stsGetCallerIdentity(http, CREDS, undefined, NOW)
    expect(requests).toHaveLength(2)
    expect(r.outcome).toBe('valid_no_usage')
  })

  test('no retry for any other error', async () => {
    const { http, requests } = recorder([stsError(403, 'InvalidClientTokenId', 'invalid')])
    await stsGetCallerIdentity(http, CREDS, undefined, NOW)
    expect(requests).toHaveLength(1)
  })

  test('an invalid region makes no request at all', async () => {
    const { http, requests } = recorder([])
    const r = await stsGetCallerIdentity(http, CREDS, 'x/..', NOW)
    expect(requests).toHaveLength(0)
    expect(r.error).toMatchObject({ kind: 'unexpected_response' })
    expect(r.error?.message).toMatch(/invalid AWS region/)
  })
})

describe('awsProbe', () => {
  test('one call to the global endpoint; no credential in the result', async () => {
    const { result, requests } = await runProbe(awsProbe, AKID, [res(200, IDENTITY)], { ...COMPANIONS, trufflehogAwsSessionToken: TOKEN })
    expect(requests).toHaveLength(1)
    expect(requests[0].url).toBe('https://sts.amazonaws.com/')
    expect(requests[0].headers?.['X-Amz-Security-Token']).toBe(TOKEN)
    expect(result.outcome).toBe('valid_no_usage')
    const strings = allStrings(result)
    for (const secret of [AKID, SECRET, TOKEN]) expect(strings.some(s => s.includes(secret))).toBe(false)
  })

  test('the error rows never carry a credential either', async () => {
    const { result } = await runProbe(awsProbe, AKID, [stsError(403, 'InvalidClientTokenId', `The security token included in the request is invalid: ${TOKEN}`)], COMPANIONS)
    expect(allStrings(result).some(s => s.includes(TOKEN) || s.includes(SECRET))).toBe(false)
  })

  test('without the secret key nothing is called', async () => {
    const { result, requests } = await runProbe(awsProbe, AKID, [], { trufflehogAwsSecretKey: '', trufflehogAwsSessionToken: '' })
    expect(requests).toHaveLength(0)
    expect(result).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'companion_missing' })
  })

  test('registry contract: the secret is a required companion, the token optional, a lone secret is reported', () => {
    expect(awsProbe).toMatchObject({
      id: 'aws', group: 'sources', kind: 'validity', field: 'trufflehogAwsAccessKeyId', reportLoneCompanion: true, verifiedOn: null,
      companions: [
        { field: 'trufflehogAwsSecretKey', required: true },
        { field: 'trufflehogAwsSessionToken', required: false },
      ],
    })
  })
})

describe('hideEmails', () => {
  test('hides address-shaped segments only', () => {
    expect(hideEmails('arn:aws:iam::000000000000:user/ci-bot')).toBe('arn:aws:iam::000000000000:user/ci-bot')
    expect(hideEmails('a/b.c@example.test')).toBe('a/(email hidden)')
  })
})
