/**
 * AWS Bedrock probe (catalogue C11): API-key mode (bearer) and IAM mode (STS),
 * plus the region check that keeps a stored region from steering a request to
 * another host. Synthetic fixtures; the credentials are fake.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { apiKeyRequest, bedrockErrorCode, bedrockProbe, IAM_NOTE, parseApiKey } from './bedrock'
import { html, res, runProbe, allStrings } from '../../testUtils'

const BEARER = 'TESTKEY-0000-bedrock-api-key-0000'
const AKID = 'AKIDEXAMPLE0000TEST2'
const SECRET = 'TESTKEY-0000-bedrock-secret-key-000000000'
const UNUSED_API_KEY = 'TESTKEY-0000-unused-apikey-column'

function companions(overrides: Record<string, string> = {}): Record<string, string> {
  return { baseUrl: '', awsRegion: 'us-west-2', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', ...overrides }
}

const MODELS = {
  modelSummaries: [{
    modelArn: 'arn:aws:bedrock:us-west-2::foundation-model/example.model-v1:0',
    modelId: 'example.model-v1:0', modelName: 'Example', providerName: 'Example',
  }],
}

const IDENTITY = {
  GetCallerIdentityResponse: {
    GetCallerIdentityResult: { Account: '000000000000', Arn: 'arn:aws:iam::000000000000:user/bedrock-agent', UserId: 'AIDAEXAMPLE0000TEST2' },
  },
}

function denied(status: number, type: string, message: string) {
  return res(status, { message }, { headers: { 'x-amzn-ErrorType': `${type}:http://internal.amazon.com/coral/com.amazon.coral.service/` } })
}

describe('API-key mode', () => {
  test('GET the region\'s foundation-models with the key as a Bearer token, and nothing else', async () => {
    const { result, requests } = await runProbe(bedrockProbe, UNUSED_API_KEY, [res(200, MODELS)], companions({ awsBearerToken: BEARER }))
    expect(requests).toEqual([{
      method: 'GET',
      url: 'https://bedrock.us-west-2.amazonaws.com/foundation-models',
      headers: { Authorization: `Bearer ${BEARER}` },
    }])
    expect(result).toEqual({ outcome: 'valid_no_usage', meters: [], notes: ['Bedrock API key accepted in us-west-2'] })
    expect(allStrings(result).some(s => s.includes(BEARER))).toBe(false)
  })

  test('the API key wins over a saved IAM pair, as in the agent', async () => {
    const { requests } = await runProbe(bedrockProbe, '', [res(200, MODELS)], companions({ awsBearerToken: BEARER, awsAccessKeyId: AKID, awsSecretKey: SECRET }))
    expect(requests).toHaveLength(1)
    expect(requests[0].url).toBe('https://bedrock.us-west-2.amazonaws.com/foundation-models')
    expect(allStrings(requests).some(s => s.includes(SECRET) || s.includes(AKID))).toBe(false)
  })

  test('the row\'s apiKey column is never sent', async () => {
    const { requests } = await runProbe(bedrockProbe, UNUSED_API_KEY, [res(200, MODELS)], companions({ awsBearerToken: BEARER }))
    expect(allStrings(requests).some(s => s.includes(UNUSED_API_KEY))).toBe(false)
  })
})

describe('parseApiKey', () => {
  test('a model list too long to read in full still proves the key', () => {
    const cut = { ...res(200, '{"modelSummaries":[{"modelArn":"arn:aws:bedrock:us-west-2::foundation-model/x"'), truncated: true }
    expect(parseApiKey(cut, 'us-west-2').outcome).toBe('valid_no_usage')
  })

  test('a 200 without modelSummaries -> unexpected_response', () => {
    expect(parseApiKey(res(200, { hello: 'world' }), 'us-west-2').error?.kind).toBe('unexpected_response')
    expect(parseApiKey(html(200), 'us-west-2').error?.kind).toBe('unexpected_response')
  })

  test('403 "Authorization header is missing" -> invalid_key', () => {
    const r = parseApiKey(res(403, { message: 'Authorization header is missing' }), 'us-west-2')
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 403, message: 'Authorization header is missing' })
  })

  test('403 "Invalid API Key format" (capital-M Message) -> invalid_key', () => {
    const r = parseApiKey(res(403, { Message: 'Invalid API Key format: Must start with pre-defined prefix' }), 'us-west-2')
    expect(r.error).toMatchObject({ kind: 'invalid_key', message: 'Invalid API Key format: Must start with pre-defined prefix' })
  })

  test('403 UnrecognizedClientException -> invalid_key with the code from x-amzn-ErrorType', () => {
    const r = parseApiKey(denied(403, 'UnrecognizedClientException', 'The security token included in the request is invalid.'), 'us-west-2')
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'UnrecognizedClientException' })
  })

  test('403 ExpiredTokenException -> invalid_key', () => {
    expect(parseApiKey(denied(403, 'ExpiredTokenException', 'The security token included in the request is expired'), 'us-west-2').error)
      .toMatchObject({ kind: 'invalid_key', providerCode: 'ExpiredTokenException' })
  })

  test('403 AccessDeniedException -> forbidden (valid credentials, no permission)', () => {
    const r = parseApiKey(denied(403, 'AccessDeniedException', 'User: arn:aws:iam::000000000000:user/BedrockAPIKey-0000 is not authorized to perform: bedrock:ListFoundationModels'), 'us-west-2')
    expect(r.error).toMatchObject({ kind: 'forbidden', providerCode: 'AccessDeniedException' })
  })

  test('an email in a denial message is hidden', () => {
    const r = parseApiKey(denied(403, 'AccessDeniedException', 'User: arn:aws:sts::000000000000:assumed-role/R/alice@example.test is not authorized'), 'us-west-2')
    expect(allStrings(r).join(' ')).not.toContain('@example.test')
  })

  test('429 ThrottlingException -> rate_limited', () => {
    expect(parseApiKey(denied(429, 'ThrottlingException', 'Too many requests'), 'us-west-2').error?.kind).toBe('rate_limited')
  })

  test('5xx -> provider_error', () => {
    expect(parseApiKey(html(503), 'us-west-2').error?.kind).toBe('provider_error')
  })

  test('bedrockErrorCode splits the header on ":"', () => {
    expect(bedrockErrorCode(denied(403, 'AccessDeniedException', 'x'))).toBe('AccessDeniedException')
    expect(bedrockErrorCode(res(403, { message: 'x' }))).toBeUndefined()
  })
})

describe('IAM mode', () => {
  test('STS GetCallerIdentity at the region\'s endpoint, signed for that region; valid with the note', async () => {
    const { result, requests } = await runProbe(bedrockProbe, '', [res(200, IDENTITY)], companions({ awsRegion: 'eu-central-1', awsAccessKeyId: AKID, awsSecretKey: SECRET }))
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ method: 'POST', url: 'https://sts.eu-central-1.amazonaws.com/', body: 'Action=GetCallerIdentity&Version=2011-06-15' })
    expect(requests[0].headers?.Authorization).toContain(`Credential=${AKID}/20260926/eu-central-1/sts/aws4_request,`)
    expect(result).toEqual({
      outcome: 'valid_no_usage',
      meters: [],
      account: { label: 'arn:aws:iam::000000000000:user/bedrock-agent' },
      notes: [IAM_NOTE],
    })
    expect(allStrings(requests).some(s => s.includes(SECRET))).toBe(false)
    expect(allStrings(result).some(s => s.includes(SECRET) || s.includes(AKID))).toBe(false)
  })

  test('an STS error passes through without the note', async () => {
    const { result } = await runProbe(bedrockProbe, '', [
      res(403, { Error: { Code: 'InvalidClientTokenId', Message: 'The security token included in the request is invalid.' } }),
    ], companions({ awsAccessKeyId: AKID, awsSecretKey: SECRET }))
    expect(result.error).toMatchObject({ kind: 'invalid_key', providerCode: 'InvalidClientTokenId' })
    expect(result.notes).toBeUndefined()
  })

  test.each([
    ['no secret', { awsAccessKeyId: AKID }],
    ['no access key id', { awsSecretKey: SECRET }],
  ])('%s -> companion_missing, nothing called', async (_name, over) => {
    const { result, requests } = await runProbe(bedrockProbe, '', [], companions(over))
    expect(requests).toHaveLength(0)
    expect(result).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'companion_missing' })
  })
})

describe('the region never steers a request', () => {
  const BAD = ['us-east-1.evil.test#', 'x/..', '', ' us-east-1', 'us-east-1 ', 'us-east-1/', 'us-east-1\n', 'US-EAST-1', 'evil.test', '127.0.0.1', 'us-east-1@evil.test']

  test.each(BAD)('API-key mode, region %j: zero requests, invalid AWS region', async region => {
    const { result, requests } = await runProbe(bedrockProbe, '', [], companions({ awsRegion: region, awsBearerToken: BEARER }))
    expect(requests).toHaveLength(0)
    expect(result.error?.kind).toBe('unexpected_response')
    expect(result.error?.message).toMatch(/invalid AWS region/)
  })

  test.each(BAD)('IAM mode, region %j: zero requests, invalid AWS region', async region => {
    const { result, requests } = await runProbe(bedrockProbe, '', [], companions({ awsRegion: region, awsAccessKeyId: AKID, awsSecretKey: SECRET }))
    expect(requests).toHaveLength(0)
    expect(result.error?.message).toMatch(/invalid AWS region/)
  })

  test('a row with no region companion at all: zero requests', async () => {
    const { requests, result } = await runProbe(bedrockProbe, '', [], { awsBearerToken: BEARER })
    expect(requests).toHaveLength(0)
    expect(result.error?.message).toMatch(/invalid AWS region/)
  })

  test('apiKeyRequest itself refuses an invalid region', () => {
    expect(() => apiKeyRequest(BEARER, 'us-east-1.evil.test#')).toThrow(/invalid AWS region/)
  })

  test('registry contract', () => {
    expect(bedrockProbe).toMatchObject({ id: 'llm-bedrock', service: 'bedrock', group: 'llm', field: 'apiKey', kind: 'validity', verifiedOn: null })
  })
})
