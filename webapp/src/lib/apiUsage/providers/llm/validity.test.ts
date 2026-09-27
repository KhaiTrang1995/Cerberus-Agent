/**
 * Validity-only LLM probes (plan catalogue C4, C5, C7-C10): a models listing
 * that answers 2xx proves the key. Fixtures are synthetic, shaped like each
 * provider's documented error envelope; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import {
  anthropicProbe, geminiProbe, glmProbe, googleReason, mistralProbe, openaiProbe, qwenProbe,
  parseAnthropic, parseGemini, parseGlm, parseMistral, parseOpenai, parseQwen,
  requestAnthropic, requestGemini, requestGlm, requestMistral, requestOpenai, requestQwen,
} from './validity'
import { html, res, runProbe, allStrings } from '../../testUtils'
import type { ProbeDef, ProbeResponse } from '../../types'

const KEY = 'TESTKEY-0000-validity-AAAAAAAAAAAAAAAAAA'
const BEARER = { Authorization: `Bearer ${KEY}` }
const MODEL_LIST = { object: 'list', data: [{ id: 'model-a', object: 'model' }] }

describe('request: exact method, URL and headers; the key only ever in a header', () => {
  test.each([
    ['GLM', requestGlm, 'https://open.bigmodel.cn/api/paas/v4/models', BEARER],
    ['Qwen', requestQwen, 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models', BEARER],
    ['OpenAI', requestOpenai, 'https://api.openai.com/v1/models', BEARER],
    ['Anthropic', requestAnthropic, 'https://api.anthropic.com/v1/models?limit=1', { 'x-api-key': KEY, 'anthropic-version': '2023-06-01' }],
    ['Gemini', requestGemini, 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=1', { 'x-goog-api-key': KEY }],
    ['Mistral', requestMistral, 'https://api.mistral.ai/v1/models', BEARER],
  ])('%s', (_name, build, url, headers) => {
    const r = build(KEY)
    expect(r).toEqual({ method: 'GET', url, headers })
    expect(r.url).not.toContain(KEY)
  })

  test('Gemini never takes the key as ?key=', () => {
    expect(requestGemini(KEY).url).not.toMatch(/[?&]key=/)
  })
})

describe('the shared 2xx rule', () => {
  const parsers = { parseGlm, parseQwen, parseOpenai, parseAnthropic, parseGemini, parseMistral }

  test.each(Object.entries(parsers))('%s: a 2xx listing -> valid_no_usage', (_name, parse) => {
    expect(parse(res(200, MODEL_LIST))).toEqual({ outcome: 'valid_no_usage', meters: [], account: undefined, notes: undefined })
    expect(parse(res(200, [{ id: 'model-a' }])).outcome).toBe('valid_no_usage')
  })

  test.each(Object.entries(parsers))('%s: a listing cut at the read cap still counts', (_name, parse) => {
    const cut: ProbeResponse = { ...res(200, '{"object":"list","data":[{"id":"mo', { contentType: 'application/json' }), truncated: true }
    expect(parse(cut).outcome).toBe('valid_no_usage')
  })

  test.each(Object.entries(parsers))('%s: a 200 HTML page -> unexpected_response', (_name, parse) => {
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('C4 GLM: any non-401 answer from the gateway means the key authenticated', () => {
  test('401 "1001" (missing header) -> invalid_key, labelled over the Chinese text', () => {
    const r = parseGlm(res(401, { error: { code: '1001', message: 'Header中未收到Authorization参数，无法进行身份验证。' } }))
    expect(r.error).toEqual({
      kind: 'invalid_key', httpStatus: 401, providerCode: '1001',
      message: 'No Authorization header was received (Header中未收到Authorization参数，无法进行身份验证。)',
    })
  })

  test('401 "1000" (invalid) and "1003" (expired) -> invalid_key', () => {
    expect(parseGlm(res(401, { error: { code: '1000', message: '身份验证失败。' } })).error?.message).toBe('Authentication failed (身份验证失败。)')
    expect(parseGlm(res(401, { error: { code: '1003', message: 'Token已过期' } })).error).toMatchObject({ kind: 'invalid_key', providerCode: '1003' })
  })

  test('401 with an unknown code keeps the provider text', () => {
    expect(parseGlm(res(401, { error: { code: '1999', message: 'something' } })).error?.message).toBe('something')
  })

  test('a 404 (the undocumented route moved) is still valid, with a note', () => {
    const r = parseGlm(res(404, { timestamp: '2026-09-26T14:32:05.000+00:00', status: 404, error: 'Not Found', path: '/api/paas/v4/models' }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.notes).toEqual(['GLM has no key-check endpoint: its gateway accepted the key, then answered HTTP 404'])
  })

  test('a coded non-401 names the code in the note', () => {
    expect(parseGlm(res(400, { error: { code: '1210', message: 'bad parameter' } })).notes?.[0]).toMatch(/HTTP 400 \(1210\)$/)
  })

  test('429 "1302" (throttle) and 403 "1220" (no permission) come after authentication: valid', () => {
    expect(parseGlm(res(429, { error: { code: '1302', message: '您当前使用该API的并发数过高' } })).outcome).toBe('valid_no_usage')
    expect(parseGlm(res(403, { error: { code: '1220', message: '您无权访问' } })).outcome).toBe('valid_no_usage')
  })

  test('429 "1113" (insufficient balance) -> quota_exhausted', () => {
    expect(parseGlm(res(429, { error: { code: '1113', message: '余额不足或无可用资源包,请充值。' } })).error)
      .toMatchObject({ kind: 'quota_exhausted', providerCode: '1113', httpStatus: 429 })
  })

  test('a 5xx or an HTML page proves nothing', () => {
    expect(parseGlm(res(500, { error: { code: '500', message: 'Internal Error' } })).error?.kind).toBe('provider_error')
    expect(parseGlm(html(502)).error?.kind).toBe('provider_error')
    expect(parseGlm(html(404)).error?.kind).toBe('unexpected_response')
  })
})

describe('C5 Qwen / DashScope', () => {
  test('401 missing (code null) and invalid_api_key -> invalid_key, with the region hint', () => {
    const missing = parseQwen(res(401, { error: { message: 'You didn\'t provide an API key.', type: 'invalid_request_error', param: null, code: null }, request_id: 'r-1' }))
    expect(missing.error).toMatchObject({ kind: 'invalid_key', providerCode: 'invalid_request_error' })
    const invalid = parseQwen(res(401, { error: { message: 'Incorrect API key provided. ', type: 'invalid_request_error', param: null, code: 'invalid_api_key' }, request_id: 'r-2' }))
    expect(invalid.error).toMatchObject({ kind: 'invalid_key', providerCode: 'invalid_api_key', message: 'Incorrect API key provided.' })
    expect(invalid.notes?.[0]).toMatch(/dashscope-intl/)
  })

  test('400 Arrearage (overdue account) -> quota_exhausted', () => {
    const r = parseQwen(res(400, { error: { message: 'Access denied, please make sure your account is in good standing.', type: 'Arrearage', code: 'Arrearage' } }))
    expect(r.error).toMatchObject({ kind: 'quota_exhausted', providerCode: 'Arrearage', httpStatus: 400 })
  })

  test('403 AllocationQuota.FreeTierOnly -> quota_exhausted; AccessDenied.Unpurchased -> forbidden', () => {
    expect(parseQwen(res(403, { error: { message: 'The free tier of the model has been exhausted.', code: 'AllocationQuota.FreeTierOnly' } })).error?.kind).toBe('quota_exhausted')
    expect(parseQwen(res(403, { error: { message: 'Access denied.', code: 'AccessDenied.Unpurchased' } })).error)
      .toMatchObject({ kind: 'forbidden', providerCode: 'AccessDenied.Unpurchased' })
  })

  test("429 insufficient_quota is DashScope's TPM throttle, not an empty account -> rate_limited", () => {
    expect(parseQwen(res(429, { error: { message: 'You exceeded your current quota', code: 'insufficient_quota' } })).error?.kind).toBe('rate_limited')
    expect(parseQwen(res(429, { error: { message: 'Requests rate limit exceeded', code: 'Throttling.RateQuota' } })).error?.kind).toBe('rate_limited')
  })

  test('the native envelope (top-level code) is read too', () => {
    expect(parseQwen(res(400, { code: 'Arrearage', message: 'Access denied', request_id: 'r-3' })).error?.kind).toBe('quota_exhausted')
  })
})

describe('C7 OpenAI', () => {
  test('401 invalid_api_key echoes a masked fragment: passed through, the key is never added', () => {
    const r = parseOpenai(res(401, { error: {
      message: 'Incorrect API key provided: TESTKEY-****************AAAA. You can find your API key at https://platform.openai.com/account/api-keys.',
      type: 'invalid_request_error', param: null, code: 'invalid_api_key',
    } }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, providerCode: 'invalid_api_key' })
    expect(allStrings(r).some(s => s.includes(KEY))).toBe(false)
  })

  test('401 missing key -> invalid_key', () => {
    expect(parseOpenai(res(401, { error: { message: "You didn't provide an API key.", type: 'invalid_request_error', param: null, code: null } })).error?.kind).toBe('invalid_key')
  })

  test.each([401, 403])('a restricted key without Models: Read (HTTP %i) is VALID, with a note', status => {
    const r = parseOpenai(res(status, { error: {
      message: "You have insufficient permissions for this operation. Missing scopes: api.model.read. Check that you have the correct role in your organization (Reader, Writer, Owner) and project (Member, Owner), and if you're using a restricted API key, that it has the necessary scopes.",
      type: 'invalid_request_error', param: null, code: null,
    } }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.notes).toEqual(['Restricted key: it authenticated, but without Models: Read (api.model.read) it cannot list models'])
  })

  test('429 insufficient_quota / credit_balance_exhausted / *_spend_limit_exceeded -> quota_exhausted', () => {
    for (const code of ['insufficient_quota', 'credit_balance_exhausted', 'project_spend_limit_exceeded']) {
      expect(parseOpenai(res(429, { error: { message: 'You exceeded your current quota', type: code, code } })).error?.kind).toBe('quota_exhausted')
    }
  })

  test('429 rate_limit_exceeded -> rate_limited; 403 region -> forbidden; 5xx -> provider_error', () => {
    expect(parseOpenai(res(429, { error: { message: 'Rate limit reached', type: 'requests', code: 'rate_limit_exceeded' } })).error?.kind).toBe('rate_limited')
    expect(parseOpenai(res(403, { error: { message: 'Country, region, or territory not supported', type: 'request_forbidden', code: 'unsupported_country_region_territory' } })).error?.kind).toBe('forbidden')
    expect(parseOpenai(res(503, { error: { message: 'The engine is currently overloaded', type: 'server_error' } })).error?.kind).toBe('provider_error')
  })
})

describe('C8 Anthropic', () => {
  test('401 authentication_error -> invalid_key with the error type', () => {
    const r = parseAnthropic(res(401, { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' }, request_id: 'req_000' }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, providerCode: 'authentication_error', message: 'invalid x-api-key' })
  })

  test('403 permission_error -> forbidden', () => {
    expect(parseAnthropic(res(403, { type: 'error', error: { type: 'permission_error', message: 'no access' } })).error?.kind).toBe('forbidden')
  })

  test('400 "credit balance is too low" -> quota_exhausted; another 400 -> unexpected_response', () => {
    expect(parseAnthropic(res(400, { type: 'error', error: { type: 'invalid_request_error', message: 'Your credit balance is too low to access the Anthropic API.' } })).error?.kind).toBe('quota_exhausted')
    expect(parseAnthropic(res(400, { type: 'error', error: { type: 'invalid_request_error', message: 'limit: must be at most 1000' } })).error?.kind).toBe('unexpected_response')
  })

  test('429 -> rate_limited; 529 overloaded_error -> provider_error', () => {
    expect(parseAnthropic(res(429, { type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } })).error?.kind).toBe('rate_limited')
    expect(parseAnthropic(res(529, { type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } })).error)
      .toMatchObject({ kind: 'provider_error', providerCode: 'overloaded_error' })
  })
})

describe('C9 Gemini', () => {
  const googleError = (code: number, status: string, message: string, reason?: string) => ({
    error: {
      code, message, status,
      details: reason ? [{ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason, domain: 'googleapis.com', metadata: { service: 'generativelanguage.googleapis.com' } }] : [],
    },
  })

  test('googleReason: ErrorInfo reason first, else the RPC status', () => {
    expect(googleReason(res(400, googleError(400, 'INVALID_ARGUMENT', 'x', 'API_KEY_INVALID')))).toBe('API_KEY_INVALID')
    expect(googleReason(res(400, googleError(400, 'FAILED_PRECONDITION', 'x')))).toBe('FAILED_PRECONDITION')
    expect(googleReason(res(500, 'oops'))).toBeUndefined()
  })

  test('400 API_KEY_INVALID -> invalid_key with the reason', () => {
    const r = parseGemini(res(400, googleError(400, 'INVALID_ARGUMENT', 'API key not valid. Please pass a valid API key.', 'API_KEY_INVALID')))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 400, providerCode: 'API_KEY_INVALID', message: 'API key not valid. Please pass a valid API key.' })
  })

  test('403 "reported as leaked" -> invalid_key', () => {
    const r = parseGemini(res(403, googleError(403, 'PERMISSION_DENIED', 'Your API key was reported as leaked. Please use another API key.')))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 403 })
  })

  test('402 RESOURCE_EXHAUSTED prepay depleted -> quota_exhausted', () => {
    const r = parseGemini(res(402, googleError(402, 'RESOURCE_EXHAUSTED', 'Your Prepay credit balance is depleted.')))
    expect(r.error).toMatchObject({ kind: 'quota_exhausted', providerCode: 'RESOURCE_EXHAUSTED' })
  })

  test('400 FAILED_PRECONDITION (billing / region) -> forbidden', () => {
    expect(parseGemini(res(400, googleError(400, 'FAILED_PRECONDITION', 'User location is not supported for the API use.'))).error?.kind).toBe('forbidden')
  })

  test('403 API disabled on the project -> forbidden; 429 -> rate_limited; a missing-key 403 -> forbidden', () => {
    expect(parseGemini(res(403, googleError(403, 'PERMISSION_DENIED', 'Generative Language API has not been used in project 0 before or it is disabled.', 'SERVICE_DISABLED'))).error)
      .toMatchObject({ kind: 'forbidden', providerCode: 'SERVICE_DISABLED' })
    expect(parseGemini(res(429, googleError(429, 'RESOURCE_EXHAUSTED', 'Resource has been exhausted (e.g. check quota).'))).error?.kind).toBe('rate_limited')
    expect(parseGemini(res(403, googleError(403, 'PERMISSION_DENIED', "Method doesn't allow unregistered callers"))).error?.kind).toBe('forbidden')
  })

  test('another 400 -> unexpected_response', () => {
    expect(parseGemini(res(400, googleError(400, 'INVALID_ARGUMENT', 'Invalid value at page_size'))).error?.kind).toBe('unexpected_response')
  })
})

describe('C10 Mistral: classified by status', () => {
  test('401 {"detail":"Invalid API Key"} / {"detail":"Unauthorized"} -> invalid_key, with the Codestral hint', () => {
    const r = parseMistral(res(401, { detail: 'Invalid API Key' }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, message: 'Invalid API Key' })
    expect(r.notes).toEqual(['A Codestral key only works on codestral.mistral.ai; api.mistral.ai rejects it'])
    expect(parseMistral(res(401, { detail: 'Unauthorized' })).error?.kind).toBe('invalid_key')
  })

  test('429 {"object":"error",…,"code":"1300"} -> rate_limited', () => {
    const r = parseMistral(res(429, { object: 'error', message: 'Rate limit exceeded', type: 'rate_limited', param: null, code: '1300' }))
    expect(r.error).toEqual({ kind: 'rate_limited', httpStatus: 429, providerCode: '1300', message: 'Rate limit exceeded' })
  })

  test('5xx -> provider_error', () => {
    expect(parseMistral(html(503)).error?.kind).toBe('provider_error')
  })
})

describe('probes', () => {
  const probes: [ProbeDef, string, string][] = [
    [glmProbe, 'llm-glm', 'glm'],
    [qwenProbe, 'llm-qwen', 'qwen'],
    [openaiProbe, 'llm-openai', 'openai'],
    [anthropicProbe, 'llm-anthropic', 'anthropic'],
    [geminiProbe, 'llm-gemini', 'gemini'],
    [mistralProbe, 'llm-mistral', 'mistral'],
  ]

  test.each(probes)('%# LLM row contract', (probe, id, service) => {
    expect(probe).toMatchObject({ id, service, group: 'llm', field: 'apiKey', kind: 'validity', verifiedOn: null })
    expect(probe.rotationTool).toBeUndefined()
    expect(probe.endpoint).not.toContain('?')
  })

  test.each(probes)('%# one call; the key never reaches the result, success or error', async probe => {
    for (const answer of [res(200, MODEL_LIST), res(401, { error: { message: 'bad key', type: 'authentication_error' } }), html(502)]) {
      const { result, requests } = await runProbe(probe, KEY, [answer])
      expect(requests).toHaveLength(1)
      expect(requests[0].url).not.toContain(KEY)
      expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
    }
  })
})
