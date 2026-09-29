/**
 * OpenAI-compatible probe (plan catalogue C12). The base URL is user text, so
 * most of these tests are about what is NOT called: anything but an exact
 * public preset origin is "not checked" with zero requests. Fixtures are
 * synthetic; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { OPENAI_COMPAT_PRESETS } from '@/lib/llmProviderPresets'
import {
  CUSTOM_ENDPOINT_NOTE, PRESET_ORIGINS, openaiCompatibleProbe, presetOrigin,
  parseDeepinfra, parseFireworksAccounts, parseFireworksModels, parseGroq, parseTogether,
  requestDeepinfra, requestFireworksAccounts, requestFireworksModels, requestGroq, requestTogether,
} from './openaiCompatible'
import { computeHealth } from '../../health'
import { html, res, runProbe, allStrings } from '../../testUtils'
import type { ProbeResponse } from '../../types'

const KEY = 'TESTKEY-0000-compat-AAAAAAAAAAAAAAAAAAAA'
const BEARER = { Authorization: `Bearer ${KEY}` }
const MODEL_LIST = { object: 'list', data: [{ id: 'model-a', object: 'model' }] }

function run(baseUrl: string, responses: (ProbeResponse | Error)[] = []) {
  return runProbe(openaiCompatibleProbe, KEY, responses, {
    baseUrl, awsRegion: '', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
  })
}

describe('the allowlist matches the https presets of llmProviderPresets.ts', () => {
  test('every https preset origin is allowlisted, and nothing else is', () => {
    const httpsOrigins = OPENAI_COMPAT_PRESETS
      .filter(p => p.baseUrl.startsWith('https:'))
      .map(p => new URL(p.baseUrl).origin)
    expect(httpsOrigins.length).toBeGreaterThan(0)
    expect(new Set(PRESET_ORIGINS)).toEqual(new Set(httpsOrigins))
    expect(PRESET_ORIGINS).toHaveLength(new Set(httpsOrigins).size)
  })

  test('each https preset base URL resolves to its own origin', () => {
    for (const p of OPENAI_COMPAT_PRESETS.filter(x => x.baseUrl.startsWith('https:'))) {
      expect(presetOrigin(p.baseUrl)).toBe(new URL(p.baseUrl).origin)
    }
  })

  test('the local presets (Ollama, vLLM, LM Studio) and Custom are never allowlisted', () => {
    for (const p of OPENAI_COMPAT_PRESETS.filter(x => !x.baseUrl.startsWith('https:'))) {
      expect(presetOrigin(p.baseUrl)).toBeUndefined()
    }
  })
})

describe('presetOrigin: exact origin match only', () => {
  test.each([
    'https://api.groq.com/openai/v1',
    'https://api.groq.com/openai/v1/',
    'HTTPS://API.GROQ.COM/openai/v1',
    'https://api.groq.com:443/openai/v1',
    'https://api.groq.com/some/other/path',
  ])('%s -> the Groq origin', url => {
    expect(presetOrigin(url)).toBe('https://api.groq.com')
  })
})

describe('any base URL off the allowlist: not checked, and NO request is made', () => {
  test.each([
    ['Ollama on the Docker host', 'http://host.docker.internal:11434/v1'],
    ['vLLM on the Docker host', 'http://host.docker.internal:8000/v1'],
    ['LM Studio on the Docker host', 'http://host.docker.internal:1234/v1'],
    ['lookalike suffix', 'https://api.groq.com.evil.test/openai/v1'],
    ['encoded-dot lookalike', 'https://api.groq.com%2eevil.test/openai/v1'],
    ['subdomain of a preset', 'https://evil.api.groq.com/openai/v1'],
    ['user and password', 'https://user:pw@api.groq.com/openai/v1'],
    ['username only', 'https://user@api.groq.com/openai/v1'],
    ['password only', 'https://:pw@api.groq.com/openai/v1'],
    ['preset host as userinfo', 'https://api.groq.com@evil.test/openai/v1'],
    ['preset host in the fragment', 'https://evil.test#@api.groq.com'],
    ['preset host in the query', 'https://evil.test/?next=https://api.groq.com'],
    ['different port', 'https://api.groq.com:8443/openai/v1'],
    ['plain http on a preset host', 'http://api.groq.com/openai/v1'],
    ['another scheme', 'wss://api.groq.com/openai/v1'],
    ['trailing-dot hostname', 'https://api.groq.com./openai/v1'],
    ['a host that is not the preset one', 'https://api.together.ai/v1'],
    ['cloud metadata', 'https://169.254.169.254/latest/meta-data'],
    ['loopback name', 'https://localhost/v1'],
    ['IPv6 loopback', 'https://[::1]/v1'],
    ['scheme-relative', '//api.groq.com/openai/v1'],
    ['no scheme', 'api.groq.com/openai/v1'],
    ['malformed', 'https://'],
    ['not a URL', 'not a url at all'],
    ['empty', ''],
  ])('%s (%s)', async (_label, baseUrl) => {
    expect(presetOrigin(baseUrl)).toBeUndefined()
    const { result, requests } = await run(baseUrl)
    expect(requests).toEqual([])
    expect(result).toEqual({ outcome: 'not_checked', meters: [], notCheckedReason: 'custom_endpoint', notes: [CUSTOM_ENDPOINT_NOTE] })
  })

  test('no baseUrl companion at all behaves like an empty one', async () => {
    const { result, requests } = await runProbe(openaiCompatibleProbe, KEY, [])
    expect(requests).toEqual([])
    expect(result.notCheckedReason).toBe('custom_endpoint')
  })

  test('the note points to the Test Connection button', () => {
    expect(CUSTOM_ENDPOINT_NOTE).toMatch(/^Use the provider's Test Connection button/)
  })
})

describe('Groq', () => {
  test('request: the preset models listing, Bearer key', () => {
    expect(requestGroq(KEY)).toEqual({ method: 'GET', url: 'https://api.groq.com/openai/v1/models', headers: BEARER })
  })

  test('200 -> valid; 401 invalid_api_key (missing and wrong alike) -> invalid_key', () => {
    expect(parseGroq(res(200, MODEL_LIST)).outcome).toBe('valid_no_usage')
    expect(parseGroq(res(401, { error: { message: 'Invalid API Key', type: 'invalid_request_error', code: 'invalid_api_key' } })).error)
      .toEqual({ kind: 'invalid_key', httpStatus: 401, providerCode: 'invalid_api_key', message: 'Invalid API Key' })
  })

  test('run: one call to the preset endpoint, whatever the saved path', async () => {
    const { result, requests } = await run('https://api.groq.com/openai/v1', [res(200, MODEL_LIST)])
    expect(requests).toEqual([requestGroq(KEY)])
    expect(result).toMatchObject({ outcome: 'valid_no_usage' })
    expect(result.notes).toBeUndefined()
  })
})

describe('Together AI', () => {
  test('request: the preset models listing, Bearer key', () => {
    expect(requestTogether(KEY)).toEqual({ method: 'GET', url: 'https://api.together.xyz/v1/models', headers: BEARER })
  })

  test('200 (a bare array, possibly cut at the read cap) -> valid', () => {
    expect(parseTogether(res(200, [{ id: 'model-a', object: 'model' }])).outcome).toBe('valid_no_usage')
    const cut: ProbeResponse = { ...res(200, '[{"id":"model-a","object":"model"},{"id":"mo', { contentType: 'application/json' }), truncated: true }
    expect(parseTogether(cut).outcome).toBe('valid_no_usage')
  })

  test('401 text/plain -> invalid_key with the text', () => {
    expect(parseTogether(res(401, 'Missing API key')).error).toEqual({ kind: 'invalid_key', httpStatus: 401, message: 'Missing API key' })
    expect(parseTogether(res(401, 'Invalid API key provided. You can find your API key at https://api.together.xyz/settings/api-keys.')).error?.kind).toBe('invalid_key')
  })

  test('402 (monthly spending limit) -> quota_exhausted; 429 -> rate_limited', () => {
    expect(parseTogether(res(402, { error: { message: 'Credit limit exceeded', type: 'credit_limit' } })).error?.kind).toBe('quota_exhausted')
    expect(parseTogether(res(429, { error: { message: 'rate limited' } })).error?.kind).toBe('rate_limited')
  })
})

describe('Fireworks AI: models listing, then the account suspend state', () => {
  const account = (suspendState?: string) => ({
    accounts: [{ name: 'accounts/test-account', displayName: 'Test Account', state: 'READY', ...(suspendState ? { suspendState } : {}) }],
  })

  test('requests: models listing, then accounts, Bearer key', () => {
    expect(requestFireworksModels(KEY)).toEqual({ method: 'GET', url: 'https://api.fireworks.ai/inference/v1/models', headers: BEARER })
    expect(requestFireworksAccounts(KEY)).toEqual({ method: 'GET', url: 'https://api.fireworks.ai/v1/accounts', headers: BEARER })
  })

  test('UNSUSPENDED -> valid, two calls in order; the account name is not copied', async () => {
    const { result, requests } = await run('https://api.fireworks.ai/inference/v1', [res(200, MODEL_LIST), res(200, account('UNSUSPENDED'))])
    expect(requests.map(r => r.url)).toEqual(['https://api.fireworks.ai/inference/v1/models', 'https://api.fireworks.ai/v1/accounts'])
    expect(result).toMatchObject({ outcome: 'valid_no_usage' })
    expect(allStrings(result).join(' ')).not.toContain('test-account')
  })

  test.each([
    ['CREDIT_DEPLETED', 'quota_exhausted'],
    ['MONTHLY_SPEND_LIMIT_EXCEEDED', 'quota_exhausted'],
    ['FAILED_PAYMENTS', 'forbidden'],
    ['BLOCKED_BY_ABUSE_RULE', 'forbidden'],
    ['SOME_FUTURE_STATE', 'forbidden'],
  ])('suspendState %s -> %s, the state as the message', (state, kind) => {
    expect(parseFireworksAccounts(res(200, account(state))).error).toEqual({
      kind, httpStatus: 200, providerCode: state, message: `Fireworks account suspended: ${state}`,
    })
  })

  test('no suspendState, or the unspecified default -> valid', () => {
    expect(parseFireworksAccounts(res(200, account())).outcome).toBe('valid_no_usage')
    expect(parseFireworksAccounts(res(200, account('SUSPEND_STATE_UNSPECIFIED'))).outcome).toBe('valid_no_usage')
  })

  test('a rejected key stops at the listing: one call', async () => {
    const { result, requests } = await run('https://api.fireworks.ai/inference/v1', [
      res(401, { error: { object: 'error', type: 'invalid_request_error', code: 'INVALID_API_KEY', message: 'The API key you provided is invalid.' } }),
    ])
    expect(requests).toHaveLength(1)
    expect(result.error).toMatchObject({ kind: 'invalid_key', providerCode: 'INVALID_API_KEY' })
    expect(parseFireworksModels(html(502)).error?.kind).toBe('provider_error')
  })

  test('an unreadable account state keeps the key valid, noted; a 401 there is invalid_key', () => {
    const forbidden = parseFireworksAccounts(res(403, { error: { message: 'forbidden' } }))
    expect(forbidden.outcome).toBe('valid_no_usage')
    expect(forbidden.notes).toEqual(['Fireworks did not report the account state (HTTP 403)'])
    expect(parseFireworksAccounts(res(200, { hello: 'world' })).outcome).toBe('valid_no_usage')
    expect(parseFireworksAccounts(res(401, { error: { message: 'unauthorized' } })).error?.kind).toBe('invalid_key')
  })
})

describe('Deepinfra: /v1/me checklist (the models listing is public and proves nothing)', () => {
  const me = (checklist: Record<string, unknown>) => ({
    uid: '00000000-0000-4000-8000-000000000009', email: 'someone@example.test', name: 'Test User', checklist,
  })

  test('request: /v1/me?checklist=true with a Bearer key', () => {
    const r = requestDeepinfra(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://api.deepinfra.com/v1/me?checklist=true', headers: BEARER })
    expect(r.url).not.toContain(KEY)
  })

  test('negative stripe_balance is credit: a primary balance meter; live scoped credits as secondary meters', () => {
    const r = parseDeepinfra(res(200, me({
      stripe_balance: -12.5, recent: 1.2, limit: 100, suspended: false, suspend_reason: null,
      scoped_credits: [
        { name: 'Welcome credit', granted_cents: 500, remaining_cents: 123, expires_ts: 1800000000, expired: false },
        { name: 'Old promo', granted_cents: 1000, remaining_cents: 1000, expires_ts: 1700000000, expired: true },
        { name: 'Spent', granted_cents: 100, remaining_cents: 0, expires_ts: 1800000000, expired: false },
      ],
    })))
    expect(r.outcome).toBe('usage')
    expect(r.meters).toEqual([
      {
        id: 'balance', label: 'Account balance', unit: 'usd', window: 'balance',
        used: null, limit: null, remaining: 12.5, resetsAt: null, resetsAtSource: null, primary: true,
      },
      {
        id: 'scoped_credit_0', label: 'Credit: Welcome credit', unit: 'usd', window: 'balance',
        used: 3.77, limit: 5, remaining: 1.23, resetsAt: null, resetsAtSource: null, primary: false,
        note: 'expires 2027-01-15',
      },
    ])
    expect(computeHealth(r.meters)).toBe('ok')
  })

  test('positive stripe_balance is owed: no credit, but not "exhausted" (usage is billed afterwards)', () => {
    const r = parseDeepinfra(res(200, me({ stripe_balance: 3.2, suspended: false })))
    expect(r.meters).toEqual([{
      id: 'balance', label: 'Account balance', unit: 'usd', window: 'balance',
      used: null, limit: null, remaining: 0, resetsAt: null, resetsAtSource: null, primary: false,
      note: '3.20 owed',
    }])
    expect(computeHealth(r.meters)).toBe('ok')
    expect(parseDeepinfra(res(200, me({ stripe_balance: 0, suspended: false }))).meters[0].note).toBe('no prepaid credit')
  })

  test('the profile around the checklist (email, name, uid) is never copied', () => {
    const joined = allStrings(parseDeepinfra(res(200, me({ stripe_balance: -1, suspended: false })))).join(' ')
    expect(joined).not.toContain('someone@example.test')
    expect(joined).not.toContain('Test User')
    expect(joined).not.toContain('00000000-0000-4000-8000')
  })

  test('suspended -> error: a balance reason is quota_exhausted, anything else forbidden', () => {
    expect(parseDeepinfra(res(200, me({ stripe_balance: 0, suspended: true, suspend_reason: 'Insufficient balance' }))).error)
      .toEqual({ kind: 'quota_exhausted', httpStatus: 200, message: 'Deepinfra account suspended: Insufficient balance' })
    expect(parseDeepinfra(res(200, me({ suspended: true, suspend_reason: 'Terms of service violation' }))).error?.kind).toBe('forbidden')
    expect(parseDeepinfra(res(200, me({ suspended: true }))).error).toMatchObject({ kind: 'forbidden', message: 'Deepinfra account suspended' })
  })

  test('401 {"detail"} -> invalid_key; 402 -> quota_exhausted; 5xx -> provider_error', () => {
    expect(parseDeepinfra(res(401, { detail: 'User is not authorized to access this resource' })).error)
      .toEqual({ kind: 'invalid_key', httpStatus: 401, message: 'User is not authorized to access this resource' })
    expect(parseDeepinfra(res(402, { detail: 'Payment required' })).error?.kind).toBe('quota_exhausted')
    expect(parseDeepinfra(html(502)).error?.kind).toBe('provider_error')
  })

  test('a profile without a checklist is valid, noted; a non-JSON 200 is unexpected', () => {
    expect(parseDeepinfra(res(200, { uid: 'x' }))).toMatchObject({ outcome: 'valid_no_usage', notes: ['Deepinfra did not report the balance'] })
    expect(parseDeepinfra(html(200)).error?.kind).toBe('unexpected_response')
  })

  test('run: one call on the preset base URL', async () => {
    const { result, requests } = await run('https://api.deepinfra.com/v1/openai', [res(200, me({ stripe_balance: -2, suspended: false }))])
    expect(requests).toEqual([requestDeepinfra(KEY)])
    expect(result.outcome).toBe('usage')
    expect(result.notes).toBeUndefined()
  })
})

describe('Mistral AI preset (the C10 check)', () => {
  test('run: GET api.mistral.ai/v1/models; a 401 carries the Codestral hint', async () => {
    const ok = await run('https://api.mistral.ai/v1', [res(200, MODEL_LIST)])
    expect(ok.requests).toEqual([{ method: 'GET', url: 'https://api.mistral.ai/v1/models', headers: BEARER }])
    expect(ok.result.outcome).toBe('valid_no_usage')
    const bad = await run('https://api.mistral.ai/v1', [res(401, { detail: 'Unauthorized' })])
    expect(bad.result.error?.kind).toBe('invalid_key')
    expect(bad.result.notes?.[0]).toMatch(/Codestral/)
  })
})

describe('a saved base URL on a preset host but another path', () => {
  test('is checked on the preset endpoint, and the row says the saved one differs', async () => {
    const { result, requests } = await run('https://api.mistral.ai', [res(200, MODEL_LIST)])
    expect(requests.map(r => r.url)).toEqual(['https://api.mistral.ai/v1/models'])
    expect(result.outcome).toBe('valid_no_usage')
    expect(result.notes).toEqual(["The saved base URL differs from the Mistral AI preset (https://api.mistral.ai/v1); the key was checked on the preset's endpoint"])
  })

  test('a trailing slash is not a difference', async () => {
    const { result } = await run('https://api.groq.com/openai/v1/', [res(200, MODEL_LIST)])
    expect(result.notes).toBeUndefined()
  })
})

describe('probe', () => {
  test('LLM row contract, with the base URL as an optional companion', () => {
    expect(openaiCompatibleProbe).toMatchObject({
      id: 'llm-openai-compatible', service: 'openai_compatible', group: 'llm', field: 'apiKey',
      kind: 'validity', verifiedOn: null, companions: [{ field: 'baseUrl', required: false }],
    })
    expect(openaiCompatibleProbe.endpoint).not.toContain('?')
  })

  test.each([
    ['https://api.groq.com/openai/v1', [res(401, { error: { message: 'Invalid API Key', code: 'invalid_api_key' } })]],
    ['https://api.together.xyz/v1', [res(200, MODEL_LIST)]],
    ['https://api.fireworks.ai/inference/v1', [res(200, MODEL_LIST), res(200, { accounts: [] })]],
    ['https://api.deepinfra.com/v1/openai', [res(200, { checklist: { stripe_balance: -1 } })]],
    ['https://api.mistral.ai/v1', [res(429, { object: 'error', message: 'Rate limit exceeded', code: '1300' })]],
  ])('%s: the key only in a header, never in the result', async (baseUrl, answers) => {
    const { result, requests } = await run(baseUrl, answers)
    expect(requests.length).toBe(answers.length)
    for (const r of requests) {
      expect(r.url).not.toContain(KEY)
      expect(r.headers).toEqual(BEARER)
    }
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })
})
