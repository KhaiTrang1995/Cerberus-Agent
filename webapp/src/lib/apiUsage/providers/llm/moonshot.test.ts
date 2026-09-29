/**
 * Kimi / Moonshot balance probe (plan catalogue C3). Fixtures are synthetic,
 * written from the documented example; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { AGENT_BASE, balanceUnit, kimiProbe, parse, request } from './moonshot'
import { computeHealth } from '../../health'
import { html, res, runProbe, allStrings } from '../../testUtils'

const KEY = 'TESTKEY-0000-kimi-AAAAAAAAAAAAAAAAAAAA'

const DOC_EXAMPLE = {
  code: 0,
  data: { available_balance: 49.58894, voucher_balance: 46.58893, cash_balance: 3.00001 },
  scode: '0x0',
  status: true,
}

describe('request', () => {
  test("GET /users/me/balance on the agent's host, key as a Bearer header", () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://api.moonshot.ai/v1/users/me/balance', headers: { Authorization: `Bearer ${KEY}` } })
    expect(r.url).not.toContain(KEY)
    expect(AGENT_BASE).toBe('https://api.moonshot.ai/v1')
  })

  test('the .cn platform builds the same path on its own host', () => {
    expect(request(KEY, 'https://api.moonshot.cn/v1').url).toBe('https://api.moonshot.cn/v1/users/me/balance')
  })
})

describe('balanceUnit: the currency follows the platform host', () => {
  test('.ai -> usd, .cn -> cny', () => {
    expect(balanceUnit('https://api.moonshot.ai/v1')).toBe('usd')
    expect(balanceUnit('https://api.moonshot.cn/v1')).toBe('cny')
  })
})

describe('parse: success', () => {
  test('documented example: one available-balance meter, voucher and cash in the note', () => {
    const r = parse(res(200, DOC_EXAMPLE), 'usd')
    expect(r.outcome).toBe('usage')
    expect(r.meters).toEqual([{
      id: 'available_balance', label: 'Available balance', unit: 'usd', window: 'balance',
      used: null, limit: null, remaining: 49.58894, resetsAt: null, resetsAtSource: null, primary: true,
      note: 'voucher 46.59 · cash 3.00',
    }])
    expect(computeHealth(r.meters)).toBe('ok')
  })

  test('the unit is the one passed for the host', () => {
    expect(parse(res(200, DOC_EXAMPLE), 'cny').meters[0].unit).toBe('cny')
  })

  test('negative cash is money owed', () => {
    const r = parse(res(200, { code: 0, data: { available_balance: 0, voucher_balance: 1.5, cash_balance: -1.5 }, status: true }), 'usd')
    expect(r.meters[0].note).toBe('voucher 1.50 · cash -1.50 (owed)')
  })

  test('available balance at or below 0 blocks inference: exhausted', () => {
    const r = parse(res(200, { code: 0, data: { available_balance: -0.2, voucher_balance: 0, cash_balance: -0.2 }, status: true }), 'usd')
    expect(computeHealth(r.meters)).toBe('exhausted')
  })

  test('without voucher/cash the meter has no note', () => {
    expect(parse(res(200, { data: { available_balance: 10 } }), 'usd').meters[0].note).toBeUndefined()
  })
})

describe('parse: errors', () => {
  test('401 incorrect_api_key_error -> invalid_key, with the one-platform hint', () => {
    const r = parse(res(401, { error: { message: 'Incorrect API key provided', type: 'incorrect_api_key_error' } }), 'usd')
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, providerCode: 'incorrect_api_key_error', message: 'Incorrect API key provided' })
    expect(r.notes?.[0]).toMatch(/platform\.moonshot\.cn/)
  })

  test('401 invalid_authentication_error -> invalid_key', () => {
    expect(parse(res(401, { error: { message: 'Invalid Authentication', type: 'invalid_authentication_error' } }), 'usd').error?.kind).toBe('invalid_key')
  })

  test('403 permission_denied_error -> forbidden', () => {
    expect(parse(res(403, { error: { message: 'denied', type: 'permission_denied_error' } }), 'usd').error)
      .toMatchObject({ kind: 'forbidden', providerCode: 'permission_denied_error' })
  })

  test('429 exceeded_current_quota_error -> quota_exhausted; the other 429s -> rate_limited', () => {
    expect(parse(res(429, { error: { message: 'Your account is suspended, please check your plan and billing details', type: 'exceeded_current_quota_error' } }), 'usd').error?.kind).toBe('quota_exhausted')
    expect(parse(res(429, { error: { message: 'Rate limit reached', type: 'rate_limit_reached_error' } }), 'usd').error?.kind).toBe('rate_limited')
    expect(parse(res(429, { error: { message: 'The engine is currently overloaded', type: 'engine_overloaded_error' } }), 'usd').error?.kind).toBe('rate_limited')
  })

  test('unknown path 404 -> unexpected_response with the provider message', () => {
    const r = parse(res(404, { code: 5, error: 'url.not_found', message: '没找到对象', method: 'GET', scode: '0x5', status: false }), 'usd')
    expect(r.error).toMatchObject({ kind: 'unexpected_response', httpStatus: 404, message: 'url.not_found' })
  })

  test('500/503 -> provider_error', () => {
    expect(parse(res(500, { error: { message: 'internal', type: 'server_error' } }), 'usd').error?.kind).toBe('provider_error')
    expect(parse(html(503), 'usd').error?.kind).toBe('provider_error')
  })

  test('a 200 without data.available_balance -> unexpected_response', () => {
    expect(parse(res(200, { code: 0, data: {}, status: true }), 'usd').error?.kind).toBe('unexpected_response')
    expect(parse(res(200, { code: 0, status: true }), 'usd').error?.kind).toBe('unexpected_response')
    expect(parse(html(200), 'usd').error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test("one call on the agent's host, reported in USD; the key never reaches the result", async () => {
    const { result, requests } = await runProbe(kimiProbe, KEY, [res(200, DOC_EXAMPLE)])
    expect(requests.map(r => r.url)).toEqual(['https://api.moonshot.ai/v1/users/me/balance'])
    expect(result.meters[0].unit).toBe('usd')
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('LLM row contract', () => {
    expect(kimiProbe).toMatchObject({
      id: 'llm-kimi', service: 'kimi', group: 'llm', field: 'apiKey', kind: 'usage', verifiedOn: null,
      endpoint: 'GET api.moonshot.ai/v1/users/me/balance',
    })
  })
})
