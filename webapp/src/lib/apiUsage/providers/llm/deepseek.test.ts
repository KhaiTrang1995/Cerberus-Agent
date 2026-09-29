/**
 * DeepSeek balance probe (plan catalogue C2). Amounts are strings; one balance
 * per currency. Fixtures are synthetic; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { deepseekProbe, modelsRequest, parse, parseModels, request } from './deepseek'
import { computeHealth } from '../../health'
import { html, res, runProbe, allStrings } from '../../testUtils'

const KEY = 'TESTKEY-0000-deepseek-AAAAAAAAAAAAAA1a2b'

const DOC_EXAMPLE = {
  is_available: true,
  balance_infos: [{ currency: 'CNY', total_balance: '110.00', granted_balance: '10.00', topped_up_balance: '100.00' }],
}

describe('request', () => {
  test('GET /user/balance on the origin (no /v1), key as a Bearer header', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://api.deepseek.com/user/balance', headers: { Authorization: `Bearer ${KEY}` } })
    expect(r.url).not.toContain('/v1')
    expect(r.url).not.toContain(KEY)
  })

  test('the validity fallback lists models on the origin', () => {
    expect(modelsRequest(KEY)).toEqual({ method: 'GET', url: 'https://api.deepseek.com/models', headers: { Authorization: `Bearer ${KEY}` } })
  })
})

describe('parse: success', () => {
  test('documented example: one CNY balance meter from the string amounts', () => {
    const r = parse(res(200, DOC_EXAMPLE))
    expect(r.outcome).toBe('usage')
    expect(r.meters).toEqual([{
      id: 'balance_cny', label: 'Balance (CNY)', unit: 'cny', window: 'balance',
      used: null, limit: null, remaining: 110, resetsAt: null, resetsAtSource: null, primary: true,
      note: 'granted 10.00 + topped-up 100.00',
    }])
    expect(r.healthOverride).toBeUndefined()
    expect(computeHealth(r.meters)).toBe('ok')
  })

  test('CNY and USD side by side: an empty currency does not mark a funded account exhausted', () => {
    const r = parse(res(200, {
      is_available: true,
      balance_infos: [
        { currency: 'CNY', total_balance: '0.00', granted_balance: '0.00', topped_up_balance: '0.00' },
        { currency: 'USD', total_balance: '5.20', granted_balance: '0.00', topped_up_balance: '5.20' },
      ],
    }))
    expect(r.meters.map(m => [m.id, m.unit, m.remaining, m.primary])).toEqual([
      ['balance_cny', 'cny', 0, false],
      ['balance_usd', 'usd', 5.2, true],
    ])
    expect(computeHealth(r.meters)).toBe('ok')
  })

  test('a zero balance on its own is exhausted', () => {
    const r = parse(res(200, { is_available: true, balance_infos: [{ currency: 'USD', total_balance: '0.00' }] }))
    expect(r.meters[0]).toMatchObject({ remaining: 0, primary: true })
    expect(r.meters[0].note).toBeUndefined()
    expect(computeHealth(r.meters)).toBe('exhausted')
  })

  test('is_available false -> health forced to exhausted, with a note', () => {
    const r = parse(res(200, { is_available: false, balance_infos: [{ currency: 'CNY', total_balance: '0.40', granted_balance: '0.40', topped_up_balance: '0.00' }] }))
    expect(r.outcome).toBe('usage')
    expect(r.healthOverride).toBe('exhausted')
    expect(r.notes).toEqual(['DeepSeek reports the balance is too low for API calls'])
  })

  test('is_available false with no balance entry -> quota_exhausted', () => {
    const r = parse(res(200, { is_available: false, balance_infos: [] }))
    expect(r.error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 200 })
  })

  test('no balance entry but available -> valid, noted', () => {
    const r = parse(res(200, { is_available: true, balance_infos: [] }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.notes).toEqual(['DeepSeek reported no balance'])
  })

  test('a currency the report has no unit for is noted, not mislabelled', () => {
    const r = parse(res(200, { is_available: true, balance_infos: [
      { currency: 'EUR', total_balance: '3.00' },
      { currency: 'usd', total_balance: '1.00' },
    ] }))
    expect(r.meters.map(m => m.id)).toEqual(['balance_usd'])
    expect(r.notes).toEqual(['DeepSeek also reported a EUR balance, which this report cannot show'])
  })
})

describe('parse: errors', () => {
  test('401 plain text (missing/malformed key) -> invalid_key with the text', () => {
    const r = parse(res(401, 'Authentication Fails (governor)'))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, message: 'Authentication Fails (governor)' })
  })

  test('401 JSON (no such user) -> invalid_key with the provider code', () => {
    const r = parse(res(401, { error: { message: 'Authentication Fails (no such user)', type: 'authentication_error', param: null, code: 'invalid_request_error' } }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'invalid_request_error', message: 'Authentication Fails (no such user)' })
  })

  test('the newer 401 text echoes the last 4 characters: passed through, the key is never added', () => {
    const r = parse(res(401, { error: { message: 'Authentication Fails, Your api key: ****1a2b is invalid', type: 'authentication_error', code: 'invalid_request_error' } }))
    expect(r.error?.message).toBe('Authentication Fails, Your api key: ****1a2b is invalid')
    expect(allStrings(r).some(s => s.includes(KEY))).toBe(false)
  })

  test('402 Insufficient Balance -> quota_exhausted', () => {
    expect(parse(res(402, { error: { message: 'Insufficient Balance', type: 'unknown_error' } })).error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 402 })
  })

  test('429 -> rate_limited; 500/503 -> provider_error', () => {
    expect(parse(res(429, { error: { message: 'Rate Limit Reached' } })).error?.kind).toBe('rate_limited')
    expect(parse(res(500, { error: { message: 'Server Error' } })).error?.kind).toBe('provider_error')
    expect(parse(html(503)).error?.kind).toBe('provider_error')
  })

  test('a 200 without balance_infos -> unexpected_response', () => {
    expect(parse(res(200, { is_available: true })).error?.kind).toBe('unexpected_response')
  })
})

describe('parseModels (validity fallback)', () => {
  test('a model list proves the key, noted as a fallback', () => {
    const r = parseModels(res(200, { object: 'list', data: [{ id: 'deepseek-chat', object: 'model' }] }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.notes?.[0]).toMatch(/checked on \/models instead/)
  })

  test('errors keep the balance mapping', () => {
    expect(parseModels(res(401, 'Authentication Fails (governor)')).error?.kind).toBe('invalid_key')
    expect(parseModels(res(402, { error: { message: 'Insufficient Balance' } })).error?.kind).toBe('quota_exhausted')
  })
})

describe('run', () => {
  test('one call when the balance answers', async () => {
    const { result, requests } = await runProbe(deepseekProbe, KEY, [res(200, DOC_EXAMPLE)])
    expect(requests.map(r => r.url)).toEqual(['https://api.deepseek.com/user/balance'])
    expect(result.outcome).toBe('usage')
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('an auth error is final: no fallback call', async () => {
    const { result, requests } = await runProbe(deepseekProbe, KEY, [res(401, 'Authentication Fails (governor)')])
    expect(requests).toHaveLength(1)
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('a moved balance route (404) falls back to /models', async () => {
    const { result, requests } = await runProbe(deepseekProbe, KEY, [
      res(404, { error: { message: 'Not Found' } }),
      res(200, { object: 'list', data: [] }),
    ])
    expect(requests.map(r => r.url)).toEqual(['https://api.deepseek.com/user/balance', 'https://api.deepseek.com/models'])
    expect(result.outcome).toBe('valid_no_usage')
  })

  test('a drifted 200 body falls back too, and the fallback error is what is reported', async () => {
    const { result, requests } = await runProbe(deepseekProbe, KEY, [
      res(200, { balance: '1.00' }),
      res(401, 'Authentication Fails (governor)'),
    ])
    expect(requests).toHaveLength(2)
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('LLM row contract', () => {
    expect(deepseekProbe).toMatchObject({
      id: 'llm-deepseek', service: 'deepseek', group: 'llm', field: 'apiKey', kind: 'usage', verifiedOn: null,
      endpoint: 'GET api.deepseek.com/user/balance',
    })
  })
})
