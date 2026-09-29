/**
 * OpenRouter key-limit probe (plan catalogue C1). Fixtures are synthetic,
 * written from the documented example; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { nextMondayUtc, openrouterProbe, parse, request } from './openrouter'
import { NOW, html, res, runProbe, allStrings } from '../../testUtils'

const KEY = 'TESTKEY-0000-openrouter-AAAAAAAAAAAAAAAA'

/** The catalogue's documented example. */
const DOC_EXAMPLE = {
  data: {
    label: 'sk-or-v1-au7...890', limit: 100, limit_remaining: 74.5, limit_reset: 'monthly', usage: 25.5,
    is_free_tier: false, is_management_key: false,
    free_model_daily_requests: { limit: 50, remaining: 38, used: 12 },
    expires_at: '2027-12-31T23:59:59Z',
  },
}

function keyData(extra: Record<string, unknown>) {
  return { data: { ...DOC_EXAMPLE.data, ...extra } }
}

describe('request', () => {
  test('GET /api/v1/key with the key as a Bearer header, never in the URL', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://openrouter.ai/api/v1/key', headers: { Authorization: `Bearer ${KEY}` } })
    expect(r.url).not.toContain(KEY)
  })
})

describe('nextMondayUtc (OpenRouter weeks run Monday-Sunday, UTC)', () => {
  test('from a Saturday -> the coming Monday', () => {
    expect(nextMondayUtc(NOW)).toBe('2026-09-28T00:00:00.000Z')
  })
  test('from a Monday -> the Monday after', () => {
    expect(nextMondayUtc(new Date('2026-09-28T10:00:00Z'))).toBe('2026-10-05T00:00:00.000Z')
  })
  test('from a Sunday -> the next day', () => {
    expect(nextMondayUtc(new Date('2026-09-27T23:59:59Z'))).toBe('2026-09-28T00:00:00.000Z')
  })
})

describe('parse: success', () => {
  test('documented example: monthly key limit, free-model meter, plan and expiry', () => {
    const r = parse(res(200, DOC_EXAMPLE), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.meters).toEqual([
      {
        id: 'key_limit', label: 'Key limit', unit: 'usd', window: 'month',
        used: 25.5, limit: 100, remaining: 74.5,
        resetsAt: '2026-10-01T00:00:00.000Z', resetsAtSource: 'computed', primary: true,
      },
      {
        id: 'free_model_requests', label: 'Free-model requests (day)', unit: 'requests', window: 'day',
        used: 12, limit: 50, remaining: 38,
        resetsAt: '2026-09-27T00:00:00.000Z', resetsAtSource: 'computed', primary: false,
      },
    ])
    expect(r.account).toEqual({ plan: 'Paid', expiresAt: '2027-12-31T23:59:59.000Z' })
    expect(r.notes).toEqual(['Account credit balance not shown: OpenRouter reveals it to management keys only'])
  })

  test('the label (a partly masked key when unnamed) is never copied', () => {
    const r = parse(res(200, DOC_EXAMPLE), NOW)
    expect(allStrings(r).join(' ')).not.toContain('sk-or-v1-au7')
  })

  test('daily reset -> day window, next 00:00 UTC', () => {
    const m = parse(res(200, keyData({ limit_reset: 'daily' })), NOW).meters[0]
    expect(m).toMatchObject({ id: 'key_limit', window: 'day', resetsAt: '2026-09-27T00:00:00.000Z', resetsAtSource: 'computed' })
  })

  test('weekly reset -> a week window resetting next Monday 00:00 UTC', () => {
    const m = parse(res(200, keyData({ limit_reset: 'weekly' })), NOW).meters[0]
    expect(m).toMatchObject({ window: 'week', resetsAt: '2026-09-28T00:00:00.000Z' })
    expect(m.note).toBeUndefined()
  })

  test('no reset -> a lifetime limit with no reset date', () => {
    const m = parse(res(200, keyData({ limit_reset: null })), NOW).meters[0]
    expect(m).toMatchObject({ window: 'lifetime', resetsAt: null, resetsAtSource: null, limit: 100, remaining: 74.5 })
  })

  test('overspent key: remaining stops at 0, used shows the overspend', () => {
    const m = parse(res(200, keyData({ limit: 10, limit_remaining: -0.25 })), NOW).meters[0]
    expect(m).toMatchObject({ limit: 10, remaining: 0, used: 10.25 })
  })

  test('no key limit -> spend meters only, marked "no key limit"', () => {
    const r = parse(res(200, {
      data: {
        label: 'redamon', limit: null, limit_remaining: null, limit_reset: null, usage: 40.1,
        usage_daily: 1.25, usage_weekly: 6.5, usage_monthly: 12.75, is_free_tier: true,
        free_model_daily_requests: { limit: 1000, remaining: 1000, used: 0 },
      },
    }), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.meters.map(m => [m.id, m.used, m.limit, m.remaining, m.primary, m.note])).toEqual([
      ['usage_daily', 1.25, null, null, false, 'no key limit'],
      ['usage_weekly', 6.5, null, null, false, 'no key limit'],
      ['usage_monthly', 12.75, null, null, true, 'no key limit'],
      ['free_model_requests', 0, 1000, 1000, false, undefined],
    ])
    expect(r.meters.find(m => m.id === 'usage_monthly')).toMatchObject({ window: 'month', resetsAt: '2026-10-01T00:00:00.000Z' })
    expect(r.account?.plan).toBe('Free tier')
  })

  test('free-model meter without `remaining` -> computed from limit - used', () => {
    const r = parse(res(200, keyData({ free_model_daily_requests: { limit: 50, used: 60 } })), NOW)
    expect(r.meters.find(m => m.id === 'free_model_requests')).toMatchObject({ limit: 50, used: 60, remaining: 0 })
  })

  test('a management key is flagged: it cannot call models', () => {
    const r = parse(res(200, keyData({ is_management_key: true })), NOW)
    expect(r.notes).toContain('This is a management key: it manages API keys and cannot call models')
  })

  test('a key with nothing to measure is valid, not usage', () => {
    const r = parse(res(200, { data: { limit: null, usage: 0, is_free_tier: true } }), NOW)
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account?.plan).toBe('Free tier')
  })
})

describe('parse: errors', () => {
  test('401 "User not found." (invalid, expired or deleted key) -> invalid_key', () => {
    const r = parse(res(401, { error: { code: 401, message: 'User not found.' } }), NOW)
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, message: 'User not found.' })
  })

  test('401 "No cookie auth credentials found" -> invalid_key', () => {
    expect(parse(res(401, { error: { code: 401, message: 'No cookie auth credentials found' } }), NOW).error?.kind).toBe('invalid_key')
  })

  test('429 rate_limit_exceeded -> rate_limited', () => {
    const r = parse(res(429, { error: { code: 429, message: 'Rate limit exceeded', metadata: { error_type: 'rate_limit_exceeded' } } }), NOW)
    expect(r.error).toMatchObject({ kind: 'rate_limited', httpStatus: 429 })
  })

  test('402 -> quota_exhausted', () => {
    const r = parse(res(402, { error: { code: 402, message: 'Insufficient credits', metadata: { limit_source: 'key' } } }), NOW)
    expect(r.error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 402 })
  })

  test('5xx HTML -> provider_error', () => {
    expect(parse(html(502), NOW).error).toMatchObject({ kind: 'provider_error', message: 'the provider returned an error page' })
  })

  test('a 200 without `data` (or HTML) -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(res(200, { data: { name: 'x' } }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('probe', () => {
  test('LLM row contract: id, service, group, field', () => {
    expect(openrouterProbe).toMatchObject({
      id: 'llm-openrouter', service: 'openrouter', group: 'llm', field: 'apiKey', kind: 'usage', verifiedOn: null,
      endpoint: 'GET openrouter.ai/api/v1/key',
    })
    expect(openrouterProbe.rotationTool).toBeUndefined()
  })

  test('one call (never /credits); the key never reaches the result', async () => {
    for (const answer of [res(200, DOC_EXAMPLE), res(401, { error: { code: 401, message: 'User not found.' } })]) {
      const { result, requests } = await runProbe(openrouterProbe, KEY, [answer])
      expect(requests.map(r => r.url)).toEqual(['https://openrouter.ai/api/v1/key'])
      expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
    }
  })
})
