/**
 * Netlas usage probe (plan catalogue A13). Two calls: users/current proves the
 * key, then the public profile_data holds the counters. Fixtures are synthetic,
 * written from the OpenAPI examples; the key and the email are fake.
 */
import { describe, test, expect } from 'vitest'
import { countersRequest, netlasProbe, parse, parseCounters, request } from './netlas'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY-0000-netlas-000000000000000'
const EMAIL = 'someone@example.test'

const PROFILE = {
  email: EMAIL,
  first_name: 'Sample',
  last_name: 'User',
  referral_code: 'REF-0000',
  api_key: { customer_api_key: KEY },
  plan: { id: 7, name: 'Business', is_free: false, subscription_period: 'month', active_until: '2027-01-15', coins: 100000000 },
  plan_active_until: '2027-01-15',
  next_plan: null,
  bonuses: 0,
}

// The OpenAPI `user_counters` example.
const COUNTERS = {
  requests_left: { remained: -1, limit: -1, will_be_updated: null },
  coins: { total_coins_spent: 432221783, left: 99996653, plan_coins_amount: 100000000 },
  scan_coins: { plan_scan_coins_amount: 327680, left: 327680, reserved_coins: 0 },
}

describe('request', () => {
  test('users/current with the X-API-Key header recon sends; the key never in the URL', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://app.netlas.io/api/users/current/', headers: { 'X-API-Key': KEY } })
  })

  test('profile_data carries the same header', () => {
    expect(countersRequest(KEY)).toEqual({ method: 'GET', url: 'https://app.netlas.io/api/users/profile_data/', headers: { 'X-API-Key': KEY } })
  })
})

describe('parse (users/current)', () => {
  test('a profile -> valid, with the plan and its expiry', () => {
    const r = parse(res(200, PROFILE))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account).toEqual({ plan: 'Business', expiresAt: '2027-01-15T00:00:00.000Z' })
  })

  test('the echoed key and the PII are never copied', () => {
    const strings = allStrings(parse(res(200, PROFILE))).join('\n')
    expect(strings).not.toContain(KEY)
    expect(strings).not.toContain(EMAIL)
    expect(strings).not.toContain('Sample')
    expect(strings).not.toContain('REF-0000')
  })

  test('a plan without expiry leaves expiresAt unset', () => {
    const r = parse(res(200, { ...PROFILE, plan: { name: 'Community' }, plan_active_until: null }))
    expect(r.account).toEqual({ plan: 'Community', expiresAt: undefined })
  })

  test('invalid key is a 400 "API key not found", not a 401', () => {
    const r = parse(res(400, { detail: 'Request had invalid authorization credentials: API key not found' }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 400 })
  })

  test('any other 400 is a malformed request -> unexpected_response', () => {
    expect(parse(res(400, { detail: 'JSON parse error - Expecting value' })).error?.kind).toBe('unexpected_response')
  })

  test('401 (missing credentials) -> invalid_key', () => {
    expect(parse(res(401, { detail: 'Authentication credentials were not provided.' })).error?.kind).toBe('invalid_key')
  })

  test('500 -> provider_error', () => {
    expect(parse(html(500)).error?.kind).toBe('provider_error')
  })

  test('a 200 that is not a profile -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parseCounters (profile_data)', () => {
  const account = { plan: 'Business' }

  test('OpenAPI example: -1 is unlimited, coins used = plan - left', () => {
    const r = parseCounters(res(200, COUNTERS), account)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual(account)
    expect(r.meters).toEqual([
      { id: 'requests', label: 'Requests', unit: 'requests', window: 'day', used: null, limit: null, remaining: null, resetsAt: null, resetsAtSource: null, primary: false, note: 'unlimited' },
      { id: 'coins', label: 'Netlas Coins', unit: 'coins', window: 'month', used: 3347, limit: 100000000, remaining: 99996653, resetsAt: null, resetsAtSource: null, primary: true },
      { id: 'scan_coins', label: 'Scan coins', unit: 'coins', window: 'month', used: null, limit: 327680, remaining: 327680, resetsAt: null, resetsAtSource: null, primary: false },
    ])
  })

  test('finite quotas with refresh dates; a plan without scan coins shows none', () => {
    const r = parseCounters(res(200, {
      requests_left: { remained: 40, limit: 50, will_be_updated: '2026-09-27T00:00:00Z' },
      coins: { total_coins_spent: 5000, left: 0, plan_coins_amount: 1000, next_time_coins_will_be_updated: '2026-10-13' },
      scan_coins: { plan_scan_coins_amount: 0, left: 0, reserved_coins: 0 },
    }), account)
    expect(r.meters).toEqual([
      { id: 'requests', label: 'Requests', unit: 'requests', window: 'day', used: 10, limit: 50, remaining: 40, resetsAt: '2026-09-27T00:00:00.000Z', resetsAtSource: 'provider', primary: true },
      { id: 'coins', label: 'Netlas Coins', unit: 'coins', window: 'month', used: 1000, limit: 1000, remaining: 0, resetsAt: '2026-10-13T00:00:00.000Z', resetsAtSource: 'provider', primary: true },
    ])
  })

  test('unlimited coins: no limit, no used, noted', () => {
    const r = parseCounters(res(200, { ...COUNTERS, coins: { left: -1, plan_coins_amount: -1, total_coins_spent: 0 } }), account)
    expect(r.meters.find(m => m.id === 'coins')).toMatchObject({ used: null, limit: null, remaining: null, note: 'unlimited' })
  })

  test('a failed counters call keeps the account and never blames the key', () => {
    const r = parseCounters(html(503), account)
    expect(r.error).toMatchObject({ kind: 'provider_error', httpStatus: 503 })
    expect(r.error?.message).toContain('the key works')
    expect(r.account).toEqual(account)
    expect(parseCounters(res(401, { detail: 'nope' }), account).error?.kind).toBe('unexpected_response')
    expect(parseCounters(res(429, { detail: 'Request was throttled.' }), account).error?.kind).toBe('rate_limited')
  })

  test('counters without the required objects -> unexpected_response, account kept', () => {
    const r = parseCounters(res(200, { requests_left: {} }), account)
    expect(r.error?.kind).toBe('unexpected_response')
    expect(r.account).toEqual(account)
  })
})

describe('run', () => {
  test('users/current first, then profile_data; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(netlasProbe, KEY, [res(200, PROFILE), res(200, COUNTERS)])
    expect(requests.map(r => `${r.method} ${r.url}`)).toEqual([
      'GET https://app.netlas.io/api/users/current/',
      'GET https://app.netlas.io/api/users/profile_data/',
    ])
    expect(result.outcome).toBe('usage')
    expect(result.account?.plan).toBe('Business')
    const strings = allStrings(result).join('\n')
    expect(strings).not.toContain(KEY)
    expect(strings).not.toContain(EMAIL)
  })

  test('a rejected key stops after the first call: profile_data cannot tell a bad key', async () => {
    const { result, requests } = await runProbe(netlasProbe, KEY, [
      res(400, { detail: 'Request had invalid authorization credentials: API key not found' }),
    ])
    expect(requests).toHaveLength(1)
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('registry wiring', () => {
    expect(netlasProbe).toMatchObject({ id: 'netlas', field: 'netlasApiKey', rotationTool: 'netlas', group: 'keys', kind: 'usage', verifiedOn: '2026-09-27' })
    expect(netlasProbe.endpoint).toBe('GET app.netlas.io/api/users/current/')
  })
})
