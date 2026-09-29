import { describe, test, expect } from 'vitest'
import { parse, request, virustotalProbe } from './virustotal'
import { NOW, html, res, runProbe } from '../testUtils'

const KEY = 'TESTKEY0000virustotal000000000000000000000000000000000000000000'

describe('request', () => {
  test('GET /users/{key}/overall_quotas with the x-apikey header', () => {
    expect(request(KEY)).toEqual({
      method: 'GET',
      url: `https://www.virustotal.com/api/v3/users/${KEY}/overall_quotas`,
      headers: { 'x-apikey': KEY },
    })
  })
})

describe('parse', () => {
  test('a public (free) key: user quotas only, daily/monthly are primary', () => {
    const r = parse(res(200, { data: {
      api_requests_hourly: { user: { allowed: 240, used: 4 } },
      api_requests_daily: { user: { allowed: 500, used: 74 } },
      api_requests_monthly: { user: { allowed: 15500, used: 900 } },
      monitor_storage_bytes: { user: { allowed: 0, used: 0 } },
    } }), NOW)
    expect(r.account?.plan).toBe('Public (free)')
    expect(r.meters.map(m => [m.id, m.window, m.used, m.limit, m.remaining, m.primary])).toEqual([
      ['api_requests_hourly', 'hour', 4, 240, 236, false],
      ['api_requests_daily', 'day', 74, 500, 426, true],
      ['api_requests_monthly', 'month', 900, 15500, 14600, true],
    ])
    expect(r.meters[1]).toMatchObject({ resetsAt: '2026-09-27T00:00:00.000Z', resetsAtSource: 'computed' })
    expect(r.meters.map(m => m.label)).toEqual(['API requests (hour)', 'API requests (day)', 'API requests (month)'])
  })

  test('the XSOAR premium fixture: group quotas, sentinel caps, a tighter personal cap', () => {
    const r = parse(res(200, { data: {
      api_requests_daily: { group: { allowed: 30000000, inherited_from: 'acme_group', used: 535676 }, user: { allowed: 1000, used: 74 } },
      api_requests_hourly: { group: { allowed: 1800000, inherited_from: 'acme_group', used: 8712 }, user: { allowed: 60000000000, used: 12 } },
      intelligence_hunting_rules: { group: { allowed: 25, inherited_from: 'acme_group', used: 1829 }, user: { allowed: 0, used: 3 } },
      monitor_storage_bytes: { user: { allowed: 0, used: 0 } },
    } }), NOW)
    expect(r.account?.plan).toBe('Premium via acme_group')
    const daily = r.meters.find(m => m.id === 'api_requests_daily')!
    expect(daily).toMatchObject({ limit: 30000000, used: 535676, note: 'group: acme_group' })
    // The personal cap (1000) is tighter than the group's: it is the one that bites.
    expect(r.meters.find(m => m.id === 'api_requests_daily.user')).toMatchObject({ limit: 1000, used: 74, remaining: 926, primary: true })
    // used can exceed allowed: remaining clamps at 0.
    expect(r.meters.find(m => m.id === 'intelligence_hunting_rules')).toMatchObject({ limit: 25, remaining: 0, window: 'balance' })
    expect(r.meters.some(m => m.id === 'monitor_storage_bytes')).toBe(false)
  })

  test('the 1e9+ sentinel means no personal cap', () => {
    const r = parse(res(200, { data: { api_requests_daily: { user: { allowed: 1000000000, used: 5 } } } }), NOW)
    expect(r.meters[0]).toMatchObject({ limit: null, remaining: null, note: 'no personal cap' })
    expect(r.account?.plan).toBe('Premium')
  })

  test.each([
    [401, 'AuthenticationRequiredError', 'X-Apikey header is missing', 'invalid_key'],
    [401, 'WrongCredentialsError', 'Wrong API key', 'invalid_key'],
    [403, 'ForbiddenError', 'You are not allowed', 'forbidden'],
    [404, 'NotFoundError', 'not found', 'unexpected_response'],
    [429, 'QuotaExceededError', 'Quota exceeded', 'quota_exhausted'],
    [429, 'TooManyRequestsError', 'Too many requests', 'rate_limited'],
    [503, 'TransientError', 'try again', 'provider_error'],
  ])('%i %s -> %s', (status, code, message, kind) => {
    const r = parse(res(status, { error: { code, message } }), NOW)
    expect(r.error?.kind).toBe(kind)
  })

  test('an inactive account is named as such', () => {
    const r = parse(res(401, { error: { code: 'UserNotActiveError', message: 'User is not active' } }), NOW)
    expect(r.error?.message).toMatch(/not activated/)
    expect(r.error?.providerCode).toBe('UserNotActiveError')
  })

  test('5xx HTML and shape drift', () => {
    expect(parse(html(504), NOW).error?.kind).toBe('provider_error')
    expect(parse(res(200, { data: 'nope' }), NOW).error?.kind).toBe('unexpected_response')
  })
})

test('run: one call, key in the path (never logged: the runner logs no URLs)', async () => {
  const { requests } = await runProbe(virustotalProbe, KEY, [res(200, { data: { api_requests_daily: { user: { allowed: 500, used: 1 } } } })])
  expect(requests).toHaveLength(1)
  expect(virustotalProbe.endpoint).not.toContain(KEY)
})
