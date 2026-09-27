/**
 * Driftnet usage probe (plan catalogue A25). Fixtures are synthetic, written
 * from the swagger `User` schema (the docs' JSON example is not valid JSON);
 * the tokens and the email are fake.
 */
import { describe, test, expect } from 'vitest'
import { driftnetProbe, parse, request } from './driftnet'
import { html, res, runProbe, allStrings } from '../testUtils'

const TOKEN = 'TESTKEY-0000-driftnet-primary-00000'
const OTHER = 'TESTKEY-0000-driftnet-ci-0000000000'
const EMAIL = 'someone@example.test'

const USER = {
  created: '2025-05-13T10:00:00Z',
  email: EMAIL,
  name: 'Sample Name',
  user_class: 'network_admin',
  paid: true,
  token: TOKEN,
  marketing: false,
  quota: {
    api_limit: 10000, api_usage: 2500, priority_limit: 100, priority_usage: 10, lifetime_usage: 50000,
    reset: '2026-09-13T00:00:00Z', next_reset: '2026-10-13T00:00:00Z', last_used: '2026-09-25T08:00:00Z',
  },
  additional_quota: [{
    token: OTHER, token_name: 'ci-runner',
    api_limit: 500, api_usage: 499, priority_limit: 0, priority_usage: 0, lifetime_usage: 1200,
    reset: '2026-09-13T00:00:00Z', next_reset: '2026-10-13T00:00:00Z',
  }],
  linked_users: [],
  private_flags: [],
}

describe('request', () => {
  test('Bearer + Accept, as uncover sends; the token never in the URL', () => {
    expect(request(TOKEN)).toEqual({
      method: 'GET',
      url: 'https://api.driftnet.io/v1/admin/user',
      headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/json' },
    })
  })
})

describe('parse: success', () => {
  test('the primary token: monthly operations, prioritizations, lifetime', () => {
    const r = parse(res(200, USER), TOKEN)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Paid · network_admin' })
    expect(r.meters).toEqual([
      { id: 'api', label: 'API operations', unit: 'requests', window: 'month', used: 2500, limit: 10000, remaining: 7500, resetsAt: '2026-10-13T00:00:00.000Z', resetsAtSource: 'provider', primary: true },
      { id: 'priority', label: 'Prioritizations', unit: 'count', window: 'month', used: 10, limit: 100, remaining: 90, resetsAt: '2026-10-13T00:00:00.000Z', resetsAtSource: 'provider', primary: false },
      { id: 'lifetime', label: 'Lifetime operations', unit: 'requests', window: 'lifetime', used: 50000, limit: null, remaining: null, resetsAt: null, resetsAtSource: null, primary: false },
    ])
  })

  test('an additional token of the same account gets its own quota', () => {
    const r = parse(res(200, USER), OTHER)
    expect(r.meters.map(m => m.id)).toEqual(['api', 'lifetime'])
    expect(r.meters[0]).toMatchObject({ used: 499, limit: 500, remaining: 1 })
  })

  test('a token matched nowhere falls back to the primary quota; the match ignores surrounding whitespace', () => {
    expect(parse(res(200, USER), 'TESTKEY-0000-unknown').meters[0]).toMatchObject({ limit: 10000 })
    expect(parse(res(200, USER), ` ${OTHER} `).meters[0]).toMatchObject({ limit: 500 })
  })

  test('usage past the limit never makes remaining negative; unpaid accounts read Free', () => {
    const r = parse(res(200, { ...USER, paid: false, quota: { ...USER.quota, api_usage: 12000 } }), TOKEN)
    expect(r.meters[0]).toMatchObject({ used: 12000, remaining: 0 })
    expect(r.account?.plan).toBe('Free · network_admin')
  })

  test('the tokens, the email and the name are never copied', () => {
    for (const key of [TOKEN, OTHER]) {
      const strings = allStrings(parse(res(200, USER), key)).join('\n')
      for (const secret of [TOKEN, OTHER, EMAIL, 'Sample Name', 'ci-runner']) expect(strings).not.toContain(secret)
    }
  })

  test('a 200 without a quota -> unexpected_response', () => {
    expect(parse(res(200, { user_class: 'x', token: TOKEN }), TOKEN).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('401 missing or non-Bearer header -> invalid_key', () => {
    expect(parse(res(401, { code: 401, message: 'this route requires authorization' }), TOKEN).error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
  })

  test('403 {code, message: "invalid token"} -> invalid_key', () => {
    expect(parse(res(403, { code: 403, message: 'invalid token' }), TOKEN).error).toMatchObject({ kind: 'invalid_key', httpStatus: 403, message: 'invalid token' })
  })

  test('403 {error} (the spec Error schema) -> quota_exhausted', () => {
    expect(parse(res(403, { error: 'quota exceeded for this period' }), TOKEN).error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 403 })
  })

  test('429 -> rate_limited; Cloudflare 524 -> provider_error', () => {
    expect(parse(res(429, { error: 'too many requests' }), TOKEN).error?.kind).toBe('rate_limited')
    expect(parse(html(524), TOKEN).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call, the token compared in memory and never returned', async () => {
    const { result, requests } = await runProbe(driftnetProbe, OTHER, [res(200, USER)])
    expect(requests).toHaveLength(1)
    expect(result.meters[0]).toMatchObject({ limit: 500 })
    expect(allStrings(result).some(s => s.includes(OTHER) || s.includes(TOKEN))).toBe(false)
  })

  test('registry wiring', () => {
    expect(driftnetProbe).toMatchObject({ id: 'driftnet', field: 'driftnetApiKey', rotationTool: 'driftnet', group: 'uncover', kind: 'usage', verifiedOn: null })
  })
})
