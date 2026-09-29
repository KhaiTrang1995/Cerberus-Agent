import { describe, test, expect } from 'vitest'
import { parse, publicwwwProbe, request } from './publicwww'
import { NOW, html, res, runProbe } from '../testUtils'

const KEY = 'TESTKEY0000publicwww0000'

describe('request', () => {
  test('GET api.publicwww.com/v1/account with a bearer key (never the legacy ?key=)', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://api.publicwww.com/v1/account', headers: { Authorization: `Bearer ${KEY}` } })
    expect(r.url).not.toContain(KEY)
  })
})

describe('parse', () => {
  test('the documented example: daily searches and snippets with the provider reset', () => {
    const r = parse(res(200, {
      plan: 'enterprise', plan_until: 1819461840, full_access: true,
      quota: { searches: { limit: 300, used: 12, resets_at: 1787961600 }, snippets: { limit: 100, used: 3, resets_at: 1787961600 } },
      limits: { disclosed_positions: 4294967295, disclosed_positions_snippets: 4294967295, max_per_page: 1000000, max_per_page_snippets: 10000 },
    }), NOW)
    expect(r.account).toEqual({ plan: 'enterprise', expiresAt: '2027-08-28T14:04:00.000Z' })
    expect(r.meters.map(m => [m.id, m.used, m.limit, m.remaining, m.primary, m.resetsAt])).toEqual([
      ['searches', 12, 300, 288, true, '2026-08-29T00:00:00.000Z'],
      ['snippets', 3, 100, 97, false, '2026-08-29T00:00:00.000Z'],
    ])
  })

  test('no quota object: fall back to the X-RateLimit-* / X-Snippets-* headers', () => {
    const r = parse(res(200, { plan: 'pro' }, { headers: {
      'X-RateLimit-Limit': '300', 'X-RateLimit-Remaining': '250', 'X-RateLimit-Reset': '1787961600',
      'X-Snippets-Limit': '100', 'X-Snippets-Remaining': '100',
    } }), NOW)
    expect(r.meters.map(m => [m.id, m.used, m.limit, m.remaining])).toEqual([
      ['searches', 50, 300, 250],
      ['snippets', 0, 100, 100],
    ])
    expect(r.meters[1].resetsAtSource).toBe('computed')
  })

  test('an account with no plan is still valid', () => {
    const r = parse(res(200, { plan: null }), NOW)
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account?.plan).toBe('No plan')
  })

  test.each([
    [401, 'missing_key', 'invalid_key'],
    [401, 'invalid_key', 'invalid_key'],
    [403, 'plan_required', 'forbidden'],
    [429, 'too_many_requests', 'rate_limited'],
    [429, 'quota_exceeded', 'quota_exhausted'],
    [429, 'snippet_quota_exceeded', 'quota_exhausted'],
  ])('%i %s -> %s', (status, code, kind) => {
    const r = parse(res(status, { error: { code, message: 'x' } }), NOW)
    expect(r.error).toMatchObject({ kind, providerCode: code })
  })

  test('5xx HTML -> provider_error; a 200 challenge page -> unexpected_response', () => {
    expect(parse(html(502), NOW).error?.kind).toBe('provider_error')
    expect(parse(html(200, '<html><body>Checking your browser before continuing</body></html>'), NOW).error?.kind).toBe('unexpected_response')
  })
})

test('run: one call; pool keys 15 s apart (2 requests / 30 s)', async () => {
  const { requests } = await runProbe(publicwwwProbe, KEY, [res(200, { plan: 'pro' })])
  expect(requests).toHaveLength(1)
  expect(publicwwwProbe.minIntervalMs).toBe(15_000)
})
