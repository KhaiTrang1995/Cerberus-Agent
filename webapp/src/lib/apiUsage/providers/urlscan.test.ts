import { describe, test, expect } from 'vitest'
import { parse, request, urlscanProbe } from './urlscan'
import { NOW, html, res, runProbe } from '../testUtils'

const KEY = '01234567-89ab-cdef-0123-TESTKEY00000'

describe('request', () => {
  test('GET /api/v1/quotas with the exact API-Key header', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://urlscan.io/api/v1/quotas', headers: { 'API-Key': KEY } })
  })
})

describe('parse', () => {
  test('meters per action and window; primary = day windows of search/public/private with a limit', () => {
    const r = parse(res(200, {
      scope: 'team',
      limits: {
        search: {
          minute: { limit: 120, used: 0, remaining: 120, percent: 0 },
          day: { limit: 500000, used: 1389, remaining: 498611, percent: 0, reset: '2026-09-27T00:00:00.000Z' },
        },
        private: { day: { limit: 2500, used: 10, remaining: 2490, percent: 0, reset: '2026-09-27T00:00:00.000Z' } },
        livescan: { day: { limit: 0, used: 0, remaining: 0, percent: 100 } },
        'files.public': { hour: { limit: 50, used: 0, remaining: 50, percent: 0 } },
        maxSearchResults: 10000,
        products: ['livescan', 'pro'],
      },
      products: ['pro'],
    }), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'urlscan Pro', label: 'quota scope: team' })
    const ids = r.meters.map(m => m.id)
    expect(ids).toEqual(['search.minute', 'search.day', 'private.day', 'livescan.day', 'files.public.hour'])
    expect(r.meters.find(m => m.id === 'search.day')).toMatchObject({ primary: true, used: 1389, limit: 500000, remaining: 498611, resetsAtSource: 'provider' })
    expect(r.meters.find(m => m.id === 'search.minute')).toMatchObject({ primary: false, resetsAt: '2026-09-26T14:33:00.000Z', resetsAtSource: 'computed' })
    expect(r.meters.find(m => m.id === 'livescan.day')).toMatchObject({ primary: false, limit: 0, note: 'not in plan' })
    expect(r.meters.find(m => m.id === 'files.public.hour')?.label).toBe('Public file downloads (hour)')
  })

  test('anonymous scope means the key was not applied, never the key\'s quotas', () => {
    const r = parse(res(200, { scope: 'ip-address', limits: { search: { day: { limit: 500, used: 0, remaining: 500 } } } }), NOW)
    expect(r.error?.kind).toBe('unexpected_response')
    expect(r.error?.message).toMatch(/not applied/)
  })

  test.each([
    [400, { message: 'Invalid API key format', status: 400 }, 'invalid_key'],
    [401, { message: 'API key supplied but not found in database!', status: 401 }, 'invalid_key'],
    [429, { message: 'Rate limit exceeded', status: 429 }, 'rate_limited'],
  ])('%i -> %s', (status, payload, kind) => {
    const r = parse(res(status, payload), NOW)
    expect(r.error?.kind).toBe(kind)
    expect(r.error?.message).toBe(payload.message)
  })

  test('5xx HTML -> provider_error; a 200 without limits -> unexpected_response', () => {
    expect(parse(html(502), NOW).error?.kind).toBe('provider_error')
    expect(parse(res(200, { scope: 'user' }), NOW).error?.kind).toBe('unexpected_response')
  })
})

test('run: one call', async () => {
  const { requests } = await runProbe(urlscanProbe, KEY, [res(200, { scope: 'user', limits: { search: { day: { limit: 1000, used: 1, remaining: 999 } } } })])
  expect(requests).toHaveLength(1)
})
