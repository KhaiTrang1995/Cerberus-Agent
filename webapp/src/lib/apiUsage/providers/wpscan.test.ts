import { describe, test, expect } from 'vitest'
import { parse, request, wpscanProbe } from './wpscan'
import { html, res, runProbe } from '../testUtils'

const TOKEN = 'TESTKEY0000wpscan0000000000000000000000000'

describe('request', () => {
  test('GET /api/v3/status with the exact "Token token=" header, key never in the URL', () => {
    const r = request(TOKEN)
    expect(r).toEqual({ method: 'GET', url: 'https://wpscan.com/api/v3/status', headers: { Authorization: `Token token=${TOKEN}` } })
    expect(r.url).not.toContain(TOKEN)
  })
})

describe('parse', () => {
  test('free plan: daily requests with the provider reset time', () => {
    const r = parse(res(200, { success: true, plan: 'free', requests_limit: 25, requests_remaining: 20, requests_reset: 1790000000 }))
    expect(r.account?.plan).toBe('Researcher (free)')
    expect(r.meters).toEqual([{
      id: 'daily', label: 'API requests (day)', unit: 'requests', window: 'day',
      used: 5, limit: 25, remaining: 20, resetsAt: '2026-09-21T14:13:20.000Z', resetsAtSource: 'provider', primary: true,
    }])
  })

  test('-1 remaining means unlimited', () => {
    const r = parse(res(200, { plan: 'enterprise', requests_remaining: -1 }))
    expect(r.meters[0]).toMatchObject({ limit: null, remaining: null, note: 'unlimited', primary: true })
    expect(r.account?.plan).toBe('enterprise')
  })

  test('old responses without requests_limit/reset still report what they have', () => {
    const r = parse(res(200, { plan: 'free', requests_remaining: 3 }))
    expect(r.meters[0]).toMatchObject({ limit: null, used: null, remaining: 3, resetsAt: null })
  })

  test.each([
    [401, { status: 'unauthorized' }, 'invalid_key'],
    [403, { status: 'forbidden' }, 'invalid_key'],
    [429, { status: 'rate limit hit' }, 'rate_limited'],
    [404, { error: 'Not found' }, 'unexpected_response'],
    [502, 'Bad gateway', 'provider_error'],
  ])('%i -> %s', (status, payload, kind) => {
    expect(parse(res(status, payload)).error?.kind).toBe(kind)
  })

  test('the 200 HTML bot-check page is not a status', () => {
    const r = parse(html(200, '<html><head><title>Browser check</title></head></html>'))
    expect(r.error?.kind).toBe('unexpected_response')
  })
})

test('run: one call; rotation rows are checked (Phase 0 now persists them)', async () => {
  const { requests } = await runProbe(wpscanProbe, TOKEN, [res(200, { plan: 'free', requests_remaining: 25, requests_limit: 25 })])
  expect(requests).toHaveLength(1)
  expect(wpscanProbe.rotationTool).toBe('wpscan')
})
