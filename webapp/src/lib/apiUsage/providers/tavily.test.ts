import { describe, test, expect } from 'vitest'
import { parse, request, tavilyProbe } from './tavily'
import { NOW, html, res, runProbe, reportRow } from '../testUtils'

const KEY = 'tvly-TESTKEY-0000'

describe('request', () => {
  test('GET /usage with a bearer key and no X-Project-ID (whole-key numbers)', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://api.tavily.com/usage', headers: { Authorization: `Bearer ${KEY}` } })
  })
})

describe('parse', () => {
  test('the OpenAPI example: plan, pay-go and per-key meters', () => {
    const r = parse(res(200, {
      key: { usage: 150, limit: 1000, search_usage: 100, extract_usage: 25, crawl_usage: 15, map_usage: 7, research_usage: 3 },
      account: { current_plan: 'Bootstrap', plan_usage: 500, plan_limit: 15000, paygo_usage: 25, paygo_limit: 100 },
    }), NOW)
    expect(r.account?.plan).toBe('Bootstrap')
    expect(r.meters.map(m => [m.id, m.used, m.limit, m.remaining, m.primary])).toEqual([
      ['plan', 500, 15000, 14500, true],
      ['paygo', 25, 100, 75, false],
      ['key', 150, 1000, 850, true],
    ])
    expect(r.meters[0]).toMatchObject({ resetsAt: '2026-10-01T00:00:00.000Z', resetsAtSource: 'computed' })
  })

  test('no per-key cap: the key meter is secondary and says so; no pay-go meter when off', () => {
    const r = parse(res(200, {
      key: { usage: 12, limit: null },
      account: { current_plan: 'Researcher', plan_usage: 12, plan_limit: 1000, paygo_usage: 0, paygo_limit: null },
    }), NOW)
    expect(r.meters.map(m => m.id)).toEqual(['plan', 'key'])
    expect(r.meters[1]).toMatchObject({ primary: false, limit: null, note: 'no per-key cap' })
  })

  test.each([
    [401, { detail: { error: 'Unauthorized: missing or invalid API key.' } }, 'invalid_key'],
    [429, { detail: { error: 'Your request has been blocked due to excessive requests.' } }, 'rate_limited'],
    [432, { detail: { error: 'This request exceeds your plan\'s set usage limit.' } }, 'quota_exhausted'],
    [433, { detail: { error: 'This request exceeds the pay-as-you-go limit.' } }, 'quota_exhausted'],
    [403, { detail: { error: 'Forbidden' } }, 'forbidden'],
    [500, { detail: { error: 'Internal Server Error' } }, 'provider_error'],
  ])('%i -> %s', (status, payload, kind) => {
    const r = parse(res(status, payload), NOW)
    expect(r.error?.kind).toBe(kind)
    expect(r.error?.httpStatus).toBe(status)
  })

  // Pay-as-you-go is what the account runs on once the plan credits are gone.
  const USED_UP = { current_plan: 'Researcher', plan_usage: 1000, plan_limit: 1000 }
  test('REGRESSION topup-balance-reads-exhausted: plan used up, pay-as-you-go room -> low, not exhausted', async () => {
    const row = await reportRow(tavilyProbe, { tavilyApiKey: KEY }, [
      res(200, { key: { usage: 1010, limit: null }, account: { ...USED_UP, paygo_usage: 10, paygo_limit: 500 } }),
    ])
    expect(row.health).toBe('low')
    expect(row.notes).toContain('Plan credits are used up; calls now spend pay-as-you-go credits')
  })

  test.each([
    ['pay-as-you-go off', { paygo_usage: 0, paygo_limit: null }, { usage: 1000, limit: null }],
    ['pay-as-you-go cap reached', { paygo_usage: 500, paygo_limit: 500 }, { usage: 1500, limit: null }],
    ['this key\'s own cap reached', { paygo_usage: 10, paygo_limit: 500 }, { usage: 200, limit: 200 }],
  ])('plan used up, %s -> exhausted', async (_n, paygo, key) => {
    const row = await reportRow(tavilyProbe, { tavilyApiKey: KEY }, [res(200, { key, account: { ...USED_UP, ...paygo } })])
    expect(row.health).toBe('exhausted')
  })

  test('the detail.error message is surfaced', () => {
    expect(parse(res(401, { detail: { error: 'Unauthorized: missing API key.' } }), NOW).error?.message).toBe('Unauthorized: missing API key.')
  })

  test('a 200 without key or account -> unexpected_response', () => {
    expect(parse(res(200, {}), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), NOW).error?.kind).toBe('unexpected_response')
  })
})

test('run: one call per key', async () => {
  const { requests } = await runProbe(tavilyProbe, KEY, [res(200, { key: { usage: 1 }, account: { plan_usage: 1, plan_limit: 1000 } })])
  expect(requests).toHaveLength(1)
  expect(tavilyProbe.rotationTool).toBe('tavily')
})
