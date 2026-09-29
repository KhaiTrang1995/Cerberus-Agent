import { describe, test, expect } from 'vitest'
import { parse, request, serpapiProbe } from './serpapi'
import { html, res, runProbe, allStrings, reportRow } from '../testUtils'

const KEY = 'TESTKEY0000serpapi000000000000000000000000000000000000000000000'

const ACCOUNT = {
  account_id: 'acc-1', api_key: KEY, account_email: 'someone@example.test', account_status: 'Active',
  plan_id: 'bigdata', plan_name: 'Big Data Plan', plan_monthly_price: 250.0, plan_renewal_date: '2026-10-26',
  searches_per_month: 30000, plan_searches_left: 5958, extra_credits: 0, total_searches_left: 5958,
  this_month_usage: 24042, this_hour_searches: 87, last_hour_searches: 42, account_rate_limit_per_hour: 6000,
}

describe('request', () => {
  test('GET /account.json?api_key=', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: `https://serpapi.com/account.json?api_key=${KEY}` })
  })
})

describe('parse', () => {
  test('the documented example: monthly searches against the renewal date, hourly throughput', () => {
    const r = parse(res(200, ACCOUNT))
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Big Data Plan' })
    expect(r.meters.map(m => [m.id, m.used, m.limit, m.remaining, m.primary])).toEqual([
      ['monthly', 24042, 30000, 5958, true],
      ['hourly', 87, 6000, 5913, false],
    ])
    expect(r.meters[0]).toMatchObject({ resetsAt: '2026-10-26T00:00:00.000Z', resetsAtSource: 'provider' })
  })

  test('the echoed key and email never reach the result', () => {
    const strings = allStrings(parse(res(200, ACCOUNT))).join(' ')
    expect(strings).not.toContain(KEY)
    expect(strings).not.toContain('someone@example.test')
  })

  test('the renamed plan_next_renewal_date is read too; extra credits are a balance', () => {
    const r = parse(res(200, { ...ACCOUNT, plan_renewal_date: null, plan_next_renewal_date: '2026-11-01', extra_credits: 250 }))
    expect(r.meters[0].resetsAt).toBe('2026-11-01T00:00:00.000Z')
    expect(r.meters.find(m => m.id === 'extra')).toMatchObject({ window: 'balance', remaining: 250, primary: false })
  })

  // total_searches_left = plan_searches_left + extra_credits: the account keeps
  // searching on its extra credits once the plan's are gone.
  test('REGRESSION topup-balance-reads-exhausted: plan used up, extra credits left -> low, not exhausted', async () => {
    const row = await reportRow(serpapiProbe, { serpApiKey: KEY }, [
      res(200, { ...ACCOUNT, plan_searches_left: 0, this_month_usage: 30000, extra_credits: 250, total_searches_left: 250 }),
    ])
    expect(row.health).toBe('low')
    expect(row.notes).toContain('Plan searches are used up; searches now spend the 250 extra credits')
  })

  test('plan used up and no extra credits -> exhausted', async () => {
    const row = await reportRow(serpapiProbe, { serpApiKey: KEY }, [
      res(200, { ...ACCOUNT, plan_searches_left: 0, this_month_usage: 30000, extra_credits: 0, total_searches_left: 0 }),
    ])
    expect(row.health).toBe('exhausted')
  })

  test('no searches left at all -> exhausted override; a non-Active status becomes a note', () => {
    const r = parse(res(200, { ...ACCOUNT, plan_searches_left: 0, total_searches_left: 0, account_status: 'Throttled' }))
    expect(r.healthOverride).toBe('exhausted')
    expect(r.notes).toEqual(['Account status: Throttled'])
  })

  test.each([
    [401, { error: 'Invalid API key. Your API key should be here: https://serpapi.com/manage-api-key' }, 'invalid_key'],
    [403, { error: "The account doesn't have permission to perform this action." }, 'forbidden'],
    [429, { error: 'Your account has run out of searches.' }, 'quota_exhausted'],
    [429, { error: 'You have exceeded the hourly throughput limit.' }, 'rate_limited'],
    [500, { error: 'Internal error' }, 'provider_error'],
    [200, { error: 'Something odd' }, 'unexpected_response'],
  ])('%i %j -> %s', (status, payload, kind) => {
    expect(parse(res(status, payload)).error?.kind).toBe(kind)
  })

  test('a 503 HTML page -> provider_error', () => {
    expect(parse(html(503)).error?.kind).toBe('provider_error')
  })
})

test('run: one call', async () => {
  const { requests } = await runProbe(serpapiProbe, KEY, [res(200, ACCOUNT)])
  expect(requests).toHaveLength(1)
  expect(serpapiProbe.rotationTool).toBe('serp')
})
