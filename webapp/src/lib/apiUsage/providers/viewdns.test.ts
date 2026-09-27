/**
 * ViewDNS usage probe (plan catalogue A18). A bad key is an HTTP 200 body
 * error and every number is a string. Fixtures are synthetic, from the
 * documented and observed shapes; the key is fake (never `demo`, which is the
 * site's real live-demo key).
 */
import { describe, test, expect } from 'vitest'
import { parse, request, viewdnsProbe } from './viewdns'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000viewdns00000000000000'
const QUERY = { tool: 'account_PRO', action: 'balance' }

function balance(response: Record<string, unknown>) {
  return { query: QUERY, response }
}

describe('request', () => {
  test('the key rides in the query string (ViewDNS takes it nowhere else)', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: `https://api.viewdns.info/account/?action=balance&apikey=${KEY}&output=json` })
    expect(r.headers).toBeUndefined()
  })

  test('a key with URL-special characters is encoded', () => {
    expect(request('a&b=c').url).toBe('https://api.viewdns.info/account/?action=balance&apikey=a%26b%3Dc&output=json')
  })
})

describe('parse: success', () => {
  test('documented example: string numbers, a subscription plus a prepaid balance', () => {
    const r = parse(res(200, balance({ monthly: { limit: '10000', usage: '3197' }, prepaid: { balance: '2000' } })))
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Subscription 10000/mo' })
    expect(r.meters).toEqual([
      { id: 'monthly', label: 'Queries (month)', unit: 'queries', window: 'month', used: 3197, limit: 10000, remaining: 6803, resetsAt: null, resetsAtSource: null, primary: true },
      { id: 'prepaid', label: 'Prepaid queries', unit: 'queries', window: 'balance', used: null, limit: null, remaining: 2000, resetsAt: null, resetsAtSource: null, primary: false },
    ])
  })

  test('no subscription: the monthly 0 is "not in plan" and the prepaid balance is primary', () => {
    const r = parse(res(200, balance({ monthly: { limit: '0', usage: '0' }, prepaid: { balance: '250' } })))
    expect(r.account?.plan).toBe('Prepaid / trial')
    expect(r.meters.map(m => [m.id, m.limit, m.remaining, m.primary])).toEqual([
      ['monthly', 0, 0, false],
      ['prepaid', null, 250, true],
    ])
    expect(parse(res(200, balance({ monthly: { limit: '0', usage: '0' }, prepaid: { balance: '0' } }))).account?.plan).toBe('No credits')
  })

  test('usage past the limit never makes remaining negative', () => {
    expect(parse(res(200, balance({ monthly: { limit: '1000', usage: '1200' } }))).meters[0]).toMatchObject({ used: 1200, remaining: 0 })
  })

  test('a 200 with neither balance -> unexpected_response', () => {
    expect(parse(res(200, balance({}))).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('bad key: HTTP 200 with response.error (observed) -> invalid_key', () => {
    const r = parse(res(200, balance({ error: 'Invalid API Key Provided.' })))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 200 })
  })

  test('bad action (HTTP 200) -> unexpected_response carrying the message', () => {
    const r = parse(res(200, balance({ error: 'Please specify a valid action.' })))
    expect(r.error).toMatchObject({ kind: 'unexpected_response', message: 'Please specify a valid action.' })
  })

  test('the newer envelope maps by error.code', () => {
    const env = (code: number, message: string) => res(code, { success: false, error: { code, message } })
    expect(parse(env(401, 'Invalid API key.')).error).toMatchObject({ kind: 'invalid_key', providerCode: '401' })
    expect(parse(env(403, 'This API key does not have access to this tool.')).error?.kind).toBe('forbidden')
    expect(parse(env(429, 'This API key has reached its monthly query limit and/or you have no prepaid queries remaining.')).error?.kind).toBe('quota_exhausted')
    expect(parse(env(400, 'Bad request.')).error?.kind).toBe('unexpected_response')
  })

  test('the legacy plain-text limit answer -> quota_exhausted', () => {
    expect(parse(res(200, 'Query limit reached for the supplied API key.')).error?.kind).toBe('quota_exhausted')
  })

  test('Cloudflare: 5xx -> provider_error, a 403 challenge page -> unexpected_response', () => {
    expect(parse(html(503)).error?.kind).toBe('provider_error')
    expect(parse(html(403)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(viewdnsProbe, KEY, [res(200, balance({ error: 'Invalid API Key Provided.' }))])
    expect(requests).toHaveLength(1)
    expect(result.error?.kind).toBe('invalid_key')
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring; the cost note says the cost is undocumented', () => {
    expect(viewdnsProbe).toMatchObject({ id: 'viewdns', field: 'viewdnsApiKey', rotationTool: 'viewdns', group: 'keys', kind: 'usage' })
    expect(viewdnsProbe.costNote).toMatch(/undocumented/i)
    expect(viewdnsProbe.endpoint).not.toContain('apikey')
  })
})
