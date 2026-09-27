/**
 * Shodan usage probe (plan catalogue A3). Fixtures are synthetic, written from
 * the documented examples; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, request, shodanProbe } from './shodan'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000shodanAAAAAAAAAAAAAAA'

describe('request', () => {
  test('GET /api-info with the key in the lowercase `key` query param', () => {
    const r = request(KEY)
    expect(r.method).toBe('GET')
    expect(r.url).toBe(`https://api.shodan.io/api-info?key=${KEY}`)
    expect(r.headers).toBeUndefined()
  })

  test('a key with URL-special characters is encoded', () => {
    expect(request('a&b=c').url).toBe('https://api.shodan.io/api-info?key=a%26b%3Dc')
  })
})

describe('parse: success', () => {
  test('documented stream-100 example: -1 limits mean remaining-only meters', () => {
    const r = parse(res(200, {
      scan_credits: 100000, usage_limits: { scan_credits: -1, query_credits: -1, monitored_ips: -1 },
      plan: 'stream-100', https: false, unlocked: true, query_credits: 100000, monitored_ips: 19,
      unlocked_left: 100000, telnet: false,
    }), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account?.plan).toBe('stream-100')
    const q = r.meters.find(m => m.id === 'query_credits')!
    expect(q).toMatchObject({ limit: null, remaining: 100000, used: null, primary: true, window: 'month', unit: 'credits' })
    expect(q.resetsAt).toBe('2026-10-01T00:00:00.000Z')
    expect(q.resetsAtSource).toBe('computed')
    expect(r.meters.find(m => m.id === 'monitored_ips')).toMatchObject({ used: 19, limit: null, remaining: null, primary: false })
  })

  test('membership plan with usage_limits: used = cap - remaining', () => {
    const r = parse(res(200, {
      plan: 'dev', query_credits: 84, scan_credits: 0, monitored_ips: 3,
      usage_limits: { query_credits: 100, scan_credits: 100, monitored_ips: 16 },
    }), NOW)
    expect(r.account?.plan).toBe('Membership (dev)')
    expect(r.meters.find(m => m.id === 'query_credits')).toMatchObject({ limit: 100, remaining: 84, used: 16 })
    expect(r.meters.find(m => m.id === 'scan_credits')).toMatchObject({ limit: 100, remaining: 0, used: 100, primary: false })
    expect(r.meters.find(m => m.id === 'monitored_ips')).toMatchObject({ used: 3, limit: 16, remaining: 13 })
  })

  test('bonus credits above the cap never make `used` negative', () => {
    const r = parse(res(200, { plan: 'dev', query_credits: 150, scan_credits: 0, usage_limits: { query_credits: 100 } }), NOW)
    expect(r.meters.find(m => m.id === 'query_credits')).toMatchObject({ limit: 100, remaining: 150, used: 0 })
  })

  test('the free oss plan is 0/0 "not in plan", not exhausted', () => {
    const r = parse(res(200, { https: false, unlocked: false, unlocked_left: 0, telnet: false, scan_credits: 0, plan: 'oss', query_credits: 0 }), NOW)
    expect(r.account?.plan).toBe('Free (oss)')
    const q = r.meters.find(m => m.id === 'query_credits')!
    expect(q).toMatchObject({ limit: 0, remaining: 0, note: 'no credits included in this plan' })
    expect(r.healthOverride).toBeUndefined()
  })
})

describe('parse: errors', () => {
  test('401 nginx HTML page (missing or invalid key) -> invalid_key, no JSON parse attempted', () => {
    const r = parse(html(401, '<html><head><title>401 Unauthorized</title></head></html>'), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
  })

  test('403 -> forbidden', () => {
    expect(parse(res(403, 'Access denied (403 Forbidden)'), NOW).error?.kind).toBe('forbidden')
  })

  test('1 rps limit message -> rate_limited', () => {
    const r = parse(res(429, { error: 'Request rate limit reached (1 request/ second). Please wait a second before trying again and slow down your API calls.' }), NOW)
    expect(r.error?.kind).toBe('rate_limited')
  })

  test('502 -> provider_error', () => {
    expect(parse(html(502), NOW).error?.kind).toBe('provider_error')
  })

  test('an `error` field on a 200 is still an error', () => {
    const r = parse(res(200, { error: 'Invalid API key' }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 200 })
  })

  test('a 200 without the plan fields -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call, and the key never appears in the result', async () => {
    const { result, requests } = await runProbe(shodanProbe, KEY, [res(200, { plan: 'dev', query_credits: 5, scan_credits: 1 })])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('paces pool keys 1.1 s apart (Shodan limits every method to 1 req/s)', () => {
    expect(shodanProbe.minIntervalMs).toBe(1100)
    expect(shodanProbe.rotationTool).toBe('shodan')
    expect(shodanProbe.field).toBe('shodanApiKey')
  })
})
