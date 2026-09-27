/**
 * SecurityTrails usage probe (plan catalogue A17). The bad-key 401 is plain
 * text without a Content-Type, so these tests feed text, not JSON. Fixtures
 * are synthetic, from the documented example; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, request, securitytrailsProbe } from './securitytrails'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000securitytrails0000000'

describe('request', () => {
  test('GET account/usage with the APIKEY header recon sends; the key never in the URL', () => {
    expect(request(KEY)).toEqual({
      method: 'GET',
      url: 'https://api.securitytrails.com/v1/account/usage',
      headers: { APIKEY: KEY, Accept: 'application/json' },
    })
  })
})

describe('parse: success', () => {
  test('documented example: monthly used / allowed, reset on the 1st (computed)', () => {
    const r = parse(res(200, { current_monthly_usage: 100, allowed_monthly_usage: 10000 }), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account?.plan).toBeUndefined()
    expect(r.meters).toEqual([
      { id: 'monthly_queries', label: 'API queries (month)', unit: 'queries', window: 'month', used: 100, limit: 10000, remaining: 9900, resetsAt: '2026-10-01T00:00:00.000Z', resetsAtSource: 'computed', primary: true },
    ])
  })

  test('an allowance of 50 reads as the Free plan (heuristic)', () => {
    expect(parse(res(200, { current_monthly_usage: 3, allowed_monthly_usage: 50 }), NOW).account?.plan).toBe('Free (50/month)')
  })

  test('the soft quota can be passed: remaining is clamped to 0', () => {
    expect(parse(res(200, { current_monthly_usage: 60, allowed_monthly_usage: 50 }), NOW).meters[0]).toMatchObject({ used: 60, limit: 50, remaining: 0 })
  })

  test('a 200 without the allowance -> unexpected_response', () => {
    expect(parse(res(200, { success: true }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('401 plain text without Content-Type -> invalid_key carrying the text', () => {
    const r = parse(res(401, 'Please check user credentials', { contentType: '' }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, message: 'Please check user credentials' })
  })

  test('429 "API rate limit exceeded" -> rate_limited; any other 429 -> quota_exhausted', () => {
    expect(parse(res(429, { message: 'API rate limit exceeded' }), NOW).error?.kind).toBe('rate_limited')
    expect(parse(res(429, { message: "You've exceeded the usage limits for your account." }), NOW).error?.kind).toBe('quota_exhausted')
  })

  test('403 feature not in the plan -> forbidden; 5xx -> provider_error', () => {
    expect(parse(res(403, { message: 'This feature is not available for your subscription package' }), NOW).error?.kind).toBe('forbidden')
    expect(parse(html(500), NOW).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(securitytrailsProbe, KEY, [res(200, { current_monthly_usage: 1, allowed_monthly_usage: 50 })])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring; the cost note says the cost is undocumented', () => {
    expect(securitytrailsProbe).toMatchObject({ id: 'securitytrails', field: 'securitytrailsApiKey', rotationTool: 'securitytrails', group: 'keys', kind: 'usage' })
    expect(securitytrailsProbe.costNote).toMatch(/undocumented/i)
  })
})
