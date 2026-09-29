/**
 * Vulners validity probe (plan catalogue A8). Errors are matched on errorCode
 * (157 unknown key, 158 scope), a Cloudflare challenge means the key never
 * arrived, and v4 validation bodies echo their input. Fixtures are synthetic,
 * from the observed and documented shapes; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, request, vulnersProbe } from './vulners'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000VULNERS00000000000000000000000000000000000000000000000'
const NOTE = 'Monthly credits: Free 100 · Basic 600 · Pro 3,000 (dashboard only)'

function v3Error(error: string, errorCode: number, status = 401) {
  return res(status, { result: 'error', data: { error, errorCode } })
}

describe('request', () => {
  test('the key only in X-Api-Key: a key in the query string gets the Cloudflare challenge', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://vulners.com/api/v4/subscriptions/list/', headers: { 'X-Api-Key': KEY } })
    expect(r.url).not.toContain('apiKey')
  })
})

describe('parse: success', () => {
  test('a subscriptions list -> valid, with the plan credits as a note', () => {
    const r = parse(res(200, { result: [] }))
    expect(r).toMatchObject({ outcome: 'valid_no_usage', meters: [], notes: [NOTE] })
    expect(parse(res(200, { result: 'OK', data: {} })).outcome).toBe('valid_no_usage')
  })

  test('X-Vulners-Ratelimit-Reqlimit (a float string) -> a secondary per-minute meter', () => {
    const r = parse(res(200, { result: [{ id: 'SUB-0000' }] }, { headers: { 'X-Vulners-Ratelimit-Reqlimit': '120.0' } }))
    expect(r.meters).toEqual([
      { id: 'rate', label: 'Request rate limit (minute)', unit: 'requests', window: 'minute', used: null, limit: 120, remaining: null, resetsAt: null, resetsAtSource: null, primary: false },
    ])
  })

  test('an unknown 200 shape -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' })).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('401 errorCode 157 (observed) -> invalid_key, matched on the code not the text', () => {
    expect(parse(v3Error('Unknown api key', 157)).error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, providerCode: '157' })
    expect(parse(v3Error('Wrong API key', 157)).error?.kind).toBe('invalid_key')
  })

  test('errorCode 157 inside an HTTP 200 is still an invalid key', () => {
    expect(parse(v3Error('Unknown api key', 157, 200)).error).toMatchObject({ kind: 'invalid_key', httpStatus: 200 })
  })

  test('errorCode 158 (scope violation), on a 200 or a 403 -> forbidden', () => {
    for (const status of [200, 403]) {
      const r = parse(v3Error('Api key scope violation', 158, status))
      expect(r.error).toMatchObject({ kind: 'forbidden', providerCode: '158', message: 'the key lacks the api scope' })
    }
  })

  test('the Cloudflare challenge (no or ignored key) -> invalid_key "did not receive the key"', () => {
    const challenge = res(403, '<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>', {
      contentType: 'text/html; charset=UTF-8', headers: { 'cf-mitigated': 'challenge' },
    })
    expect(parse(challenge).error).toMatchObject({ kind: 'invalid_key', httpStatus: 403, message: 'Vulners did not receive the key (Cloudflare challenge)' })
  })

  test('401 from the FastAPI v4 routes -> invalid_key', () => {
    const r = parse(res(401, { detail: { type: 'auth_error', msg: 'Unauthorized API key' } }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', message: 'Unauthorized API key' })
  })

  test('402 wallet empty -> quota_exhausted; 429 -> rate_limited; 5xx -> provider_error', () => {
    expect(parse(res(402, { detail: 'Payment required' })).error?.kind).toBe('quota_exhausted')
    expect(parse(res(429, { detail: 'Too many requests' }, { headers: { 'Retry-After': '30' } })).error?.kind).toBe('rate_limited')
    expect(parse(html(503)).error?.kind).toBe('provider_error')
  })

  test('another v3 error code -> unexpected_response with the code', () => {
    expect(parse(v3Error('Something else', 999, 200)).error).toMatchObject({ kind: 'unexpected_response', providerCode: '999' })
  })

  test('a v4 validation error that echoes its input never quotes the body', () => {
    const r = parse(res(422, { detail: [{ type: 'missing', loc: ['header', 'x-api-key'], msg: 'Field required', input: KEY }] }))
    expect(r.error).toMatchObject({ kind: 'unexpected_response', message: 'Field required' })
    expect(allStrings(r).join('\n')).not.toContain(KEY)
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(vulnersProbe, KEY, [res(200, { result: [] })])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring: validity', () => {
    expect(vulnersProbe).toMatchObject({ id: 'vulners', field: 'vulnersApiKey', rotationTool: 'vulners', group: 'keys', kind: 'validity' })
  })
})
