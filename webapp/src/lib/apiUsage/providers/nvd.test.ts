/**
 * NVD validity probe (plan catalogue A7). A bad key is a 404 with an empty
 * body and the reason in the `message` response header. Fixtures are
 * synthetic, from the CVE API 2.0 schema; the key is a fake UUID.
 */
import { describe, test, expect } from 'vitest'
import { nvdProbe, parse, request } from './nvd'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = '00000000-test-key0-0000-000000000000'

const CVES = {
  resultsPerPage: 1,
  startIndex: 0,
  totalResults: 250000,
  format: 'NVD_CVE',
  version: '2.0',
  timestamp: '2026-09-26T14:32:05.000',
  vulnerabilities: [{ cve: { id: 'CVE-0000-00000' } }],
}

describe('request', () => {
  test('one CVE, the key in the apiKey header and never in the URL', () => {
    expect(request(KEY)).toEqual({
      method: 'GET',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1',
      headers: { apiKey: KEY },
    })
  })

  test('never an empty apiKey header', () => {
    expect(request('')).toMatchObject({ headers: {} })
    expect(request('   ').headers).not.toHaveProperty('apiKey')
  })
})

describe('parse', () => {
  test('200 NVD_CVE -> valid, with the documented limit as a note', () => {
    const r = parse(res(200, CVES))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.meters).toEqual([])
    expect(r.notes).toEqual(['Limit: 50 requests per rolling 30 s with a key (documented; NVD does not report usage)'])
  })

  test('404, empty body, `message: Invalid apiKey.` -> invalid_key', () => {
    const r = parse(res(404, undefined, { headers: { message: 'Invalid apiKey.' } }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 404, message: 'Invalid apiKey.' })
  })

  test('404 `Invalid parameter` (or no reason at all) -> unexpected_response', () => {
    expect(parse(res(404, undefined, { headers: { message: 'Invalid parameter: resultsPerPage' } })).error).toMatchObject({ kind: 'unexpected_response', message: 'Invalid parameter: resultsPerPage' })
    expect(parse(res(404)).error?.kind).toBe('unexpected_response')
  })

  test('403 (often a Cloudflare page) -> rate_limited', () => {
    expect(parse(html(403)).error).toMatchObject({ kind: 'rate_limited', httpStatus: 403 })
  })

  test('502 / 503 / 504 -> provider_error', () => {
    for (const status of [502, 503, 504]) expect(parse(html(status)).error?.kind).toBe('provider_error')
  })

  test('a 200 that is not the CVE API -> unexpected_response', () => {
    expect(parse(res(200, { format: 'SOMETHING_ELSE' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(nvdProbe, KEY, [res(200, CVES)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('a blank key is never sent: a keyless request would pass', async () => {
    const { result, requests } = await runProbe(nvdProbe, '  ', [])
    expect(requests).toHaveLength(0)
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('registry wiring: validity', () => {
    expect(nvdProbe).toMatchObject({ id: 'nvd', field: 'nvdApiKey', rotationTool: 'nvd', group: 'keys', kind: 'validity' })
  })
})
