/**
 * Onyphe usage probe (plan catalogue A24). The envelope's `error`/`status`
 * decide whatever the HTTP status. Fixtures are synthetic, from the archived
 * docs sample; the key is fake and `myip` is a documentation address.
 */
import { describe, test, expect } from 'vitest'
import { onypheProbe, parse, request } from './onyphe'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000onyphe00000000000000000000000'
const MYIP = '192.0.2.10'

const RESULT = {
  view: 'Eagle View',
  credits: 250000,
  startdate: '2026-01-01T00:00:00.000Z',
  enddate: 0,
  apis: ['search', 'summary'],
  categories: ['datascan'],
  filters: ['ip'],
  functions: ['country'],
  history: '7M',
  apikey: KEY,
  oqlversion: 2,
}

// `took` and `page*` arrive as strings on some answers.
const ENVELOPE = {
  count: 1, error: 0, max_page: 1, myip: MYIP, page: '1', page_size: '10',
  results: [RESULT], status: 'ok', text: 'Success', took: '0.000', total: 1,
}

function nok(error: number, text: string) {
  return { count: 0, error, myip: MYIP, status: 'nok', text }
}

describe('request', () => {
  test('GET v2/user with the bearer header uncover sends; the key never in the URL', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://www.onyphe.io/api/v2/user', headers: { Authorization: `bearer ${KEY}` } })
  })
})

describe('parse: success', () => {
  test('the credit balance is the one primary meter; enddate 0 = no end date', () => {
    const r = parse(res(200, ENVELOPE))
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Eagle View', expiresAt: undefined })
    expect(r.meters).toEqual([
      { id: 'credits', label: 'Credits', unit: 'credits', window: 'balance', used: null, limit: null, remaining: 250000, resetsAt: null, resetsAtSource: null, primary: true },
    ])
  })

  test('a dated enddate becomes the expiry', () => {
    const r = parse(res(200, { ...ENVELOPE, results: [{ ...RESULT, enddate: '2027-06-30T00:00:00Z' }] }))
    expect(r.account?.expiresAt).toBe('2027-06-30T00:00:00.000Z')
    expect(parse(res(200, { ...ENVELOPE, results: [{ ...RESULT, enddate: '0' }] })).account?.expiresAt).toBeUndefined()
  })

  test('the echoed key and the caller IP are never copied', () => {
    const strings = allStrings(parse(res(200, ENVELOPE))).join('\n')
    expect(strings).not.toContain(KEY)
    expect(strings).not.toContain(MYIP)
  })

  test('an ok envelope without a result -> unexpected_response', () => {
    expect(parse(res(200, { ...ENVELOPE, results: [] })).error?.kind).toBe('unexpected_response')
    expect(parse(res(200, { hello: 'world' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('400 error 2 "No API key given" -> invalid_key, without the caller IP', () => {
    const r = parse(res(400, nok(2, 'No API key given')))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 400, providerCode: '2', message: 'No API key given' })
    expect(allStrings(r).join('\n')).not.toContain(MYIP)
  })

  test('400 error 3 "Invalid API key format" -> invalid_key', () => {
    expect(parse(res(400, nok(3, 'Invalid API key format'))).error).toMatchObject({ kind: 'invalid_key', providerCode: '3' })
  })

  test('402 -> quota_exhausted', () => {
    expect(parse(res(402, nok(7, 'Not enough credits'))).error?.kind).toBe('quota_exhausted')
  })

  test('429 (enveloped or not) -> rate_limited', () => {
    expect(parse(res(429, nok(9, 'Too many requests'))).error?.kind).toBe('rate_limited')
    expect(parse(res(429, 'Too Many Requests')).error?.kind).toBe('rate_limited')
  })

  test('an error inside an HTTP 200 is still an error, carrying `text`', () => {
    const r = parse(res(200, nok(5, 'Unknown error')))
    expect(r.error).toMatchObject({ kind: 'unexpected_response', httpStatus: 200, providerCode: '5', message: 'Unknown error' })
    expect(parse(res(200, { ...ENVELOPE, status: 'nok' })).error?.kind).toBe('unexpected_response')
  })

  test('an undocumented 401 envelope -> invalid_key; 5xx -> provider_error', () => {
    expect(parse(res(401, nok(1, 'Unknown API key'))).error?.kind).toBe('invalid_key')
    expect(parse(html(500)).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(onypheProbe, KEY, [res(200, ENVELOPE)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('1 req/s per source IP: paced process-wide', () => {
    expect(onypheProbe).toMatchObject({
      id: 'onyphe', field: 'onypheApiKey', rotationTool: 'onyphe', group: 'uncover', kind: 'usage', minIntervalMs: 1100, limitScope: 'ip',
    })
  })
})
