/**
 * ZoomEye usage probe (plan catalogue A15). `code` 60000 is the only success,
 * whatever the HTTP status and Content-Type. Fixtures are synthetic, written
 * from the official v2 doc example with the PII replaced; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, request, zoomeyeProbe } from './zoomeye'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY-0000-zoomeye-000000000000'
const EMAIL = 'someone@example.test'
const PHONE = '+00 555 0100'

// The official v2 doc example, PII values replaced.
const DOC = {
  code: 60000,
  message: 'success',
  data: {
    username: 'sample-user',
    email: EMAIL,
    phone: PHONE,
    created_at: '2023-01-15T08:00:00Z',
    subscription: { plan: 'Premium', end_date: '2024-01-20T00:00:00Z', points: '30000', zoomeye_points: '10000000' },
  },
}

function withSubscription(subscription: Record<string, unknown>) {
  return { ...DOC, data: { ...DOC.data, subscription } }
}

// 1st of next month, 00:00 UTC+8.
const NEXT_MONTH_CST = '2026-09-30T16:00:00.000Z'

describe('request', () => {
  test('POST with the API-KEY header, no body and no Content-Type (as the official curl)', () => {
    expect(request(KEY)).toEqual({ method: 'POST', url: 'https://api.zoomeye.ai/v2/userinfo', headers: { 'API-KEY': KEY } })
    expect(request(KEY).url).not.toContain(KEY)
  })
})

describe('parse: success', () => {
  test('doc example: string points, a plan not in the table -> remaining only', () => {
    const r = parse(res(200, DOC), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Premium', label: 'sample-user', expiresAt: '2024-01-20T00:00:00.000Z' })
    expect(r.meters).toEqual([
      { id: 'points', label: 'Basic points (month)', unit: 'points', window: 'month', used: null, limit: null, remaining: 30000, resetsAt: NEXT_MONTH_CST, resetsAtSource: 'computed', primary: true },
      { id: 'zoomeye_points', label: 'ZoomEye-Points', unit: 'points', window: 'balance', used: null, limit: null, remaining: 10000000, resetsAt: null, resetsAtSource: null, primary: false, note: 'expire 12 months after purchase' },
    ])
  })

  test('a plan from the table: allotment as the limit, used = allotment - left', () => {
    const r = parse(res(200, withSubscription({ plan: 'Personal', end_date: '2027-03-01', points: 40000, zoomeye_points: 0 })), NOW)
    expect(r.meters[0]).toMatchObject({ limit: 100000, remaining: 40000, used: 60000, note: 'allotment from the plan table' })
    expect(r.meters[1]).toMatchObject({ id: 'zoomeye_points', remaining: 0 })
    expect(r.account?.expiresAt).toBe('2027-03-01T00:00:00.000Z')
  })

  test('JSON served as application/octet-stream is still read', () => {
    const r = parse(res(200, DOC, { contentType: 'application/octet-stream' }), NOW)
    expect(r.outcome).toBe('usage')
  })

  test('empty end_date = no subscription; missing plan shows Free', () => {
    const r = parse(res(200, withSubscription({ end_date: '', points: '3000' })), NOW)
    expect(r.account).toMatchObject({ plan: 'Free', expiresAt: undefined })
    expect(r.meters).toHaveLength(1)
  })

  test('the email and the phone are never copied', () => {
    const strings = allStrings(parse(res(200, DOC), NOW)).join('\n')
    expect(strings).not.toContain(EMAIL)
    expect(strings).not.toContain(PHONE)
  })

  test('an email-shaped username is not used as the label', () => {
    const r = parse(res(200, { ...DOC, data: { ...DOC.data, username: EMAIL } }), NOW)
    expect(r.account?.label).toBeUndefined()
  })

  test('code 60000 without balances -> unexpected_response', () => {
    expect(parse(res(200, { code: 60000, message: 'success', data: { username: 'x' } }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(res(200, { code: 60000, message: 'success' }), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('401 login_required (missing and invalid keys look the same) -> invalid_key', () => {
    const r = parse(res(401, {
      code: 50000, error: 'login_required', message: 'login required, missing Authorization header', url: 'https://www.zoomeye.ai/api',
    }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, providerCode: 'login_required', message: 'ZoomEye rejected the key' })
  })

  test('the mainland host 403 "not aviliable in your area" (octet-stream) -> provider_error', () => {
    const r = parse(res(403, {
      status_code: 403, message: 'this service not aviliable in your area, please use api.zoomeye.ai instead',
    }, { contentType: 'application/octet-stream' }), NOW)
    expect(r.error?.kind).toBe('provider_error')
    expect(r.error?.message).toContain('api.zoomeye.ai')
  })

  test('402 credits_insufficient -> quota_exhausted', () => {
    expect(parse(res(402, { error: 'credits_insufficient', message: 'credits insufficient' }), NOW).error?.kind).toBe('quota_exhausted')
  })

  test('403 forbidden / suspended -> forbidden', () => {
    expect(parse(res(403, { error: 'forbidden', message: 'could not access to specified resource' }), NOW).error).toMatchObject({ kind: 'forbidden', providerCode: 'forbidden' })
    const s = parse(res(403, { error: 'suspended', message: 'account suspended' }), NOW)
    expect(s.error?.kind).toBe('forbidden')
    expect(s.error?.message).toContain('suspended')
  })

  test('429 rate_limit -> rate_limited', () => {
    expect(parse(res(429, { error: 'rate_limit', message: 'Your account reached the API rate limit' }), NOW).error?.kind).toBe('rate_limited')
  })

  test('5xx and the Jiasule WAF page -> provider_error', () => {
    expect(parse(html(503), NOW).error?.kind).toBe('provider_error')
    const waf = parse(res(403, '<html><body>blocked</body></html>', { contentType: 'text/html', headers: { 'X-Via-JSL': 'a1b2' } }), NOW)
    expect(waf.error?.kind).toBe('provider_error')
    expect(waf.error?.message).toContain('firewall')
  })

  test('HTTP 200 with any code other than 60000 is a failure', () => {
    const r = parse(res(200, { code: 50001, message: 'something went wrong' }), NOW)
    expect(r.error).toMatchObject({ kind: 'unexpected_response', httpStatus: 200, providerCode: '50001' })
    expect(parse(res(200, { code: 60000 - 1, error: 'login_required' }), NOW).error?.kind).toBe('invalid_key')
  })

  test('a GET-style 405 -> unexpected_response', () => {
    expect(parse(res(405, { error: 'method_not_allowed', message: 'method not allowed' }), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one POST; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(zoomeyeProbe, KEY, [res(200, DOC)])
    expect(requests).toEqual([request(KEY)])
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('paced for the Free plan (0.5 req/s)', () => {
    expect(zoomeyeProbe).toMatchObject({ id: 'zoomeye', field: 'zoomEyeApiKey', rotationTool: 'zoomeye', group: 'keys', kind: 'usage', minIntervalMs: 2100 })
  })
})
