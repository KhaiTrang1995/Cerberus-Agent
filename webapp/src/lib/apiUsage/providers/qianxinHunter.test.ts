/**
 * Qianxin Hunter usage probe (plan catalogue A20), EXPERIMENTAL: anything it
 * does not recognise is "not checked", the firewall is a provider error, and
 * it never calls the point-spending search. Fixtures are synthetic, from the
 * OctoBus / HunterX field sets; the key and the phone are fake.
 */
import { describe, test, expect } from 'vitest'
import { ProbeTransportError } from '../http'
import { parse, qianxinHunterProbe, request } from './qianxinHunter'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000hunter0000000000000000000000000000000000000000000000'
const PHONE = '+00 555 0100'
const BLOCKED = "blocked by Hunter's firewall (often outside mainland China)"

const OK = {
  code: 200,
  message: 'success',
  data: {
    type: '个人用户',
    rest_free_point: 420,
    day_free_point: 500,
    // HunterX decodes numbers loosely: numeric strings happen.
    rest_equity_point: '1200',
    rest_export_quota: 9,
    day_export_quota: 10,
    once_export_quota: 1000,
    personal_info: { username: 'sample-user', phone: PHONE, is_charge: false },
  },
}

// Next midnight, UTC+8.
const MIDNIGHT_CST = '2026-09-26T16:00:00.000Z'

describe('request', () => {
  test('GET userInfo with the key in the api-key query parameter (the only way Hunter takes it)', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: `https://hunter.qianxin.com/openApi/userInfo?api-key=${KEY}` })
    expect(request('a&b=c').url).toBe('https://hunter.qianxin.com/openApi/userInfo?api-key=a%26b%3Dc')
  })
})

describe('parse: success', () => {
  test('free points today against the daily allowance; equity as a balance; exports', () => {
    const r = parse(res(200, OK), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: 'Personal' })
    expect(r.meters).toEqual([
      { id: 'free', label: 'Free points (today)', unit: 'points', window: 'day', used: 80, limit: 500, remaining: 420, resetsAt: MIDNIGHT_CST, resetsAtSource: 'computed', primary: true },
      { id: 'equity', label: 'Equity points', unit: 'points', window: 'balance', used: null, limit: null, remaining: 1200, resetsAt: null, resetsAtSource: null, primary: false },
      { id: 'export', label: 'Exports (today)', unit: 'count', window: 'day', used: null, limit: 10, remaining: 9, resetsAt: MIDNIGHT_CST, resetsAtSource: 'computed', primary: false },
    ])
  })

  test('an enterprise account without export quotas', () => {
    const data: Record<string, unknown> = { ...OK.data, type: '企业用户' }
    delete data.day_export_quota
    delete data.rest_export_quota
    const r = parse(res(200, { ...OK, data }), NOW)
    expect(r.account?.plan).toBe('Enterprise')
    expect(r.meters.map(m => m.id)).toEqual(['free', 'equity'])
  })

  test('code 40205 is a notice: the data is still read', () => {
    expect(parse(res(200, { ...OK, code: 40205, message: 'notice' }), NOW).outcome).toBe('usage')
  })

  test('the username, the phone and the key are never copied', () => {
    const strings = allStrings(parse(res(200, OK), NOW)).join('\n')
    for (const secret of ['sample-user', PHONE, KEY]) expect(strings).not.toContain(secret)
  })
})

describe('parse: recognised errors', () => {
  test('code 401 (expired / missing token), in an HTTP 200 or as the status -> invalid_key', () => {
    const r = parse(res(200, { code: 401, data: null, message: '令牌过期' }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 200, providerCode: '401' })
    expect(r.error?.message).toContain('令牌过期')
    expect(parse(res(401, { code: 401, message: '令牌缺失' }), NOW).error?.kind).toBe('invalid_key')
  })

  test('code 429 -> rate_limited', () => {
    expect(parse(res(200, { code: 429, data: null, message: '请求太多啦，稍后再试试' }), NOW).error?.kind).toBe('rate_limited')
  })

  test('points used up -> quota_exhausted', () => {
    expect(parse(res(200, { code: 400, data: null, message: '大牛，您的积分用完了，明天再试试' }), NOW).error?.kind).toBe('quota_exhausted')
    expect(parse(res(200, { code: 400, data: null, message: '积分不足' }), NOW).error?.kind).toBe('quota_exhausted')
  })

  test('the WAF (HTML page or WZWS-RAY header) -> provider_error, not the key', () => {
    const waf = res(403, '<html><body>blocked</body></html>', { contentType: 'text/html', headers: { 'WZWS-RAY': '1234-5678' } })
    expect(parse(waf, NOW).error).toEqual({ kind: 'provider_error', httpStatus: 403, message: BLOCKED })
    expect(parse(html(200), NOW).error?.kind).toBe('provider_error')
    expect(parse(res(200, OK, { headers: { 'wzws-ray': 'x' } }), NOW).error?.kind).toBe('provider_error')
  })
})

describe('parse: anything unrecognised is "not checked", never an error', () => {
  test.each([
    ['404', res(404, { code: 404, message: 'Not Found' })],
    ['unknown JSON', res(200, { code: 200, message: 'ok', data: { something: 1 } })],
    ['no data', res(200, { code: 200, message: 'ok' })],
    ['a 5xx', res(500, { code: 500, message: 'error' })],
    ['plain text', res(200, 'ok')],
  ])('%s -> not_checked: costs_credits', (_name, response) => {
    const r = parse(response, NOW)
    expect(r.outcome).toBe('not_checked')
    expect(r.notCheckedReason).toBe('costs_credits')
    expect(r.error).toBeUndefined()
  })
})

describe('run', () => {
  test('a dropped connection is the firewall -> provider_error', async () => {
    const { result, requests } = await runProbe(qianxinHunterProbe, KEY, [new ProbeTransportError('network', 'could not reach the provider (ECONNRESET)')])
    expect(requests).toHaveLength(1)
    expect(result.error).toEqual({ kind: 'provider_error', message: BLOCKED })
  })

  test('a refused redirect is an unrecognised answer -> not checked', async () => {
    const { result } = await runProbe(qianxinHunterProbe, KEY, [new ProbeTransportError('unexpected_response', 'the provider redirected; the redirect was not followed')])
    expect(result).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'costs_credits' })
  })

  test('a timeout is left to the runner', async () => {
    await expect(runProbe(qianxinHunterProbe, KEY, [new ProbeTransportError('timeout', 'timed out after 10 s')])).rejects.toBeInstanceOf(ProbeTransportError)
  })

  test('never calls /openApi/search, whatever the answer', async () => {
    const answers = [res(200, OK), res(404, 'Not Found'), res(200, { code: 200, data: {} }), html(403), res(200, { code: 401, message: '令牌过期' })]
    for (const answer of answers) {
      const { requests } = await runProbe(qianxinHunterProbe, KEY, [answer])
      expect(requests.map(r => r.url.split('?')[0])).toEqual(['https://hunter.qianxin.com/openApi/userInfo'])
    }
  })

  test('experimental, paced per source IP', () => {
    expect(qianxinHunterProbe).toMatchObject({
      id: 'hunter', service: 'hunter', field: 'hunterApiKey', rotationTool: 'hunter', group: 'uncover',
      kind: 'usage', experimental: true, limitScope: 'ip', minIntervalMs: 2000,
    })
    expect(qianxinHunterProbe.endpoint).toBe('GET hunter.qianxin.com/openApi/userInfo')
  })
})
