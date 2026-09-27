/**
 * 360 Quake usage probe (plan catalogue A19). Errors are string codes inside
 * HTTP 200 bodies, except the bad-token 401 whose body is plain `/quake/login`.
 * Fixtures are synthetic, from the official doc example with identifiers
 * replaced; the token is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, quakeProbe, request } from './quake'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY-0000-quake-0000-000000000000'
const EMAIL = 'someone@example.test'
const PHONE = '+00 555 0100'

// The official doc example, identifiers replaced.
const DOC = {
  code: 0,
  message: 'Successful',
  data: {
    id: 'ID-0000',
    user: { id: 'UID-0000', username: 'sample-user', fullname: 'Sample Fullname', email: EMAIL },
    baned: false,
    ban_status: '使用中',
    credit: 5000,
    persistent_credit: 1000,
    token: KEY,
    mobile_phone: PHONE,
    source: 'quake',
    role: [{ fullname: '注册用户', priority: 4, credit: 3000 }],
  },
  meta: {},
}

function withData(extra: Record<string, unknown>) {
  return { ...DOC, data: { ...DOC.data, ...extra } }
}

function codeBody(code: string, message: string) {
  return { code, message, data: {}, meta: {} }
}

// 1st of next month, 00:00 UTC+8.
const NEXT_MONTH_CST = '2026-09-30T16:00:00.000Z'

describe('request', () => {
  test('GET user/info with the X-QuakeToken header; the token never in the URL', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://quake.360.net/api/v3/user/info', headers: { 'X-QuakeToken': KEY } })
  })
})

describe('parse: success', () => {
  test('doc example: monthly credits against the role allotment, long-term as a balance', () => {
    const r = parse(res(200, DOC), NOW)
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ plan: '注册用户', expiresAt: undefined })
    expect(r.meters).toEqual([
      { id: 'monthly', label: 'Monthly credits', unit: 'credits', window: 'month', used: 0, limit: 3000, remaining: 5000, resetsAt: NEXT_MONTH_CST, resetsAtSource: 'computed', primary: true },
      { id: 'long_term', label: 'Long-term credits', unit: 'credits', window: 'balance', used: null, limit: null, remaining: 1000, resetsAt: null, resetsAtSource: null, primary: false },
    ])
  })

  test('newer fields win: month_remaining_credit, constant_credit, free API queries, role expiry', () => {
    const r = parse(res(200, withData({
      credit: 30000,
      month_remaining_credit: 1200,
      constant_credit: 50,
      free_query_api_count: 5,
      role: [{ fullname: '高级会员', priority: 3, credit: 30000 }, { fullname: '注册用户', priority: 4, credit: 3000 }],
      role_validity: {
        '高级会员': { start_time: '2026-01-01 00:00:00', end_time: '2027-01-01 00:00:00', remain_days: 97 },
        '注册用户': null,
      },
    })), NOW)
    expect(r.account).toEqual({ plan: '高级会员, 注册用户', expiresAt: '2027-01-01T00:00:00.000Z' })
    expect(r.meters.find(m => m.id === 'monthly')).toMatchObject({ remaining: 1200, limit: 30000, used: 28800 })
    expect(r.meters.find(m => m.id === 'long_term')).toMatchObject({ remaining: 50 })
    expect(r.meters.find(m => m.id === 'free_queries')).toEqual({
      id: 'free_queries', label: 'Free API queries (month)', unit: 'queries', window: 'month', used: null, limit: null, remaining: 5, resetsAt: NEXT_MONTH_CST, resetsAtSource: 'computed', primary: false,
    })
  })

  test('f_query_api_count is read when free_query_api_count is absent', () => {
    const r = parse(res(200, withData({ f_query_api_count: 10 })), NOW)
    expect(r.meters.find(m => m.id === 'free_queries')?.remaining).toBe(10)
  })

  test('no role: the monthly credits are a remaining-only meter', () => {
    const r = parse(res(200, withData({ role: [] })), NOW)
    expect(r.meters[0]).toMatchObject({ remaining: 5000, limit: null, used: null })
    expect(r.account?.plan).toBeUndefined()
  })

  test('the echoed token, the email, the phone and the names are never copied', () => {
    const strings = allStrings(parse(res(200, DOC), NOW)).join('\n')
    for (const secret of [KEY, EMAIL, PHONE, 'sample-user', 'Sample Fullname']) expect(strings).not.toContain(secret)
  })
})

describe('parse: errors', () => {
  test('401 with the bare text /quake/login -> invalid_key', () => {
    const r = parse(res(401, '/quake/login', { contentType: 'text/html' }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
    expect(parse(res(200, '/quake/login\n'), NOW).error?.kind).toBe('invalid_key')
  })

  test('HTTP-200 string codes map to their kinds', () => {
    expect(parse(res(200, codeBody('q3005', '调用API过于频繁')), NOW).error).toMatchObject({ kind: 'rate_limited', providerCode: 'q3005', httpStatus: 200 })
    expect(parse(res(200, codeBody('q3011', '无权限')), NOW).error).toMatchObject({ kind: 'forbidden', providerCode: 'q3011' })
    expect(parse(res(200, codeBody('q1001', '未登录')), NOW).error).toMatchObject({ kind: 'forbidden', providerCode: 'q1001' })
    expect(parse(res(200, codeBody('u3009', '其他错误')), NOW).error).toMatchObject({ kind: 'unexpected_response', providerCode: 'u3009' })
  })

  test('q3007 -> quota_exhausted with the balance, never the user name', () => {
    const r = parse(res(200, codeBody('q3007', '用户 sample-user 积分不足，当前积分：12')), NOW)
    expect(r.error).toMatchObject({ kind: 'quota_exhausted', providerCode: 'q3007', message: 'not enough credits (balance 12)' })
    expect(allStrings(r).join('\n')).not.toContain('sample-user')
  })

  test('q2001 is a credit shortage only when it says so', () => {
    expect(parse(res(200, codeBody('q2001', '当前积分不足')), NOW).error?.kind).toBe('quota_exhausted')
    expect(parse(res(200, codeBody('q2001', '超出限制')), NOW).error?.kind).toBe('forbidden')
  })

  test('a banned account -> forbidden with its state', () => {
    const r = parse(res(200, withData({ baned: true, ban_status: '已封禁' })), NOW)
    expect(r.error?.kind).toBe('forbidden')
    expect(r.error?.message).toContain('已封禁')
  })

  test('a numeric non-zero code, a 200 without credits, 5xx', () => {
    expect(parse(res(200, { code: 7, message: 'x', data: {} }), NOW).error).toMatchObject({ kind: 'unexpected_response', providerCode: '7' })
    expect(parse(res(200, { code: 0, message: 'Successful', data: { baned: false } }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(502), NOW).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; the token never reaches the result', async () => {
    const { result, requests } = await runProbe(quakeProbe, KEY, [res(200, DOC)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring', () => {
    expect(quakeProbe).toMatchObject({ id: 'quake', field: 'quakeApiKey', rotationTool: 'quake', group: 'uncover', kind: 'usage', verifiedOn: null })
  })
})
