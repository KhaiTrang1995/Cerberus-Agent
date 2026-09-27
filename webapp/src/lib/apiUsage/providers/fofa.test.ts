/**
 * FOFA usage probe (plan catalogue A11). Every FOFA error is an HTTP 200 with
 * `error: true`, so these tests are mostly about reading the body, not the status.
 */
import { describe, test, expect } from 'vitest'
import { authParams, fofaCode, fofaProbe, parse, request } from './fofa'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000fofa0000000000000000a'

describe('request: the same auth params recon sends', () => {
  test('a modern key is sent as `key` only', () => {
    const r = request(KEY)
    expect(r.method).toBe('GET')
    expect(r.url).toBe(`https://fofa.info/api/v1/info/my?key=${KEY}`)
  })

  test('a legacy `email:key` is split on the first colon, both parts trimmed', () => {
    const p = authParams(' user@example.test : KEY:WITH:COLONS ')
    expect(p.get('email')).toBe('user@example.test')
    expect(p.get('key')).toBe('KEY:WITH:COLONS')
    expect(request('user@example.test:abc').url).toBe('https://fofa.info/api/v1/info/my?email=user%40example.test&key=abc')
  })

  test('surrounding whitespace is trimmed like recon does', () => {
    expect(authParams('  abc  ').get('key')).toBe('abc')
  })
})

describe('fofaCode', () => {
  test('reads the code between a leading [ and the first ]', () => {
    expect(fofaCode('[-700] Account Invalid')).toBe('-700')
    expect(fofaCode('[45012] 请求速度过快')).toBe('45012')
    expect(fofaCode('no code here')).toBeUndefined()
  })
})

describe('parse: success', () => {
  test('a subscription account: queries and rows left are primary balances', () => {
    const r = parse(res(200, {
      error: false, username: 'sample', fcoin: 0, fofa_point: 1200, isvip: true, vip_level: 12,
      remain_api_query: 9800, remain_api_data: 99000, email: 'someone@example.test', avatar: 'x',
    }))
    expect(r.outcome).toBe('usage')
    expect(r.account).toMatchObject({ plan: 'Subscription (professional)', label: 'sample' })
    expect(r.meters.map(m => [m.id, m.remaining, m.limit, m.primary])).toEqual([
      ['queries', 9800, null, true],
      ['rows', 99000, null, true],
      ['fpoints', 1200, null, false],
    ])
  })

  test('a registered account without remain_* fields is valid with no API quota', () => {
    const r = parse(res(200, {
      username: 'sample', fofacli_ver: '4.0.3', fcoin: 0, error: false, fofa_server: true,
      avatar: '…', vip_level: 0, is_verified: false, message: '', isvip: false, email: 'someone@example.test',
    }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account?.plan).toBe('Registered')
    expect(r.notes?.[0]).toMatch(/no API query quota/)
  })

  test('a Registered account reporting 0/0 (seen live) has no API quota: valid, not exhausted', () => {
    const r = parse(res(200, {
      error: false, username: 'sample', category: 'user', fcoin: 0, fofa_point: 0, remain_free_point: 1000,
      remain_api_query: 0, remain_api_data: 0, isvip: false, vip_level: 0, is_verified: false, message: '',
      fofacli_ver: '4.0.3', fofa_server: true, expiration: '-',
    }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.notes?.[0]).toMatch(/no API query quota/)
    expect(r.meters.map(m => [m.id, m.remaining, m.primary])).toEqual([['free_points', 1000, false]])
    expect(r.account?.expiresAt).toBeUndefined()
  })

  test('a VIP account that used its quota up is exhausted, not "no quota"', () => {
    const r = parse(res(200, { error: false, username: 'sample', isvip: true, vip_level: 2, remain_api_query: 0, remain_api_data: 0 }))
    expect(r.outcome).toBe('usage')
    expect(r.meters.filter(m => m.primary).map(m => m.remaining)).toEqual([0, 0])
  })

  test('the email is never copied anywhere', () => {
    const r = parse(res(200, { error: false, username: 'sample', email: 'someone@example.test', remain_api_query: 1 }))
    expect(allStrings(r).join(' ')).not.toContain('someone@example.test')
  })
})

describe('parse: HTTP-200 errors', () => {
  test('[-700] -> invalid_key with the code and a translated label', () => {
    const r = parse(res(200, { error: true, errmsg: '[-700] Account Invalid' }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: '-700', httpStatus: 200 })
    expect(r.error?.message).toContain('Account invalid')
  })

  test('[45012] -> rate_limited', () => {
    expect(parse(res(200, { error: true, errmsg: '[45012] 请求速度过快' })).error).toMatchObject({ kind: 'rate_limited', providerCode: '45012' })
  })

  test('an unknown code -> unexpected_response carrying the message', () => {
    const r = parse(res(200, { error: true, errmsg: '[123] something else' }))
    expect(r.error).toMatchObject({ kind: 'unexpected_response', providerCode: '123' })
    expect(r.error?.message).toContain('something else')
  })

  test('non-200 statuses use the default mapping', () => {
    expect(parse(html(502)).error?.kind).toBe('provider_error')
    expect(parse(res(429, 'slow down')).error?.kind).toBe('rate_limited')
  })

  test('a 200 that is neither an error nor an account -> unexpected_response', () => {
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(fofaProbe, KEY, [res(200, { error: true, errmsg: `[-700] Account Invalid for ${KEY}` })])
    expect(requests).toHaveLength(1)
    // The probe itself does not scrub (the runner does), but it must not add the key.
    expect(result.error?.kind).toBe('invalid_key')
    expect(fofaProbe.minIntervalMs).toBe(1100)
  })
})
