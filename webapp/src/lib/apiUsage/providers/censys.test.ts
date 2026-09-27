import { describe, test, expect } from 'vitest'
import { censysProbe, parse, request } from './censys'
import { html, res, runProbe } from '../testUtils'

const TOKEN = 'censys_TESTTOKEN0000'
const ORG = '11111111-2222-3333-4444-555555555555'

describe('request', () => {
  test('with an org id: the organization endpoint', () => {
    expect(request(TOKEN, ORG)).toEqual({
      method: 'GET',
      url: `https://api.platform.censys.io/v3/accounts/organizations/${ORG}/credits`,
      headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/json' },
    })
  })

  test('without one: the Free user endpoint', () => {
    expect(request(TOKEN, '').url).toBe('https://api.platform.censys.io/v3/accounts/users/credits')
  })

  test('the org id is path-encoded', () => {
    expect(request(TOKEN, '../x').url).toBe('https://api.platform.censys.io/v3/accounts/organizations/..%2Fx/credits')
  })
})

describe('parse: organization', () => {
  test('balance, the soonest-expiring lot, auto top-up', () => {
    const r = parse(res(200, { result: {
      uid: ORG, balance: 12000,
      credit_expirations: [
        { balance: 5000, initial_balance: 5000, expires_at: '2027-03-01T00:00:00Z' },
        { balance: 7000, initial_balance: 10000, expires_at: '2026-12-01T00:00:00Z' },
      ],
      auto_replenish_config: { enabled: true, amount: 1000, threshold: 500 },
    } }), true)
    expect(r.account).toEqual({ plan: 'Starter / Enterprise (organization)', label: 'auto top-up below 500' })
    expect(r.meters).toEqual([{
      id: 'balance', label: 'Credits', unit: 'credits', window: 'balance', used: null, limit: null, remaining: 12000,
      resetsAt: null, resetsAtSource: null, primary: true, note: '7000 expire on 2026-12-01',
    }])
  })

  test('403 -> forbidden (role cannot read the org credits); 404/422 -> the org id is wrong', () => {
    expect(parse(res(403, { title: 'Forbidden', status: 403 }), true).error).toMatchObject({ kind: 'forbidden' })
    expect(parse(res(404, { title: 'Not Found', status: 404 }), true).error?.message).toMatch(/Organization ID is wrong/)
    expect(parse(res(422, { title: 'Unprocessable Entity', status: 422 }), true).error?.kind).toBe('invalid_key')
  })
})

describe('parse: free', () => {
  test('balance against the documented 100/month, with the provider reset', () => {
    const r = parse(res(200, { result: { balance: 64, resets_at: '2026-10-01T00:00:00Z' } }), false)
    expect(r.account).toEqual({ plan: 'Free' })
    expect(r.meters[0]).toMatchObject({ used: 36, limit: 100, remaining: 64, resetsAt: '2026-10-01T00:00:00.000Z', resetsAtSource: 'provider', primary: true })
  })

  test('a balance above the Free allowance drops the limit and asks for the org id', () => {
    const r = parse(res(200, { result: { balance: 2500 } }), false)
    expect(r.meters[0]).toMatchObject({ limit: null, used: null, remaining: 2500 })
    expect(r.notes?.[0]).toMatch(/Organization ID/)
  })

  test('404 on the Free endpoint tells a paid user to set the Organization ID', () => {
    const r = parse(res(404, { title: 'Not Found', detail: 'user not found' }), false)
    expect(r.error?.kind).toBe('invalid_key')
    expect(r.error?.message).toMatch(/Organization ID/)
  })
})

describe('parse: common', () => {
  test('401 invalid token; 500 provider error; shape drift', () => {
    const invalid = parse(res(401, { error: { code: 401, message: 'Access credentials are invalid', reason: 'Access token is not active', status: 'Unauthorized' } }), false)
    expect(invalid.error).toMatchObject({ kind: 'invalid_key', message: 'Access credentials are invalid' })
    expect(parse(html(500), true).error?.kind).toBe('provider_error')
    expect(parse(res(200, { result: {} }), true).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('the optional org id companion picks the endpoint', async () => {
    const free = await runProbe(censysProbe, TOKEN, [res(200, { result: { balance: 5 } })], { censysOrgId: '' })
    expect(free.requests[0].url).toContain('/users/credits')
    const org = await runProbe(censysProbe, TOKEN, [res(200, { result: { balance: 5 } })], { censysOrgId: ` ${ORG} ` })
    expect(org.requests[0].url).toContain(`/organizations/${ORG}/credits`)
  })
})
