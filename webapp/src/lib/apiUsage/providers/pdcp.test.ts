/**
 * ProjectDiscovery Cloud validity probe (plan catalogue A6). Call 1 proves the
 * key; call 2 only adds the vulnx per-minute headroom and can never turn a
 * valid key into an error. Fixtures are synthetic; the key and email are fake.
 */
import { describe, test, expect } from 'vitest'
import { ProbeTransportError } from '../http'
import { headroomRequest, parse, parseHeadroom, pdcpProbe, request } from './pdcp'
import { NOW, html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY-0000-pdcp-0000-000000000000'
const EMAIL = 'someone@example.test'
const USER = { name: 'sample-user', email: EMAIL, plan: 'PRO', role: 'owner' }

const RESET = Math.floor(NOW.getTime() / 1000) + 55
const RESET_ISO = new Date(RESET * 1000).toISOString()

function headroom(status: number, limit: string, remaining: string) {
  return res(status, status === 200 ? { data: [] } : { message: 'Too Many Requests on /v2/vulnerability/filters', success: false }, {
    headers: { 'x-ratelimit-limit': limit, 'x-ratelimit-remaining': remaining, 'x-ratelimit-reset': String(RESET) },
  })
}

describe('request', () => {
  test('call 1: /v1/user as the utils ValidateAPIKey sends it; the key only in X-Api-Key', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://api.projectdiscovery.io/v1/user?utm_source=redamon', headers: { 'X-Api-Key': KEY } })
  })

  test('call 2: the vulnx filters endpoint, same header', () => {
    expect(headroomRequest(KEY)).toEqual({ method: 'GET', url: 'https://api.projectdiscovery.io/v2/vulnerability/filters', headers: { 'X-Api-Key': KEY } })
  })
})

describe('parse (/v1/user)', () => {
  test('a profile -> valid, plan name mapped, the account name as the label', () => {
    const r = parse(res(200, USER))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account).toEqual({ plan: 'Pro', label: 'sample-user' })
    expect(allStrings(r).join('\n')).not.toContain(EMAIL)
  })

  test('every documented plan code maps; an unknown one is left out', () => {
    expect(parse(res(200, { ...USER, plan: 'VERIFIED_FREE' })).account?.plan).toBe('Verified Free')
    expect(parse(res(200, { ...USER, plan: 'ENT_TRIAL' })).account?.plan).toBe('Enterprise Trial')
    expect(parse(res(200, { ...USER, plan: 'SOMETHING_NEW' })).account?.plan).toBeUndefined()
  })

  test('an email-shaped name is never the label', () => {
    expect(parse(res(200, { ...USER, name: EMAIL })).account?.label).toBeUndefined()
  })

  test('a 200 without an email is an invalid key (the utils rule)', () => {
    expect(parse(res(200, { name: 'x', email: '' })).error).toMatchObject({ kind: 'invalid_key', httpStatus: 200 })
  })

  test('401 "not authorized" -> invalid_key; 429 -> rate_limited; 5xx -> provider_error; HTML 200 -> unexpected_response', () => {
    const r = parse(res(401, { message: 'User is not authorized to perform this action' }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, message: 'User is not authorized to perform this action' })
    expect(parse(res(429, { message: 'Too Many Requests' })).error?.kind).toBe('rate_limited')
    expect(parse(html(502)).error?.kind).toBe('provider_error')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parseHeadroom (x-ratelimit-* headers)', () => {
  test('a 200 -> the secondary per-minute meter', () => {
    expect(parseHeadroom(headroom(200, '60', '59'))).toEqual({
      id: 'vulnx', label: 'vulnx requests (minute)', unit: 'requests', window: 'minute',
      used: 1, limit: 60, remaining: 59, resetsAt: RESET_ISO, resetsAtSource: 'provider', primary: false,
    })
  })

  test('a 429 still describes the window: used up', () => {
    expect(parseHeadroom(headroom(429, '10', '0'))).toMatchObject({ used: 10, limit: 10, remaining: 0 })
  })

  test('a rejected call or missing headers -> no meter', () => {
    expect(parseHeadroom(headroom(401, '10', '9'))).toBeNull()
    expect(parseHeadroom(res(200, { data: [] }))).toBeNull()
  })
})

describe('run', () => {
  test('/v1/user then the filters call; valid with the headroom meter', async () => {
    const { result, requests } = await runProbe(pdcpProbe, KEY, [res(200, USER), headroom(200, '60', '59')])
    expect(requests.map(r => r.url)).toEqual([
      'https://api.projectdiscovery.io/v1/user?utm_source=redamon',
      'https://api.projectdiscovery.io/v2/vulnerability/filters',
    ])
    expect(result.outcome).toBe('valid_no_usage')
    expect(result.account).toEqual({ plan: 'Pro', label: 'sample-user' })
    expect(result.meters.map(m => m.id)).toEqual(['vulnx'])
    expect(result.notes).toBeUndefined()
    const strings = allStrings(result).join('\n')
    expect(strings).not.toContain(KEY)
    expect(strings).not.toContain(EMAIL)
  })

  test('a failed call 2 never turns a valid key into an error', async () => {
    const timedOut = await runProbe(pdcpProbe, KEY, [res(200, USER), new ProbeTransportError('timeout', 'timed out after 10 s')])
    expect(timedOut.result).toMatchObject({ outcome: 'valid_no_usage', meters: [], notes: ['vulnx rate headroom not read (timed out after 10 s)'] })
    expect(timedOut.result.error).toBeUndefined()

    const down = await runProbe(pdcpProbe, KEY, [res(200, USER), html(503)])
    expect(down.result).toMatchObject({ outcome: 'valid_no_usage', meters: [], notes: ['vulnx rate headroom not read (HTTP 503)'] })
  })

  test('a rejected key stops after call 1', async () => {
    const { result, requests } = await runProbe(pdcpProbe, KEY, [res(401, { message: 'User is not authorized to perform this action' })])
    expect(requests).toHaveLength(1)
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('registry wiring: validity', () => {
    expect(pdcpProbe).toMatchObject({ id: 'pdcp', field: 'pdcpApiKey', rotationTool: 'pdcp', group: 'keys', kind: 'validity', verifiedOn: null })
  })
})
