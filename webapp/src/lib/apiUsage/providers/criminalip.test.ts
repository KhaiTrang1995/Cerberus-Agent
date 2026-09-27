/**
 * Criminal IP validity probe (plan catalogue A16). The status is in the body,
 * and the success body echoes the key, the email and the name. Fixtures are
 * synthetic, from the docs example with the values replaced; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { criminalipProbe, parse, request } from './criminalip'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000criminalip0000000000000000000000000000000000000000'
const EMAIL = 'someone@example.test'

// The docs example, values replaced.
const DOC = {
  data: {
    account_type: 'google_social',
    api_key: KEY,
    email: EMAIL,
    last_access_date: '2022-04-11 06:06:54',
    max_search: '20,000,000',
    membership_date: '2021-07-05 02:14:24',
    name: 'Sample Name',
  },
  message: 'success',
  status: 200,
}

function bodyStatus(status: number, message: string, httpStatus = 200) {
  return res(httpStatus, { status, message })
}

describe('request', () => {
  test('POST with the x-api-key header recon sends and an empty body', () => {
    expect(request(KEY)).toEqual({ method: 'POST', url: 'https://api.criminalip.io/v1/user/me', headers: { 'x-api-key': KEY } })
  })
})

describe('parse: success', () => {
  test('valid, with the plan search cap as a secondary meter', () => {
    const r = parse(res(200, DOC))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account).toEqual({ label: 'last API use 2022-04-11 06:06:54' })
    expect(r.meters).toEqual([
      { id: 'max_search', label: 'Plan search cap', unit: 'searches', window: 'month', used: null, limit: 20000000, remaining: null, resetsAt: null, resetsAtSource: null, primary: false },
    ])
    expect(r.notes).toEqual(['Criminal IP does not expose remaining credits'])
  })

  test('a Free account (seen live) answers without max_search: no empty meter, still valid', () => {
    const r = parse(res(200, {
      data: { account_type: 'not_social', last_access_date: '2026-05-15 00:00:00', membership_date: '2022-06-23 11:06:45' },
      message: 'success', status: 200,
    }))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.meters).toEqual([])
    expect(r.notes).toEqual(['Criminal IP does not expose remaining credits'])
  })

  test('the echoed key, the email and the name are never copied; the sign-in method is not a plan', () => {
    const r = parse(res(200, DOC))
    const strings = allStrings(r).join('\n')
    for (const secret of [KEY, EMAIL, 'Sample Name', 'google_social']) expect(strings).not.toContain(secret)
    expect(r.account?.plan).toBeUndefined()
  })

  test('a success without data -> unexpected_response', () => {
    expect(parse(res(200, { status: 200, message: 'success' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: the documented error table (status in the body)', () => {
  test('401 "invalid api key" -> invalid_key, whatever the HTTP status', () => {
    expect(parse(bodyStatus(401, 'invalid api key')).error).toMatchObject({ kind: 'invalid_key', httpStatus: 200, providerCode: '401' })
    expect(parse(bodyStatus(401, 'invalid api key', 401)).error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
  })

  test('412 / 415 -> unexpected_response; 413 / 414 / 500 -> provider_error', () => {
    expect(parse(bodyStatus(412, 'Missing parameter')).error).toMatchObject({ kind: 'unexpected_response', providerCode: '412' })
    expect(parse(bodyStatus(415, 'failed')).error?.kind).toBe('unexpected_response')
    expect(parse(bodyStatus(413, 'Database error')).error?.kind).toBe('provider_error')
    expect(parse(bodyStatus(414, 'Database error')).error?.kind).toBe('provider_error')
    expect(parse(bodyStatus(500, 'Unexpected error')).error?.kind).toBe('provider_error')
  })

  test('a Free key (undocumented answer) -> not checked, plan_restricted', () => {
    const plan = parse(bodyStatus(403, 'Upgrade your plan to use this API'))
    expect(plan).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'plan_restricted' })
    expect(plan.notes?.[0]).toMatch(/Starter plan/)
    expect(parse(bodyStatus(402, 'Not allowed')).notCheckedReason).toBe('plan_restricted')
  })

  test('the edge (non-JSON) answers by HTTP status', () => {
    expect(parse(html(502)).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one POST; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(criminalipProbe, KEY, [res(200, DOC)])
    expect(requests).toEqual([request(KEY)])
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring: validity (no remaining credits exist)', () => {
    expect(criminalipProbe).toMatchObject({ id: 'criminalip', field: 'criminalIpApiKey', rotationTool: 'criminalip', group: 'keys', kind: 'validity' })
  })
})
