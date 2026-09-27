/**
 * Postman probe (catalogue B6). Synthetic fixtures written from the
 * "Get authenticated user" reference; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, postmanProbe, request } from './postman'
import { html, res, runProbe, allStrings } from '../../testUtils'

const KEY = 'PMAK-TESTKEY0000postman0000-000000000000000000'

const ME = {
  user: {
    id: 12345678,
    sub: '00000000-0000-0000-0000-000000000000',
    username: 'sample-user',
    email: 'someone@example.test',
    fullName: 'Sample User',
    avatar: null,
    isPublic: false,
    emailVerified: true,
    teamId: 0,
    teamName: null,
    teamDomain: null,
    roles: ['user'],
  },
  operations: [
    { name: 'api_usage', limit: 1000, usage: 120, overage: 0 },
    { name: 'mock_usage', limit: 1000, usage: 0, overage: 0 },
    { name: 'monitor_request_runs', limit: 99999999, usage: 40, overage: 0 },
    { name: 'file_storage_limit', limit: 20, usage: 0.5, overage: 0 },
    { name: 'brand_new_operation', limit: 10, usage: 11, overage: 1 },
  ],
}

describe('request', () => {
  test('GET /me with the X-API-Key header; never in the URL', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://api.getpostman.com/me', headers: { 'X-API-Key': KEY } })
  })
})

describe('parse: success', () => {
  test('operations -> meters; api_usage is the primary monthly meter; 99999999 is unlimited', () => {
    const r = parse(res(200, ME))
    expect(r.outcome).toBe('usage')
    expect(r.account).toEqual({ label: 'sample-user', plan: 'Personal' })
    expect(r.meters).toEqual([
      { id: 'api_usage', label: 'Postman API calls', unit: 'requests', window: 'month', used: 120, limit: 1000, remaining: 880, resetsAt: null, resetsAtSource: null, primary: true },
      { id: 'mock_usage', label: 'Mock server calls', unit: 'requests', window: 'month', used: 0, limit: 1000, remaining: 1000, resetsAt: null, resetsAtSource: null, primary: false },
      { id: 'monitor_request_runs', label: 'Monitor requests', unit: 'requests', window: 'month', used: 40, limit: null, remaining: null, resetsAt: null, resetsAtSource: null, primary: false, note: 'unlimited' },
      { id: 'file_storage_limit', label: 'File storage (GB)', unit: 'count', window: 'lifetime', used: 0.5, limit: 20, remaining: 19.5, resetsAt: null, resetsAtSource: null, primary: false },
      { id: 'brand_new_operation', label: 'Brand new operation', unit: 'count', window: 'month', used: 11, limit: 10, remaining: 0, resetsAt: null, resetsAtSource: null, primary: false, note: 'overage: 1' },
    ])
  })

  test('a team account: the team name is the plan', () => {
    const r = parse(res(200, { ...ME, user: { ...ME.user, teamId: 7, teamName: 'Sample Team' } }))
    expect(r.account?.plan).toBe('Sample Team')
  })

  test('no operations (Guest / Partner role): the monthly API-call headers give the primary meter', () => {
    const r = parse(res(200, { user: ME.user }, { headers: { 'RateLimit-Limit-Month': '1000', 'RateLimit-Remaining-Month': '879' } }))
    expect(r.outcome).toBe('usage')
    expect(r.meters).toEqual([{
      id: 'api_usage', label: 'Postman API calls', unit: 'requests', window: 'month',
      used: 121, limit: 1000, remaining: 879, resetsAt: null, resetsAtSource: null, primary: true,
    }])
  })

  test('the X- prefixed monthly headers work too', () => {
    const r = parse(res(200, { user: ME.user }, { headers: { 'X-RateLimit-Limit-Month': '1000', 'X-RateLimit-Remaining-Month': '10' } }))
    expect(r.meters[0]).toMatchObject({ id: 'api_usage', limit: 1000, remaining: 10 })
  })

  test('no operations and no headers -> valid, with a note', () => {
    const r = parse(res(200, { user: ME.user }))
    expect(r).toMatchObject({ outcome: 'valid_no_usage', meters: [], notes: ['Postman reports no usage for this account role'] })
  })

  test('the email and full name are never copied anywhere', () => {
    const text = allStrings(parse(res(200, ME))).join(' ')
    expect(text).not.toContain('someone@example.test')
    expect(text).not.toContain('Sample User')
  })
})

describe('parse: errors', () => {
  test('401 AuthenticationError -> invalid_key with Postman\'s message', () => {
    const r = parse(res(401, { error: { name: 'AuthenticationError', message: 'Invalid API Key. Every request requires a valid API Key to be sent.' } }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, message: 'Invalid API Key. Every request requires a valid API Key to be sent.' })
  })

  test('429 rateLimited -> rate_limited', () => {
    expect(parse(res(429, { error: { name: 'rateLimited', message: 'Rate limit exceeded. Please retry after 1669048687' } })).error)
      .toMatchObject({ kind: 'rate_limited', providerCode: 'rateLimited' })
  })

  test('429 serviceLimitExhausted -> quota_exhausted', () => {
    expect(parse(res(429, { error: { name: 'serviceLimitExhausted', message: "You've reached the Postman API usage limit." } })).error)
      .toMatchObject({ kind: 'quota_exhausted', providerCode: 'serviceLimitExhausted' })
  })

  test('5xx page -> provider_error; a 200 without a user -> unexpected_response', () => {
    expect(parse(html(503)).error?.kind).toBe('provider_error')
    expect(parse(res(200, { operations: [] })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(postmanProbe, KEY, [res(200, ME)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('the cost note discloses the Postman API call', () => {
    expect(postmanProbe.costNote).toMatch(/Costs 1 Postman API call/)
    expect(postmanProbe).toMatchObject({ id: 'postman', group: 'sources', field: 'trufflehogPostmanToken', kind: 'usage', verifiedOn: null })
  })
})
