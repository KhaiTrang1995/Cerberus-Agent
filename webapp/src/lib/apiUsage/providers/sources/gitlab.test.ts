/**
 * GitLab.com probe (catalogue B1). Synthetic fixtures written from the
 * documented token entity; the token is fake.
 */
import { describe, test, expect } from 'vitest'
import { gitlabProbe, isNotAccessToken, parse, parseUser, rateLimitMeter, request, SELF_HOSTED_NOTE, userRequest } from './gitlab'
import { html, res, runProbe, allStrings } from '../../testUtils'

const TOKEN = 'glpat-TESTKEY0000gitlab0000'

const RATE = {
  'RateLimit-Limit': '2000',
  'RateLimit-Observed': '3',
  'RateLimit-Remaining': '1997',
  'RateLimit-Reset': '1790433180',
  'RateLimit-Name': 'throttle_authenticated_api',
}

const SELF = {
  id: 1,
  name: 'redamon-scan',
  revoked: false,
  created_at: '2026-01-10T09:00:00.000Z',
  description: 'secret scanning',
  scopes: ['read_api', 'read_repository'],
  user_id: 2,
  last_used_at: '2026-09-25T08:00:00.000Z',
  last_used_ips: ['192.0.2.10'],
  active: true,
  expires_at: '2027-01-10',
  granular: false,
}

const NOT_PAT = { message: '400 Bad request - This endpoint requires token type to be a personal access token' }

describe('request', () => {
  test('GET /personal_access_tokens/self with the PRIVATE-TOKEN header; never in the URL', () => {
    expect(request(TOKEN)).toEqual({
      method: 'GET',
      url: 'https://gitlab.com/api/v4/personal_access_tokens/self',
      headers: { 'PRIVATE-TOKEN': TOKEN },
    })
  })

  test('the fallback is GET /user, same header', () => {
    expect(userRequest(TOKEN)).toEqual({ method: 'GET', url: 'https://gitlab.com/api/v4/user', headers: { 'PRIVATE-TOKEN': TOKEN } })
  })
})

describe('parse: success', () => {
  test('an active token: valid, token name + expiry, scopes, per-minute headroom as a secondary meter', () => {
    expect(parse(res(200, SELF, { headers: RATE }))).toEqual({
      outcome: 'valid_no_usage',
      account: { label: 'redamon-scan', expiresAt: '2027-01-10T00:00:00.000Z' },
      notes: ['Scopes: read_api, read_repository'],
      meters: [{
        id: 'api_minute', label: 'GitLab API (per minute)', unit: 'requests', window: 'minute',
        used: 3, limit: 2000, remaining: 1997,
        resetsAt: new Date(1790433180 * 1000).toISOString(), resetsAtSource: 'provider', primary: false,
      }],
    })
  })

  test('no expiry and no rate headers: no expiresAt, no meter', () => {
    const r = parse(res(200, { ...SELF, expires_at: null }))
    expect(r.account).toEqual({ label: 'redamon-scan', expiresAt: undefined })
    expect(r.meters).toEqual([])
  })

  test('rateLimitMeter needs both limit and remaining', () => {
    expect(rateLimitMeter({ 'ratelimit-limit': '2000' })).toBeUndefined()
  })
})

describe('parse: errors', () => {
  test('401 -> invalid_key, saying a self-hosted token cannot be checked here', () => {
    const r = parse(res(401, { message: '401 Unauthorized' }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
    expect(r.error?.message).toContain('401 Unauthorized')
    expect(r.error?.message).toContain(SELF_HOSTED_NOTE)
  })

  test('a 200 with revoked or inactive -> invalid_key', () => {
    expect(parse(res(200, { ...SELF, revoked: true })).error).toMatchObject({ kind: 'invalid_key', message: 'GitLab reports this token as revoked or inactive' })
    expect(parse(res(200, { ...SELF, active: false })).error?.kind).toBe('invalid_key')
  })

  test('403 blocked account -> forbidden with GitLab\'s message', () => {
    const r = parse(res(403, { message: '403 Forbidden - Your account has been blocked.' }))
    expect(r.error).toMatchObject({ kind: 'forbidden', httpStatus: 403 })
    expect(r.error?.message).toMatch(/blocked/)
  })

  test('429 -> rate_limited; 5xx page -> provider_error', () => {
    expect(parse(res(429, 'Retry later', { headers: { 'Retry-After': '60' } })).error?.kind).toBe('rate_limited')
    expect(parse(html(502)).error?.kind).toBe('provider_error')
  })

  test('a 200 that is not a token entity -> unexpected_response', () => {
    expect(parse(res(200, { id: 1 })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('the OAuth-token fallback', () => {
  test('isNotAccessToken matches only that 400', () => {
    expect(isNotAccessToken(res(400, NOT_PAT))).toBe(true)
    expect(isNotAccessToken(res(400, { message: '400 Bad request - something else' }))).toBe(false)
    expect(isNotAccessToken(res(401, NOT_PAT))).toBe(false)
  })

  test('400 not-an-access-token -> GET /user: valid with the username, never the email', async () => {
    const { result, requests } = await runProbe(gitlabProbe, TOKEN, [
      res(400, NOT_PAT),
      res(200, { id: 2, username: 'sample-user', name: 'Sample User', state: 'active', email: 'someone@example.test', public_email: 'someone@example.test' }, { headers: RATE }),
    ])
    expect(requests.map(r => r.url)).toEqual([
      'https://gitlab.com/api/v4/personal_access_tokens/self',
      'https://gitlab.com/api/v4/user',
    ])
    expect(requests[1].headers).toEqual({ 'PRIVATE-TOKEN': TOKEN })
    expect(result.outcome).toBe('valid_no_usage')
    expect(result.account).toEqual({ label: 'sample-user' })
    expect(result.notes?.[0]).toMatch(/Not a personal, project or group access token/)
    expect(result.meters).toHaveLength(1)
    expect(allStrings(result).join(' ')).not.toContain('@example.test')
  })

  test('/user 401 -> invalid_key with the self-hosted note', () => {
    expect(parseUser(res(401, { message: '401 Unauthorized' })).error?.message).toContain(SELF_HOSTED_NOTE)
  })

  test('/user 200 without a username -> unexpected_response', () => {
    expect(parseUser(res(200, { id: 2 })).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call for an access token; the token never reaches the result', async () => {
    const { result, requests } = await runProbe(gitlabProbe, TOKEN, [res(200, SELF, { headers: RATE })])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(TOKEN))).toBe(false)
  })

  test('registry contract', () => {
    expect(gitlabProbe).toMatchObject({ id: 'gitlab', group: 'sources', field: 'trufflehogGitlabToken', kind: 'validity', verifiedOn: null })
  })
})
