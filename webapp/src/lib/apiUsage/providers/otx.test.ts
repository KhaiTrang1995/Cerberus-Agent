/**
 * AlienVault OTX validity probe (plan catalogue A12). Fixtures are synthetic,
 * from the `/users/me` schema (every field required) and the observed 403;
 * the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { otxProbe, parse, request } from './otx'
import { html, res, runProbe, allStrings } from '../testUtils'

const KEY = 'TESTKEY0000otx00000000000000000000000000000000000000000000000000'

const ME = {
  username: 'sample-user',
  user_id: 1,
  pulse_count: 0,
  subscriber_count: 0,
  award_count: 0,
  follower_count: 0,
  indicator_count: 0,
  member_since: '1343 days ago ',
  avatar_url: 'https://otx.alienvault.com/assets/images/default-avatar.png',
}

describe('request', () => {
  test('users/me with X-OTX-API-KEY, as recon sends; the key never in the URL', () => {
    expect(request(KEY)).toEqual({ method: 'GET', url: 'https://otx.alienvault.com/api/v1/users/me', headers: { 'X-OTX-API-KEY': KEY } })
  })
})

describe('parse', () => {
  test('200 -> valid, the username as the label; member_since is not a date', () => {
    const r = parse(res(200, ME))
    expect(r.outcome).toBe('valid_no_usage')
    expect(r.account).toEqual({ label: 'sample-user' })
    expect(r.notes).toEqual(['OTX has no quota API; ~10,000 requests/hour with a key'])
    expect(allStrings(r).join('\n')).not.toContain('days ago')
  })

  test('an email-shaped username is never the label', () => {
    expect(parse(res(200, { ...ME, username: 'someone@example.test' })).account?.label).toBeUndefined()
  })

  test('403 "Authentication required" (observed, as Anonymous) -> invalid_key, neutral message', () => {
    const r = parse(res(403, { detail: 'Authentication required' }, { headers: { 'X-Remote-User-Name': 'Anonymous', 'X-OTX-ACTIVE': '0' } }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 403, message: 'OTX rejected the key' })
  })

  test('429 -> rate_limited; 5xx and CloudFront HTML -> provider_error', () => {
    expect(parse(res(429, { detail: 'Request was throttled.' })).error?.kind).toBe('rate_limited')
    expect(parse(html(502)).error?.kind).toBe('provider_error')
    expect(parse(html(403)).error?.kind).toBe('provider_error')
  })

  test('a 200 without a username -> unexpected_response', () => {
    expect(parse(res(200, { user_id: 1 })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    const { result, requests } = await runProbe(otxProbe, KEY, [res(200, ME)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
  })

  test('registry wiring: validity', () => {
    expect(otxProbe).toMatchObject({ id: 'otx', field: 'otxApiKey', rotationTool: 'otx', group: 'keys', kind: 'validity' })
  })
})
