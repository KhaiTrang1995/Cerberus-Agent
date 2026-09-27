/**
 * Travis CI probe (catalogue B8). Synthetic fixtures; the token is fake.
 */
import { describe, test, expect } from 'vitest'
import { parse, request, travisciProbe } from './travis'
import { html, res, runProbe, allStrings } from '../../testUtils'

const TOKEN = 'TESTKEY0000travisci0000'

const USER = {
  '@type': 'user',
  '@href': '/user/1',
  '@representation': 'standard',
  id: 1,
  login: 'sample-user',
  name: 'Sample User',
  github_id: 1,
  vcs_id: '1',
  vcs_type: 'GithubUser',
  avatar_url: 'https://example.test/a.png',
  education: false,
  is_syncing: false,
  synced_at: '2026-09-01T00:00:00Z',
  email: 'someone@example.test',
}

describe('request', () => {
  test('GET /user, scheme "token" (not Bearer), API version 3; never in the URL', () => {
    expect(request(TOKEN)).toEqual({
      method: 'GET',
      url: 'https://api.travis-ci.com/user',
      headers: { Authorization: `token ${TOKEN}`, 'Travis-API-Version': '3' },
    })
  })
})

describe('parse: success', () => {
  test('200 -> valid with the login as label, never the email', () => {
    const r = parse(res(200, USER))
    expect(r).toEqual({ outcome: 'valid_no_usage', meters: [], account: { label: 'sample-user' } })
    expect(allStrings(r).join(' ')).not.toContain('someone@example.test')
  })

  test('a 200 that is not a user -> unexpected_response', () => {
    expect(parse(res(200, { '@type': 'error' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('invalid token: 403 text/html whose body is just "access denied" -> invalid_key', () => {
    const r = parse(res(403, 'access denied', { contentType: 'text/html' }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 403, message: 'Travis CI rejected the token (access denied)' })
  })

  test('missing token: 403 JSON login_required -> invalid_key', () => {
    const r = parse(res(403, { '@type': 'error', error_type: 'login_required', error_message: 'login required' }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 403, providerCode: 'login_required', message: 'login required' })
  })

  test('another 403 error_type -> forbidden', () => {
    expect(parse(res(403, { '@type': 'error', error_type: 'insufficient_access', error_message: 'forbidden' })).error)
      .toMatchObject({ kind: 'forbidden', providerCode: 'insufficient_access' })
  })

  test('a full HTML page on 403 is a page in front of Travis, not an invalid key', () => {
    expect(parse(html(403)).error).toMatchObject({ kind: 'provider_error', message: 'the provider returned an error page' })
  })

  test('429 -> rate_limited; 5xx page -> provider_error', () => {
    expect(parse(res(429, 'Too Many Requests')).error?.kind).toBe('rate_limited')
    expect(parse(html(503)).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; the token never reaches the result', async () => {
    const { result, requests } = await runProbe(travisciProbe, TOKEN, [res(200, USER)])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(TOKEN))).toBe(false)
  })

  test('registry contract', () => {
    expect(travisciProbe).toMatchObject({ id: 'travisci', group: 'sources', field: 'trufflehogTravisciToken', kind: 'validity', verifiedOn: null })
  })
})
