/**
 * CircleCI probe (catalogue B7). Synthetic fixtures; the tokens are fake.
 */
import { describe, test, expect } from 'vitest'
import { circleciProbe, parse, request } from './circleci'
import { html, res, runProbe, allStrings } from '../../testUtils'

const TOKEN = 'TESTKEY0000circleci000000000000000000000'
const PROJECT_TOKEN = 'CCIPRJ_TESTKEY0000_circleci0000'

describe('request', () => {
  test('GET /api/v2/me with the Circle-Token header; never in the URL', () => {
    expect(request(TOKEN)).toEqual({ method: 'GET', url: 'https://circleci.com/api/v2/me', headers: { 'Circle-Token': TOKEN } })
  })
})

describe('parse: success', () => {
  test('200 -> valid with the login as label', () => {
    expect(parse(res(200, { id: '00000000-0000-0000-0000-000000000000', login: 'sample-user', name: 'Sample User', avatar_url: 'https://example.test/a.png' }), TOKEN))
      .toEqual({ outcome: 'valid_no_usage', meters: [], account: { label: 'sample-user' } })
  })

  test('a 200 that is not a user -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' }), TOKEN).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), TOKEN).error?.kind).toBe('unexpected_response')
  })
})

describe('parse: errors', () => {
  test('invalid token: 401 PLAIN TEXT -> invalid_key, the text kept, the personal-token hint added', () => {
    const r = parse(res(401, 'Invalid token provided.'), TOKEN)
    expect(r.error).toEqual({
      kind: 'invalid_key',
      httpStatus: 401,
      message: 'Invalid token provided. A project token is not accepted here: use a personal API token',
    })
  })

  test('missing token: 401 JSON "You must log in first." -> invalid_key', () => {
    expect(parse(res(401, { message: 'You must log in first.' }), TOKEN).error)
      .toMatchObject({ kind: 'invalid_key', message: 'You must log in first. A project token is not accepted here: use a personal API token' })
  })

  test('a CCIPRJ_ project token -> invalid_key that says so', () => {
    expect(parse(res(401, 'Invalid token provided.'), PROJECT_TOKEN).error?.message)
      .toBe('Invalid token provided. This is a project token, which API v2 does not accept: use a personal API token')
  })

  test('an HTML 401 falls back to a fixed text', () => {
    expect(parse(html(401), TOKEN).error?.message).toMatch(/^CircleCI rejected the token\./)
  })

  test('429 -> rate_limited; 5xx page -> provider_error', () => {
    expect(parse(res(429, { message: 'Rate limit exceeded' }, { headers: { 'Retry-After': '30' } }), TOKEN).error?.kind).toBe('rate_limited')
    expect(parse(html(502), TOKEN).error?.kind).toBe('provider_error')
  })
})

describe('run', () => {
  test('one call; the token never reaches the result', async () => {
    const { result, requests } = await runProbe(circleciProbe, TOKEN, [res(401, 'Invalid token provided.')])
    expect(requests).toHaveLength(1)
    expect(result.error?.kind).toBe('invalid_key')
    expect(allStrings(result).some(s => s.includes(TOKEN))).toBe(false)
  })

  test('registry contract', () => {
    expect(circleciProbe).toMatchObject({ id: 'circleci', group: 'sources', field: 'trufflehogCircleciToken', kind: 'validity', verifiedOn: null })
  })
})
