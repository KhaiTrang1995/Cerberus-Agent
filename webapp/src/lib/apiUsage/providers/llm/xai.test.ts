/**
 * xAI key-information probe (plan catalogue C6). Fixtures are synthetic,
 * shaped like the documented response; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { createdAt, parse, request, xaiProbe } from './xai'
import { html, res, runProbe, allStrings } from '../../testUtils'

const KEY = 'TESTKEY-0000-xai-AAAAAAAAAAAAAAAAAAAAAgA'

const KEY_INFO = {
  redacted_api_key: 'xai-****AgA',
  user_id: '00000000-0000-4000-8000-000000000001',
  name: 'redamon-agent',
  create_time: '2026-03-01T09:30:00Z',
  modify_time: '2026-03-01T09:30:00Z',
  modified_by: '00000000-0000-4000-8000-000000000001',
  team_id: '00000000-0000-4000-8000-000000000002',
  acls: ['api-key:model:*', 'api-key:endpoint:*'],
  api_key_id: '00000000-0000-4000-8000-000000000003',
  team_blocked: false,
  api_key_blocked: false,
  api_key_disabled: false,
}

describe('request', () => {
  test('GET /v1/api-key with the key as a Bearer header', () => {
    const r = request(KEY)
    expect(r).toEqual({ method: 'GET', url: 'https://api.x.ai/v1/api-key', headers: { Authorization: `Bearer ${KEY}` } })
    expect(r.url).not.toContain(KEY)
  })
})

describe('createdAt: documented as Unix time, served as ISO', () => {
  test('ISO string, epoch number and numeric string all parse', () => {
    expect(createdAt('2026-03-01T09:30:00Z')).toBe('2026-03-01T09:30:00.000Z')
    expect(createdAt(1772357400)).toBe('2026-03-01T09:30:00.000Z')
    expect(createdAt('1772357400')).toBe('2026-03-01T09:30:00.000Z')
  })

  test('missing or garbage -> null', () => {
    expect(createdAt(undefined)).toBeNull()
    expect(createdAt('not a date')).toBeNull()
  })
})

describe('parse: success', () => {
  test('valid, no usage: the key name as the account label and its creation date', () => {
    const r = parse(res(200, KEY_INFO))
    expect(r).toEqual({
      outcome: 'valid_no_usage', meters: [],
      account: { label: 'redamon-agent' },
      notes: ['Key created 2026-03-01'],
    })
  })

  test('the redacted key and the user/team ids are never copied', () => {
    const joined = allStrings(parse(res(200, KEY_INFO))).join(' ')
    expect(joined).not.toContain('xai-****')
    expect(joined).not.toContain('00000000-0000-4000-8000')
  })

  test.each([
    ['api_key_blocked', 'key blocked/disabled: the key is blocked'],
    ['api_key_disabled', 'key blocked/disabled: the key is disabled'],
    ['team_blocked', 'key blocked/disabled: the team is blocked'],
  ])('%s -> forbidden', (flag, message) => {
    const r = parse(res(200, { ...KEY_INFO, [flag]: true }))
    expect(r.error).toEqual({ kind: 'forbidden', httpStatus: 200, message })
    expect(r.account?.label).toBe('redamon-agent')
  })

  test('several flags are listed together', () => {
    const r = parse(res(200, { ...KEY_INFO, team_blocked: true, api_key_disabled: true }))
    expect(r.error?.message).toBe('key blocked/disabled: the team is blocked; the key is disabled')
  })
})

describe('parse: errors', () => {
  test('401 unauthenticated:no-credentials (string `error`) -> invalid_key with the code', () => {
    const r = parse(res(401, { code: 'unauthenticated:no-credentials', error: 'No credentials provided' }))
    expect(r.error).toEqual({ kind: 'invalid_key', httpStatus: 401, providerCode: 'unauthenticated:no-credentials', message: 'No credentials provided' })
  })

  test('an unknown key answered 400 "Incorrect API key provided: xa***gA" -> invalid_key; the fragment passes, the key is never added', () => {
    const r = parse(res(400, {
      code: 'Client specified an invalid argument',
      error: 'Incorrect API key provided: xa***gA. You can obtain an API key from https://console.x.ai.',
    }))
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 400 })
    expect(r.error?.message).toContain('xa***gA')
    expect(allStrings(r).some(s => s.includes(KEY))).toBe(false)
  })

  test('another 400 stays unexpected_response', () => {
    expect(parse(res(400, { code: 'Client specified an invalid argument', error: 'Malformed request' })).error?.kind).toBe('unexpected_response')
  })

  test('429 out of credits / spending limit -> quota_exhausted; a plain 429 -> rate_limited', () => {
    expect(parse(res(429, {
      code: 'Some resource has been exhausted',
      error: 'Your team has either used all available credits or reached its monthly spending limit.',
    })).error?.kind).toBe('quota_exhausted')
    expect(parse(res(429, { code: 'Some resource has been exhausted', error: 'Too many requests' })).error?.kind).toBe('rate_limited')
  })

  test('404 plain text -> unexpected_response with the text', () => {
    expect(parse(res(404, 'Not Found')).error).toEqual({ kind: 'unexpected_response', httpStatus: 404, message: 'Not Found' })
  })

  test('403 -> forbidden; 5xx -> provider_error', () => {
    expect(parse(res(403, { code: 'permission denied', error: 'The caller does not have permission' })).error?.kind).toBe('forbidden')
    expect(parse(html(502)).error?.kind).toBe('provider_error')
  })

  test('a 200 that is not a key description -> unexpected_response', () => {
    expect(parse(res(200, { hello: 'world' })).error?.kind).toBe('unexpected_response')
    expect(parse(html(200)).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the key never reaches the result', async () => {
    for (const answer of [res(200, KEY_INFO), res(401, { code: 'unauthenticated:no-credentials', error: 'No credentials provided' })]) {
      const { result, requests } = await runProbe(xaiProbe, KEY, [answer])
      expect(requests).toHaveLength(1)
      expect(allStrings(result).some(s => s.includes(KEY))).toBe(false)
    }
  })

  test('LLM row contract', () => {
    expect(xaiProbe).toMatchObject({
      id: 'llm-xai', service: 'xai', group: 'llm', field: 'apiKey', kind: 'validity', verifiedOn: null,
      endpoint: 'GET api.x.ai/v1/api-key',
    })
  })
})
