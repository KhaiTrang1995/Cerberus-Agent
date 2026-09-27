/**
 * Hugging Face probe (catalogue B3). Synthetic fixtures written from the
 * whoami-v2 schema (OpenAPI / huggingface.js); the token is fake.
 */
import { describe, test, expect } from 'vitest'
import { huggingfaceProbe, itemParams, parse, rateLimitMeter, request } from './huggingface'
import { NOW, html, res, runProbe, allStrings } from '../../testUtils'

const TOKEN = 'hf_TESTKEY0000huggingface0000'

const RATE = {
  RateLimit: '"api";r=992;t=184',
  'RateLimit-Policy': '"fixed window";"api";q=1000;w=300',
}

const WHOAMI = {
  type: 'user',
  id: '000000000000000000000000',
  name: 'sample-user',
  fullname: 'Sample User',
  email: 'someone@example.test',
  emailVerified: true,
  isPro: true,
  canPay: true,
  billingMode: 'prepaid',
  avatarUrl: 'https://example.test/avatar.png',
  periodEnd: null,
  orgs: [{ type: 'org', id: '1', name: 'sample-org', fullname: 'Sample Org', roleInOrg: 'read', isEnterprise: true, plan: 'enterprise' }],
  auth: {
    type: 'access_token',
    accessToken: { displayName: 'redamon-scan', role: 'read', createdAt: '2026-01-10T09:00:00.000Z' },
  },
}

describe('request', () => {
  test('GET /api/whoami-v2 with a Bearer token; never in the URL', () => {
    expect(request(TOKEN)).toEqual({
      method: 'GET',
      url: 'https://huggingface.co/api/whoami-v2',
      headers: { Authorization: `Bearer ${TOKEN}` },
    })
  })
})

describe('parse: success', () => {
  test('valid: username label, plan, token name + role, the 5-minute api window as a secondary meter', () => {
    expect(parse(res(200, WHOAMI, { headers: RATE }), NOW)).toEqual({
      outcome: 'valid_no_usage',
      account: { label: 'sample-user', plan: 'PRO · org plan: enterprise', expiresAt: undefined },
      notes: ['Token: redamon-scan (read)'],
      meters: [{
        id: 'api', label: 'HF API (5 min)', unit: 'requests', window: 'minute',
        used: 8, limit: 1000, remaining: 992,
        resetsAt: '2026-09-26T14:35:09.000Z', resetsAtSource: 'provider', primary: false,
      }],
    })
  })

  test('a free account without orgs, an expiring OAuth token, no rate headers', () => {
    const r = parse(res(200, {
      ...WHOAMI, isPro: false, orgs: [],
      auth: { type: 'oauth', expiresAt: '2026-12-31T00:00:00.000Z' },
    }), NOW)
    expect(r.account).toEqual({ label: 'sample-user', plan: 'Free', expiresAt: '2026-12-31T00:00:00.000Z' })
    expect(r.notes).toBeUndefined()
    expect(r.meters).toEqual([])
  })

  test('an org token: no personal plan, the type noted', () => {
    const r = parse(res(200, { type: 'org', name: 'sample-org', auth: { type: 'access_token' } }), NOW)
    expect(r.account?.plan).toBeUndefined()
    expect(r.notes).toEqual(['Account type: org'])
  })

  test('the email is never copied anywhere', () => {
    expect(allStrings(parse(res(200, WHOAMI, { headers: RATE }), NOW)).join(' ')).not.toContain('someone@example.test')
  })
})

describe('rate-limit headers', () => {
  test('itemParams reads the named item of a list', () => {
    expect(itemParams('"resolvers";r=1;t=2, "api";r=992;t=184', 'api')).toEqual({ r: '992', t: '184' })
    expect(itemParams('"fixed window";"api";q=1000;w=300', 'api')).toEqual({ q: '1000', w: '300' })
    expect(itemParams(undefined, 'api')).toBeUndefined()
  })

  test('remaining without a policy: a meter with no limit', () => {
    expect(rateLimitMeter({ ratelimit: '"api";r=5;t=10' }, NOW)).toMatchObject({ remaining: 5, limit: null, used: null, label: 'HF API' })
  })

  test('no RateLimit header -> no meter', () => {
    expect(rateLimitMeter({ 'ratelimit-policy': '"fixed window";"api";q=1000;w=300' }, NOW)).toBeUndefined()
  })
})

describe('parse: errors', () => {
  test('401 "Invalid username or password." -> invalid_key, worded for a token', () => {
    const r = parse(res(401, { error: 'Invalid username or password.' }, { headers: { 'x-error-message': 'Invalid username or password.' } }), NOW)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401 })
    expect(r.error?.message).toMatch(/rejected the token/)
  })

  test('429 -> rate_limited; 5xx page -> provider_error', () => {
    expect(parse(res(429, { error: 'Too many requests' }), NOW).error?.kind).toBe('rate_limited')
    expect(parse(html(503), NOW).error?.kind).toBe('provider_error')
  })

  test('a 200 without a name -> unexpected_response', () => {
    expect(parse(res(200, { type: 'user' }), NOW).error?.kind).toBe('unexpected_response')
    expect(parse(html(200), NOW).error?.kind).toBe('unexpected_response')
  })
})

describe('run', () => {
  test('one call; the token never reaches the result', async () => {
    const { result, requests } = await runProbe(huggingfaceProbe, TOKEN, [res(200, WHOAMI, { headers: RATE })])
    expect(requests).toHaveLength(1)
    expect(allStrings(result).some(s => s.includes(TOKEN))).toBe(false)
  })

  test('registry contract', () => {
    expect(huggingfaceProbe).toMatchObject({ id: 'huggingface', group: 'sources', field: 'trufflehogHuggingfaceToken', kind: 'validity', verifiedOn: null })
  })
})
