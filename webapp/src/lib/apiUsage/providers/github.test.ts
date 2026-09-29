/**
 * GitHub rate-limit probe (plan catalogue A1): four settings fields, one probe,
 * and the rule that an Enterprise token only ever goes to the saved GHE host.
 */
import { describe, test, expect } from 'vitest'
import {
  githubEnterpriseProbe, githubHuntProbe, githubMultiscannerProbe, githubSupplyChainProbe,
  parse, parseGithubExpiry, request, tokenKind,
} from './github'
import { html, res, runProbe, allStrings, reportRow } from '../testUtils'

const TOKEN = 'ghp_TESTTOKEN000000000000000000000000'

const RATE = {
  resources: {
    core: { limit: 5000, used: 1, remaining: 4999, reset: 1790000000 },
    search: { limit: 30, used: 0, remaining: 30, reset: 1790000060 },
    graphql: { limit: 5000, used: 12, remaining: 4988, reset: 1790000000 },
    integration_manifest: { limit: 5000, used: 0, remaining: 5000, reset: 1790000000 },
    code_search: { limit: 10, used: 0, remaining: 10, reset: 1790000060 },
    audit_log: { limit: 1750, used: 0, remaining: 1750, reset: 1790000000 },
    source_import: { limit: 0, used: 0, remaining: 0, reset: 1790000000 },
  },
  rate: { limit: 5000, used: 1, remaining: 4999, reset: 1790000000 },
}

describe('request', () => {
  test('GET {api}/rate_limit, no trailing slash, bearer + the GitHub API headers', () => {
    const r = request(TOKEN, 'https://api.github.com')
    expect(r).toEqual({
      method: 'GET',
      url: 'https://api.github.com/rate_limit',
      headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
    })
  })
})

describe('helpers', () => {
  test('tokenKind from the documented prefixes', () => {
    expect(tokenKind('ghp_x')).toBe('Classic PAT')
    expect(tokenKind('github_pat_x')).toBe('Fine-grained PAT')
    expect(tokenKind('gho_x')).toBe('OAuth token')
    expect(tokenKind('something')).toBeUndefined()
  })

  test('token expiry header, UTC and offset forms', () => {
    expect(parseGithubExpiry('2027-09-06 12:00:00 UTC')).toBe('2027-09-06T12:00:00.000Z')
    expect(parseGithubExpiry('2027-09-06 12:00:00 +0200')).toBe('2027-09-06T10:00:00.000Z')
    expect(parseGithubExpiry(undefined)).toBeUndefined()
    expect(parseGithubExpiry('garbage')).toBeUndefined()
  })
})

describe('parse', () => {
  test('iterates every resource, skips limit-0 ones, core is the primary meter', () => {
    const r = parse(res(200, RATE, { headers: { 'github-authentication-token-expiration': '2027-09-06 12:00:00 UTC', 'x-oauth-scopes': 'repo, user' } }), TOKEN)
    expect(r.outcome).toBe('usage')
    expect(r.meters.map(m => m.id)).toEqual(['core', 'search', 'graphql', 'integration_manifest', 'code_search', 'audit_log'])
    expect(r.meters.find(m => m.id === 'core')).toMatchObject({ primary: true, window: 'hour', limit: 5000, remaining: 4999, used: 1, resetsAt: '2026-09-21T14:13:20.000Z' })
    expect(r.meters.find(m => m.id === 'search')).toMatchObject({ primary: false, window: 'minute' })
    expect(r.meters.find(m => m.id === 'graphql')).toMatchObject({ unit: 'points' })
    expect(r.meters.find(m => m.id === 'audit_log')?.label).toBe('Audit log')
    expect(r.account).toEqual({ plan: 'Classic PAT', expiresAt: '2027-09-06T12:00:00.000Z' })
    expect(r.notes).toEqual(['Scopes: repo, user'])
  })

  test('anonymous limits (core 60/h) mean the token was not applied', () => {
    const r = parse(res(200, { resources: { core: { limit: 60, used: 0, remaining: 60, reset: 1 } } }), TOKEN)
    expect(r.error?.kind).toBe('invalid_key')
  })

  test('401 Bad credentials -> invalid_key', () => {
    const r = parse(res(401, { message: 'Bad credentials', documentation_url: 'https://docs.github.com/rest', status: '401' }), TOKEN)
    expect(r.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, message: 'Bad credentials' })
  })

  test('403/429 with x-ratelimit-remaining 0 -> quota_exhausted', () => {
    const r = parse(res(403, { message: 'API rate limit exceeded' }, { headers: { 'x-ratelimit-remaining': '0' } }), TOKEN)
    expect(r.error?.kind).toBe('quota_exhausted')
  })

  test('secondary rate limit -> rate_limited', () => {
    expect(parse(res(403, { message: 'You have exceeded a secondary rate limit.' }), TOKEN).error?.kind).toBe('rate_limited')
    expect(parse(res(429, { message: 'slow down' }, { headers: { 'retry-after': '60' } }), TOKEN).error?.kind).toBe('rate_limited')
  })

  test('5xx -> provider_error; unexpected 200 -> unexpected_response', () => {
    expect(parse(html(503), TOKEN).error?.kind).toBe('provider_error')
    expect(parse(res(200, { foo: 1 }), TOKEN).error?.kind).toBe('unexpected_response')
  })
})

// A Multiscanner scan can point this token at a GitHub Enterprise endpoint (set
// per scan, unknown to Settings). api.github.com rejects such a token although it
// works, so a bare "Key rejected" row would be a false alarm.
describe('REGRESSION multiscanner-ghe-token-false-alarm', () => {
  const REJECTED = res(401, { message: 'Bad credentials', documentation_url: 'https://docs.github.com/rest', status: '401' })

  test('a rejected Multiscanner token says where it was checked and why that may not mean it is bad', async () => {
    const row = await reportRow(githubMultiscannerProbe, { trufflehogGithubToken: TOKEN }, [REJECTED])
    expect(row.error?.kind).toBe('invalid_key')
    expect(row.notes?.join(' ')).toMatch(/Checked against api\.github\.com.*GitHub Enterprise endpoint/)
  })

  test('a working Multiscanner token carries no such note', async () => {
    const row = await reportRow(githubMultiscannerProbe, { trufflehogGithubToken: TOKEN }, [res(200, RATE)])
    expect(row.outcome).toBe('usage')
    expect(row.notes ?? []).not.toContainEqual(expect.stringMatching(/GitHub Enterprise endpoint/))
  })

  test('the github.com-only tokens carry no such note', async () => {
    const row = await reportRow(githubHuntProbe, { githubAccessToken: TOKEN }, [REJECTED])
    expect(row.error?.kind).toBe('invalid_key')
    expect(row.notes).toBeUndefined()
  })
})

describe('the four registry entries', () => {
  test('the three github.com tokens share one service (run one after another)', () => {
    expect([githubHuntProbe, githubSupplyChainProbe, githubMultiscannerProbe].map(p => [p.field, p.service])).toEqual([
      ['githubAccessToken', 'github'],
      ['supplyChainGithubToken', 'github'],
      ['trufflehogGithubToken', 'github'],
    ])
  })

  test('a github.com token goes to api.github.com only', async () => {
    const { requests, result } = await runProbe(githubHuntProbe, TOKEN, [res(200, RATE)])
    expect(requests.map(r => r.url)).toEqual(['https://api.github.com/rate_limit'])
    expect(allStrings(result).join(' ')).not.toContain(TOKEN)
  })

  test('the Enterprise token goes to the saved host /api/v3 only', async () => {
    const { requests } = await runProbe(githubEnterpriseProbe, TOKEN, [res(200, RATE)], { githubEnterpriseHost: 'ghe.example.test' })
    expect(requests.map(r => r.url)).toEqual(['https://ghe.example.test/api/v3/rate_limit'])
  })

  test('an invalid or github.com Enterprise host is never contacted', async () => {
    for (const host of ['169.254.169.254', 'localhost', 'ghe.example.test:8443', 'github.com', 'api.github.com']) {
      const { requests, result } = await runProbe(githubEnterpriseProbe, TOKEN, [], { githubEnterpriseHost: host })
      expect(requests, host).toHaveLength(0)
      expect(result.outcome, host).toBe('error')
    }
  })

  test('GHES with rate limiting disabled falls back to /user', async () => {
    const disabled = res(404, { message: 'Rate limiting is not enabled.', documentation_url: 'https://docs.github.com' })
    const ok = await runProbe(githubEnterpriseProbe, TOKEN, [disabled, res(200, { login: 'someone' })], { githubEnterpriseHost: 'ghe.example.test' })
    expect(ok.requests.map(r => r.url)).toEqual(['https://ghe.example.test/api/v3/rate_limit', 'https://ghe.example.test/api/v3/user'])
    expect(ok.result.outcome).toBe('valid_no_usage')
    expect(ok.result.notes?.[0]).toMatch(/Rate limiting is disabled/)
    // The login is not copied: the plan does not ask for it.
    expect(allStrings(ok.result).join(' ')).not.toContain('someone')

    const bad = await runProbe(githubEnterpriseProbe, TOKEN, [disabled, res(401, { message: 'Bad credentials' })], { githubEnterpriseHost: 'ghe.example.test' })
    expect(bad.result.error?.kind).toBe('invalid_key')
  })
})
