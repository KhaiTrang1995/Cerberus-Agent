/**
 * Helpers shared by the LLM provider probes (plan catalogue Part C).
 */
import { describe, test, expect } from 'vitest'
import { LLM_PROBE, bearer, fail, listed, providerCode, withNote } from './common'
import { html, res } from '../../testUtils'

describe('LLM_PROBE', () => {
  test('every LLM row is one key in the apiKey field, parsed from the docs only', () => {
    expect(LLM_PROBE).toEqual({ group: 'llm', field: 'apiKey', verifiedOn: null })
  })
})

describe('bearer', () => {
  test('an Authorization Bearer header', () => {
    expect(bearer('TESTKEY-0000-common')).toEqual({ Authorization: 'Bearer TESTKEY-0000-common' })
  })
})

describe('providerCode', () => {
  test('error.code first, then error.type, then a top-level code', () => {
    expect(providerCode(res(401, { error: { code: 'invalid_api_key', type: 'invalid_request_error' } }))).toBe('invalid_api_key')
    expect(providerCode(res(401, { error: { code: null, type: 'authentication_error' } }))).toBe('authentication_error')
    expect(providerCode(res(401, { code: 'unauthenticated:no-credentials', error: 'No credentials' }))).toBe('unauthenticated:no-credentials')
  })

  test('numeric codes (an HTTP status echoed back) are skipped', () => {
    expect(providerCode(res(401, { error: { code: 401, message: 'User not found.' } }))).toBeUndefined()
    expect(providerCode(res(404, { code: 5, error: 'url.not_found' }))).toBeUndefined()
  })

  test('no JSON body -> undefined', () => {
    expect(providerCode(res(401, 'Authentication Fails (governor)'))).toBeUndefined()
    expect(providerCode(html(502))).toBeUndefined()
  })
})

describe('fail', () => {
  test('default status mapping with the provider code attached', () => {
    const r = fail(res(401, { error: { message: 'Incorrect API key provided', code: 'invalid_api_key' } }))
    expect(r).toMatchObject({ outcome: 'error', error: { kind: 'invalid_key', httpStatus: 401, providerCode: 'invalid_api_key', message: 'Incorrect API key provided' } })
  })

  test('an explicit kind and code override the defaults', () => {
    const r = fail(res(400, { error: { message: 'bad', status: 'INVALID_ARGUMENT' } }), 'invalid_key', 'API_KEY_INVALID')
    expect(r.error).toMatchObject({ kind: 'invalid_key', providerCode: 'API_KEY_INVALID' })
  })

  test('no code in the body -> no providerCode field', () => {
    expect(fail(res(503, 'upstream down')).error).toEqual({ kind: 'provider_error', httpStatus: 503, message: 'upstream down' })
  })
})

describe('listed', () => {
  test('a 2xx JSON object or array proves the key', () => {
    expect(listed(res(200, { object: 'list', data: [] }))).toMatchObject({ outcome: 'valid_no_usage', meters: [] })
    expect(listed(res(200, [{ id: 'model-a' }]))).toMatchObject({ outcome: 'valid_no_usage' })
  })

  test('a 2xx JSON body cut at the read cap still proves the key', () => {
    const cut = { ...res(200, '[{"id":"model-a"},{"id":"mod', { contentType: 'application/json' }), truncated: true }
    expect(listed(cut)?.outcome).toBe('valid_no_usage')
  })

  test('a 2xx HTML page or empty body is not a listing', () => {
    expect(listed(html(200))?.error?.kind).toBe('unexpected_response')
    expect(listed(res(200))?.error?.kind).toBe('unexpected_response')
    expect(listed({ ...html(200), truncated: true })?.error?.kind).toBe('unexpected_response')
  })

  test('a non-2xx is left to the provider (undefined)', () => {
    expect(listed(res(401, { error: 'x' }))).toBeUndefined()
    expect(listed(res(404, 'not found'))).toBeUndefined()
  })
})

describe('withNote', () => {
  test('appends without dropping existing notes', () => {
    expect(withNote({ outcome: 'valid_no_usage', meters: [], notes: ['a'] }, 'b').notes).toEqual(['a', 'b'])
    expect(withNote({ outcome: 'valid_no_usage', meters: [] }, 'b').notes).toEqual(['b'])
  })
})
