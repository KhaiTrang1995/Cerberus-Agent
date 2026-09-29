/**
 * probeFetch against real local HTTP servers, so the redirect, timeout and
 * body-cap behaviour is Node's actual behaviour, not a mock's.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { MAX_BODY_BYTES, ProbeTransportError, probeFetch, scrub, hasControlChars, PROBE_USER_AGENT } from './http'

let target: http.Server
let redirector: http.Server
let targetHits: http.IncomingHttpHeaders[] = []
let base = ''
let redirectBase = ''

function listen(server: http.Server): Promise<string> {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)
  }))
}

beforeAll(async () => {
  target = http.createServer((req, res) => {
    targetHits.push(req.headers)
    const url = new URL(req.url ?? '/', 'http://x')
    switch (url.pathname) {
      case '/json':
        res.writeHead(200, { 'content-type': 'application/json', 'x-ratelimit-remaining': '7', 'set-cookie': 'sid=secret' })
        res.end('{"ok":true,"n":1}')
        return
      case '/octet-json':
        res.writeHead(403, { 'content-type': 'application/octet-stream' })
        res.end('{"status_code":403,"message":"this service not aviliable in your area"}')
        return
      case '/plain401':
        res.writeHead(401)
        res.end('Please check user credentials')
        return
      case '/html':
        res.writeHead(403, { 'content-type': 'text/html; charset=UTF-8', 'cf-mitigated': 'challenge' })
        res.end('<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>')
        return
      case '/nvd404':
        res.writeHead(404, { message: 'Invalid apiKey.' })
        res.end()
        return
      case '/big':
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(`{"pad":"${'x'.repeat(1024 * 1024)}"}`)
        return
      case '/slow':
        setTimeout(() => { res.writeHead(200); res.end('late') }, 2000)
        return
      default:
        res.writeHead(200)
        res.end('ok')
    }
  })
  redirector = http.createServer((req, res) => {
    res.writeHead(302, { location: `${base}/json` })
    res.end()
  })
  base = await listen(target)
  redirectBase = await listen(redirector)
})

afterAll(() => {
  target.close()
  redirector.close()
})

describe('probeFetch', () => {
  test('JSON body, status, allowlisted headers only, the default User-Agent', async () => {
    targetHits = []
    const r = await probeFetch({ method: 'GET', url: `${base}/json`, headers: { 'x-apikey': 'k' } })
    expect(r.status).toBe(200)
    expect(r.json).toEqual({ ok: true, n: 1 })
    expect(r.headers['x-ratelimit-remaining']).toBe('7')
    expect(r.headers['set-cookie']).toBeUndefined()
    expect(r.contentType).toBe('application/json')
    expect(targetHits[0]['user-agent']).toBe(PROBE_USER_AGENT)
  })

  test('JSON is sniffed from the body even with a non-JSON content type', async () => {
    const r = await probeFetch({ method: 'GET', url: `${base}/octet-json` })
    expect(r.status).toBe(403)
    expect(r.json).toMatchObject({ status_code: 403 })
  })

  test('a plain-text 401 is text, not JSON', async () => {
    const r = await probeFetch({ method: 'GET', url: `${base}/plain401` })
    expect(r.json).toBeUndefined()
    expect(r.text).toBe('Please check user credentials')
  })

  test('an HTML challenge page is text with its content type and the cf-mitigated header', async () => {
    const r = await probeFetch({ method: 'GET', url: `${base}/html` })
    expect(r.json).toBeUndefined()
    expect(r.contentType).toContain('text/html')
    expect(r.headers['cf-mitigated']).toBe('challenge')
  })

  test('an empty 404 keeps the reason from the `message` header (NVD)', async () => {
    const r = await probeFetch({ method: 'GET', url: `${base}/nvd404` })
    expect(r.status).toBe(404)
    expect(r.text).toBe('')
    expect(r.headers.message).toBe('Invalid apiKey.')
  })

  test('a redirect is never followed: the second host is never contacted, and it is unexpected_response', async () => {
    targetHits = []
    const err = await probeFetch({ method: 'GET', url: `${redirectBase}/`, headers: { 'x-apikey': 'SECRET-KEY-1234' } })
      .catch(e => e)
    expect(err).toBeInstanceOf(ProbeTransportError)
    expect((err as ProbeTransportError).kind).toBe('unexpected_response')
    expect((err as ProbeTransportError).message).toMatch(/redirect/)
    expect(targetHits).toHaveLength(0)
  })

  test('the body is cut at 256 KB and not parsed', async () => {
    const r = await probeFetch({ method: 'GET', url: `${base}/big` })
    expect(r.truncated).toBe(true)
    expect(r.json).toBeUndefined()
    expect(r.text.length).toBeLessThanOrEqual(2048)
    expect(MAX_BODY_BYTES).toBe(256 * 1024)
  })

  test('a slow answer times out as `timeout`', async () => {
    const err = await probeFetch({ method: 'GET', url: `${base}/slow` }, { timeoutMs: 200 }).catch(e => e)
    expect(err).toBeInstanceOf(ProbeTransportError)
    expect((err as ProbeTransportError).kind).toBe('timeout')
  })

  test('a refused connection is `network`, and the message carries no URL', async () => {
    const closed = http.createServer()
    const url = await listen(closed)
    closed.close()
    const err = await probeFetch({ method: 'GET', url: `${url}/path?key=SECRET-IN-URL` }).catch(e => e)
    expect(err).toBeInstanceOf(ProbeTransportError)
    expect((err as ProbeTransportError).kind).toBe('network')
    expect((err as ProbeTransportError).message).not.toContain('SECRET-IN-URL')
  })

  test('a key with a CR/LF is never put in a header: invalid_key, flagged as a key-format problem, no request made', async () => {
    targetHits = []
    for (const bad of ['abc\r', 'abc\r\n', 'ab\ncd', '\tabc']) {
      const err = await probeFetch({ method: 'GET', url: `${base}/json`, headers: { 'x-apikey': bad } }).catch(e => e)
      expect(err).toBeInstanceOf(ProbeTransportError)
      expect((err as ProbeTransportError).kind).toBe('invalid_key')
      expect((err as ProbeTransportError).keyFormat).toBe(true)
    }
    expect(targetHits).toHaveLength(0)
  })
})

describe('scrub', () => {
  test('removes the raw, trimmed and URL-encoded forms of every secret', () => {
    const key = 'ab+cd/ef==12'
    const text = `raw ${key} enc ${encodeURIComponent(key)} other`
    expect(scrub(text, [key])).toBe('raw *** enc *** other')
    expect(scrub('x TOKEN y', [' TOKEN\r'])).toBe('x *** y')
  })

  test('ignores empty and very short secrets', () => {
    expect(scrub('a b c', ['', 'b'])).toBe('a b c')
  })

  test('hasControlChars', () => {
    expect(hasControlChars('abc')).toBe(false)
    expect(hasControlChars('abc\r')).toBe(true)
    expect(hasControlChars('a\u007fb')).toBe(true)
  })
})
