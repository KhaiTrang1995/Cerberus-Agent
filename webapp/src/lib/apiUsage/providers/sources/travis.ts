/**
 * Travis CI (catalogue B8): `GET api.travis-ci.com/user` with API v3 headers.
 * The auth scheme is `token`, not Bearer. Travis also refuses a request with
 * no User-Agent; probeFetch sends one on every probe.
 *
 * A missing token is a 403 JSON error, an invalid one a 403 served as
 * text/html whose whole body is "access denied": both are an invalid key. Any
 * real HTML document on a 403 is a page in front of Travis, not its verdict.
 */
import { str } from '../../parse'
import { body, errorResult, isHtml, messageOf, shapeError, statusError, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

export function request(token: string): ProbeRequest {
  return {
    method: 'GET',
    url: 'https://api.travis-ci.com/user',
    headers: { Authorization: `token ${token}`, 'Travis-API-Version': '3' },
  }
}

function authError(res: ProbeResponse): ProbeResult {
  const b = body(res)
  const type = str(b.error_type)
  if (type) {
    const message = str(b.error_message) ?? type
    if (res.status === 401 || type === 'login_required') {
      return errorResult('invalid_key', message, { httpStatus: res.status, providerCode: type })
    }
    return errorResult('forbidden', message, { httpStatus: res.status, providerCode: type })
  }
  if (/^\s*</.test(res.text)) return statusError(res, 'provider_error')
  const text = isHtml(res) ? res.text.trim() : messageOf(res)
  return errorResult('invalid_key', `Travis CI rejected the token (${text || 'access denied'})`, { httpStatus: res.status })
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 401 || res.status === 403) return authError(res)
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  const login = str(b.login)
  if (b['@type'] !== 'user' && !login) return shapeError(res)
  return validResult({ account: { label: login } })
}

export const travisciProbe: ProbeDef = {
  id: 'travisci',
  service: 'travisci',
  label: 'Travis CI',
  group: 'sources',
  field: 'trufflehogTravisciToken',
  kind: 'validity',
  costNote: 'Free: reading the current user costs nothing',
  docsUrl: 'https://developer.travis-ci.com/resource/user',
  dashboardUrl: 'https://app.travis-ci.com/account/preferences',
  verifiedOn: null,
  endpoint: 'GET api.travis-ci.com/user',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
