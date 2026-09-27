/**
 * CircleCI (catalogue B7): `GET circleci.com/api/v2/me` with the Circle-Token
 * header. An invalid token is a 401 with a PLAIN-TEXT body ("Invalid token
 * provided."), a missing one a 401 JSON message: the JSON is sniffed, never
 * assumed. API v2 accepts personal tokens only, so a 401 row names that.
 */
import { str } from '../../parse'
import { body, errorResult, messageOf, shapeError, statusError, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'

export function request(token: string): ProbeRequest {
  return { method: 'GET', url: 'https://circleci.com/api/v2/me', headers: { 'Circle-Token': token } }
}

export function parse(res: ProbeResponse, token: string): ProbeResult {
  if (res.status === 401) {
    // CCIPRJ_ is the prefix of CircleCI project tokens; older project tokens have none.
    const hint = token.startsWith('CCIPRJ_')
      ? 'This is a project token, which API v2 does not accept: use a personal API token'
      : 'A project token is not accepted here: use a personal API token'
    const said = messageOf(res) || 'CircleCI rejected the token'
    return errorResult('invalid_key', `${said.replace(/\.$/, '')}. ${hint}`, { httpStatus: 401 })
  }
  if (res.status !== 200) return statusError(res)

  const b = body(res)
  const login = str(b.login)
  if (!login && !str(b.id)) return shapeError(res)
  return validResult({ account: { label: login } })
}

export const circleciProbe: ProbeDef = {
  id: 'circleci',
  service: 'circleci',
  label: 'CircleCI',
  group: 'sources',
  field: 'trufflehogCircleciToken',
  kind: 'validity',
  costNote: 'Free: reading the current user costs nothing',
  docsUrl: 'https://circleci.com/docs/api/v2/index.html#operation/getCurrentUser',
  dashboardUrl: 'https://app.circleci.com/settings/user/tokens',
  verifiedOn: null,
  endpoint: 'GET circleci.com/api/v2/me',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.key),
}
