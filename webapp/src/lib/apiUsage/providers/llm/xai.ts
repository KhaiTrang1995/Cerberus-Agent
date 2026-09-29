/**
 * xAI: `GET api.x.ai/v1/api-key` (catalogue C6) describes the calling key: its
 * name and whether the key or its team is blocked or disabled. An inference key
 * has no balance endpoint (credits live behind the management API). The body
 * also carries the redacted key and user/team ids: none of them is copied.
 */
import { epochToIso, isoOrNull, str } from '../../parse'
import { body, errorResult, messageOf, shapeError, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail } from './common'

const FLAGS: readonly (readonly [string, string])[] = [
  ['team_blocked', 'the team is blocked'],
  ['api_key_blocked', 'the key is blocked'],
  ['api_key_disabled', 'the key is disabled'],
]

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.x.ai/v1/api-key', headers: bearer(key) }
}

/** `create_time` is documented as a Unix timestamp but served as ISO: accept both. */
export function createdAt(v: unknown): string | null {
  if (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v.trim())) return epochToIso(v)
  return isoOrNull(v)
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status === 200) {
    const b = body(res)
    if (typeof b.api_key_id !== 'string' && !FLAGS.some(([flag]) => typeof b[flag] === 'boolean')) return shapeError(res)
    const account = { label: str(b.name) }
    const flagged = FLAGS.filter(([flag]) => b[flag] === true).map(([, text]) => text)
    if (flagged.length) {
      return errorResult('forbidden', `key blocked/disabled: ${flagged.join('; ')}`, { httpStatus: 200, account })
    }
    const created = createdAt(b.create_time)
    return validResult({ account, notes: created ? [`Key created ${created.slice(0, 10)}`] : undefined })
  }

  const msg = messageOf(res)
  // Documented as a 401, but an unknown key is answered 400 "Incorrect API key
  // provided: xa***…" in practice.
  if (res.status === 400 && /api key/i.test(msg)) return fail(res, 'invalid_key')
  // One 429 for a throttle and for "used all available credits or reached its
  // monthly spending limit".
  if (res.status === 429) return fail(res, /credits|spending limit/i.test(msg) ? 'quota_exhausted' : 'rate_limited')
  return fail(res)
}

export const xaiProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-xai',
  service: 'xai',
  label: 'xAI (Grok)',
  kind: 'validity',
  costNote: 'Free: reading the key information is not billed',
  docsUrl: 'https://docs.x.ai/developers/rest-api-reference/inference/other',
  dashboardUrl: 'https://console.x.ai/',
  endpoint: 'GET api.x.ai/v1/api-key',
  run: async ctx => parse(await ctx.http(request(ctx.key))),
}
