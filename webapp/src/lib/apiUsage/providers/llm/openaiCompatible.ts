/**
 * OpenAI-compatible providers (catalogue C12). The base URL is text the user
 * typed, so the webapp never fetches it: Ollama, vLLM or LM Studio on
 * host.docker.internal, or any other host, would turn the check into an SSRF
 * probe of the Docker network. Only the public cloud presets offered in the
 * provider form are checked, on each preset's own endpoints; the saved path is
 * never used. Anything else is "not checked": the provider's Test Connection
 * button runs from the agent and covers it.
 */
import { epochToIso, isPlainObject, num, str } from '../../parse'
import { body, errorResult, meter, notCheckedResult, shapeError, usageResult, validResult } from '../../results'
import type { ErrorKind, Meter, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail, listed, withNote } from './common'
import { parseMistral, requestMistral } from './validity'

/**
 * The origins of the https presets in OPENAI_COMPAT_PRESETS
 * (llmProviderPresets.ts). Copied, not imported: that module pulls React icon
 * components into this server code. A test keeps the two lists equal.
 */
export const PRESET_ORIGINS = [
  'https://api.groq.com',
  'https://api.together.xyz',
  'https://api.fireworks.ai',
  'https://api.deepinfra.com',
  'https://api.mistral.ai',
] as const

export type PresetOrigin = typeof PRESET_ORIGINS[number]

export const CUSTOM_ENDPOINT_NOTE = "Use the provider's Test Connection button; the report only calls the public preset hosts (Groq, Together AI, Fireworks AI, Deepinfra, Mistral AI), never a custom base URL"

/**
 * The preset a saved base URL belongs to, or undefined. Exact origin match:
 * https, no credentials, the preset's hostname on the default port. A lookalike
 * host (api.groq.com.evil.test), userinfo, another port or plain http is a
 * custom endpoint.
 */
export function presetOrigin(baseUrl: string): PresetOrigin | undefined {
  let url: URL
  try {
    url = new URL(baseUrl)
  } catch {
    return undefined
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') return undefined
  return PRESET_ORIGINS.find(origin => origin === url.origin)
}

// ---------------------------------------------------------------------------
// Groq, Together AI: a models listing
// ---------------------------------------------------------------------------

export function requestGroq(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.groq.com/openai/v1/models', headers: bearer(key) }
}

/** A missing and a wrong key both get 401 `invalid_api_key`. */
export function parseGroq(res: ProbeResponse): ProbeResult {
  return listed(res) ?? fail(res)
}

export function requestTogether(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.together.xyz/v1/models', headers: bearer(key) }
}

/** A 401 is text/plain ("Invalid API key provided…"); 402 is the monthly spending limit. */
export function parseTogether(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  if (res.status === 402) return fail(res, 'quota_exhausted')
  return fail(res)
}

// ---------------------------------------------------------------------------
// Fireworks AI: a models listing, then the account's suspend state
// ---------------------------------------------------------------------------

const FIREWORKS_ACTIVE = new Set(['UNSUSPENDED', 'SUSPEND_STATE_UNSPECIFIED'])
const FIREWORKS_SUSPENDED = new Map<string, ErrorKind>([
  ['CREDIT_DEPLETED', 'quota_exhausted'],
  ['MONTHLY_SPEND_LIMIT_EXCEEDED', 'quota_exhausted'],
  ['FAILED_PAYMENTS', 'forbidden'],
  ['BLOCKED_BY_ABUSE_RULE', 'forbidden'],
])

export function requestFireworksModels(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.fireworks.ai/inference/v1/models', headers: bearer(key) }
}

export function requestFireworksAccounts(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.fireworks.ai/v1/accounts', headers: bearer(key) }
}

export function parseFireworksModels(res: ProbeResponse): ProbeResult {
  return listed(res) ?? fail(res)
}

/** The account behind a key the models listing already accepted. */
export function parseFireworksAccounts(res: ProbeResponse): ProbeResult {
  // The account API authenticates the same key: a 401 here outranks the listing.
  if (res.status === 401) return fail(res, 'invalid_key')
  const accounts = res.status === 200 ? body(res).accounts : undefined
  if (!Array.isArray(accounts)) {
    return validResult({ notes: [`Fireworks did not report the account state (HTTP ${res.status})`] })
  }
  for (const a of accounts.filter(isPlainObject)) {
    const state = str(a.suspendState)
    if (state && !FIREWORKS_ACTIVE.has(state)) {
      return errorResult(FIREWORKS_SUSPENDED.get(state) ?? 'forbidden', `Fireworks account suspended: ${state}`, {
        httpStatus: 200, providerCode: state,
      })
    }
  }
  return validResult()
}

async function checkFireworks(ctx: ProbeContext): Promise<ProbeResult> {
  const models = parseFireworksModels(await ctx.http(requestFireworksModels(ctx.key)))
  if (models.outcome !== 'valid_no_usage') return models
  return parseFireworksAccounts(await ctx.http(requestFireworksAccounts(ctx.key)))
}

// ---------------------------------------------------------------------------
// Deepinfra: the account checklist (its models listing is public, so it proves nothing)
// ---------------------------------------------------------------------------

export function requestDeepinfra(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.deepinfra.com/v1/me?checklist=true', headers: bearer(key) }
}

export function parseDeepinfra(res: ProbeResponse): ProbeResult {
  if (res.status === 402) return fail(res, 'quota_exhausted')
  // 401 {"detail":"User is not authorized to access this resource"}
  if (res.status !== 200) return fail(res)
  if (!isPlainObject(res.json)) return shapeError(res)
  // Only the checklist is read: the rest of /v1/me is the user's profile (email included).
  const c = body(res).checklist
  if (!isPlainObject(c)) return validResult({ notes: ['Deepinfra did not report the balance'] })

  if (c.suspended === true) {
    const reason = str(c.suspend_reason)
    return errorResult(
      reason && /balance|credit|fund/i.test(reason) ? 'quota_exhausted' : 'forbidden',
      reason ? `Deepinfra account suspended: ${reason}` : 'Deepinfra account suspended',
      { httpStatus: 200 },
    )
  }

  const meters: Meter[] = []
  const stripe = num(c.stripe_balance)
  if (stripe != null) {
    // A Stripe customer balance: negative is credit, positive is owed. An
    // account without credit can still be billed for usage afterwards, so an
    // empty balance is not "exhausted": the meter only leads the row when it
    // holds credit (and `suspended` is the signal that calls are refused).
    const credit = Math.max(0, -stripe)
    meters.push(meter({
      id: 'balance', label: 'Account balance', unit: 'usd', window: 'balance',
      remaining: credit, primary: credit > 0,
      note: stripe > 0 ? `${stripe.toFixed(2)} owed` : credit === 0 ? 'no prepaid credit' : undefined,
    }))
  }
  const scoped = Array.isArray(c.scoped_credits) ? c.scoped_credits.filter(isPlainObject) : []
  scoped.forEach((s, i) => {
    const leftCents = num(s.remaining_cents)
    if (s.expired === true || leftCents == null || leftCents <= 0) return
    const grantedCents = num(s.granted_cents)
    const granted = grantedCents != null && grantedCents > 0 ? grantedCents : null
    const expires = epochToIso(s.expires_ts)
    meters.push(meter({
      id: `scoped_credit_${i}`, label: `Credit: ${str(s.name) ?? 'promotional'}`, unit: 'usd', window: 'balance',
      remaining: leftCents / 100,
      limit: granted == null ? null : granted / 100,
      used: granted == null ? null : Math.max(0, granted - leftCents) / 100,
      primary: false, note: expires ? `expires ${expires.slice(0, 10)}` : undefined,
    }))
  })
  return usageResult(meters)
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

interface Preset {
  name: string
  /** The preset's own base URL path, to flag a saved base URL the agent would call differently. */
  basePath: string
  check(ctx: ProbeContext): Promise<ProbeResult>
}

const PRESETS: Record<PresetOrigin, Preset> = {
  'https://api.groq.com': {
    name: 'Groq', basePath: '/openai/v1',
    check: async ctx => parseGroq(await ctx.http(requestGroq(ctx.key))),
  },
  'https://api.together.xyz': {
    name: 'Together AI', basePath: '/v1',
    check: async ctx => parseTogether(await ctx.http(requestTogether(ctx.key))),
  },
  'https://api.fireworks.ai': {
    name: 'Fireworks AI', basePath: '/inference/v1',
    check: checkFireworks,
  },
  'https://api.deepinfra.com': {
    name: 'Deepinfra', basePath: '/v1/openai',
    check: async ctx => parseDeepinfra(await ctx.http(requestDeepinfra(ctx.key))),
  },
  'https://api.mistral.ai': {
    name: 'Mistral AI', basePath: '/v1',
    check: async ctx => parseMistral(await ctx.http(requestMistral(ctx.key))),
  },
}

async function run(ctx: ProbeContext): Promise<ProbeResult> {
  const baseUrl = ctx.companions.baseUrl ?? ''
  const origin = presetOrigin(baseUrl)
  if (!origin) return notCheckedResult('custom_endpoint', CUSTOM_ENDPOINT_NOTE)
  const preset = PRESETS[origin]
  const result = await preset.check(ctx)
  if (new URL(baseUrl).pathname.replace(/\/+$/, '') === preset.basePath) return result
  return withNote(result, `The saved base URL differs from the ${preset.name} preset (${origin}${preset.basePath}); the key was checked on the preset's endpoint`)
}

export const openaiCompatibleProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-openai-compatible',
  service: 'openai_compatible',
  label: 'OpenAI-Compatible',
  companions: [{ field: 'baseUrl', required: false }],
  kind: 'validity',
  costNote: 'Free: lists models or reads the account; a custom base URL is never contacted',
  // The host varies per row: the one contract every preset shares.
  docsUrl: 'https://developers.openai.com/api/reference/resources/models',
  dashboardUrl: 'https://developers.openai.com/api/reference/resources/models',
  endpoint: 'GET <preset host>/…/models (Deepinfra: api.deepinfra.com/v1/me)',
  run,
}
