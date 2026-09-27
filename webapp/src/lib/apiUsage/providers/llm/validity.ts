/**
 * The LLM providers a normal key can only prove, not measure (catalogue C4,
 * C5, C7-C10): each probe lists models, which is free, and a 2xx means the key
 * works. Their usage and billing APIs need an admin or management credential,
 * an Alibaba AccessKey or a browser session, and the report never asks for one.
 * Hosts are the ones the agent calls (model_providers.py / llm_setup.py).
 */
import { isPlainObject, str } from '../../parse'
import { errorResult, isHtml, messageOf, validResult } from '../../results'
import type { ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail, listed, providerCode, withNote } from './common'

const MODELS_COST = 'Free: listing models is not billed'

// ---------------------------------------------------------------------------
// C4 GLM / Zhipu
// ---------------------------------------------------------------------------

// The codes Zhipu documents for a 401; the message itself is often Chinese, even on api.z.ai.
const GLM_AUTH_CODES = new Map([
  ['1000', 'Authentication failed'],
  ['1001', 'No Authorization header was received'],
  ['1002', 'Invalid token'],
  ['1003', 'The token has expired'],
])

export function requestGlm(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://open.bigmodel.cn/api/paas/v4/models', headers: bearer(key) }
}

export function parseGlm(res: ProbeResponse): ProbeResult {
  const code = providerCode(res)
  if (res.status === 401) {
    const msg = messageOf(res)
    const label = code ? GLM_AUTH_CODES.get(code) : undefined
    return errorResult('invalid_key', label ? `${label} (${msg || code})` : msg || 'the provider rejected the key', {
      httpStatus: 401, providerCode: code,
    })
  }
  // "1113" (insufficient balance) is documented on inference; on any call it means an empty account.
  if (code === '1113') return fail(res, 'quota_exhausted')
  const ok = listed(res)
  if (ok) return ok
  // A 5xx or an HTML page may come from in front of the gateway, before anything was authenticated.
  if (res.status >= 500 || isHtml(res)) return fail(res)
  // The models route is undocumented, but the gateway authenticates before it
  // routes: any other answer, even a 404, means the key authenticated.
  return validResult({
    notes: [`GLM has no key-check endpoint: its gateway accepted the key, then answered HTTP ${res.status}${code ? ` (${code})` : ''}`],
  })
}

export const glmProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-glm',
  service: 'glm',
  label: 'GLM (Zhipu AI)',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://docs.bigmodel.cn/cn/api/api-code',
  dashboardUrl: 'https://open.bigmodel.cn/usercenter/apikeys',
  endpoint: 'GET open.bigmodel.cn/api/paas/v4/models',
  run: async ctx => parseGlm(await ctx.http(requestGlm(ctx.key))),
}

// ---------------------------------------------------------------------------
// C5 Qwen / DashScope
// ---------------------------------------------------------------------------

const QWEN_REGION_NOTE = 'DashScope keys belong to one region: RedAmon calls the international endpoint (dashscope-intl), which rejects keys from the China (Beijing) region'

export function requestQwen(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models', headers: bearer(key) }
}

export function parseQwen(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  const code = providerCode(res)
  if (res.status === 401) return withNote(fail(res), QWEN_REGION_NOTE)
  // 400: the Alibaba Cloud account has an overdue payment.
  if (code === 'Arrearage') return fail(res, 'quota_exhausted')
  // The free quota is used up and the account is set to "free tier only".
  if (code === 'AllocationQuota.FreeTierOnly') return fail(res, 'quota_exhausted')
  // Every 429 is a throttle: DashScope's `insufficient_quota` means a TPM
  // limit, not an empty account.
  if (res.status === 429) return fail(res, 'rate_limited')
  return fail(res)
}

export const qwenProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-qwen',
  service: 'qwen',
  label: 'Qwen (Alibaba)',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://www.alibabacloud.com/help/en/model-studio/error-code',
  dashboardUrl: 'https://bailian.console.aliyun.com/?apiKey=1#/api-key',
  endpoint: 'GET dashscope-intl.aliyuncs.com/compatible-mode/v1/models',
  run: async ctx => parseQwen(await ctx.http(requestQwen(ctx.key))),
}

// ---------------------------------------------------------------------------
// C7 OpenAI
// ---------------------------------------------------------------------------

// Only billable calls send these, but on any call they mean the account cannot pay.
const OPENAI_QUOTA_CODES = /insufficient_quota|credit_balance_exhausted|spend_limit_exceeded/
const RESTRICTED_NOTE = 'Restricted key: it authenticated, but without Models: Read (api.model.read) it cannot list models'

export function requestOpenai(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.openai.com/v1/models', headers: bearer(key) }
}

export function parseOpenai(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  const msg = messageOf(res)
  // A restricted key without Models: Read authenticated fine; it just may not list models.
  if ((res.status === 401 || res.status === 403) && /insufficient permissions|missing scopes?:/i.test(msg)) {
    return validResult({ notes: [RESTRICTED_NOTE] })
  }
  if (res.status === 429) return fail(res, OPENAI_QUOTA_CODES.test(providerCode(res) ?? '') ? 'quota_exhausted' : 'rate_limited')
  return fail(res)
}

export const openaiProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-openai',
  service: 'openai',
  label: 'OpenAI',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://developers.openai.com/api/docs/guides/error-codes',
  dashboardUrl: 'https://platform.openai.com/usage',
  endpoint: 'GET api.openai.com/v1/models',
  run: async ctx => parseOpenai(await ctx.http(requestOpenai(ctx.key))),
}

// ---------------------------------------------------------------------------
// C8 Anthropic
// ---------------------------------------------------------------------------

export function requestAnthropic(key: string): ProbeRequest {
  return {
    method: 'GET',
    url: 'https://api.anthropic.com/v1/models?limit=1',
    headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' },
  }
}

export function parseAnthropic(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  // "Your credit balance is too low" is a 400 on billable endpoints only; it would mean the same here.
  if (res.status === 400 && /credit balance is too low/i.test(messageOf(res))) return fail(res, 'quota_exhausted')
  // 529 overloaded_error falls in the 5xx default.
  return fail(res)
}

export const anthropicProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-anthropic',
  service: 'anthropic',
  label: 'Anthropic',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://platform.claude.com/docs/en/api/errors',
  dashboardUrl: 'https://console.anthropic.com/settings/billing',
  endpoint: 'GET api.anthropic.com/v1/models',
  run: async ctx => parseAnthropic(await ctx.http(requestAnthropic(ctx.key))),
}

// ---------------------------------------------------------------------------
// C9 Google Gemini
// ---------------------------------------------------------------------------

export function requestGemini(key: string): ProbeRequest {
  // The key goes in the header, never `?key=`: query strings end up in proxy and access logs.
  return {
    method: 'GET',
    url: 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=1',
    headers: { 'x-goog-api-key': key },
  }
}

/** Google's envelope: `{error: {code, message, status, details[]}}`. */
function googleError(res: ProbeResponse): Record<string, unknown> | undefined {
  return isPlainObject(res.json) && isPlainObject(res.json.error) ? res.json.error : undefined
}

/** Google's machine-readable reason: the ErrorInfo `reason` in `details[]`, else the RPC status. */
export function googleReason(res: ProbeResponse): string | undefined {
  const e = googleError(res)
  if (!e) return undefined
  const details = Array.isArray(e.details) ? e.details.filter(isPlainObject) : []
  return str(details.find(d => typeof d.reason === 'string')?.reason) ?? str(e.status)
}

export function parseGemini(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  const reason = googleReason(res)
  const msg = messageOf(res)
  // A bad key is a 400 INVALID_ARGUMENT here, not a 401.
  if (reason === 'API_KEY_INVALID' || /api key not valid/i.test(msg)) return fail(res, 'invalid_key', reason)
  // A key Google found published is disabled for good.
  if (res.status === 403 && /leaked/i.test(msg)) return fail(res, 'invalid_key', reason)
  // 402 RESOURCE_EXHAUSTED "Your Prepay credit balance is depleted."
  if (res.status === 402 || /prepay/i.test(msg)) return fail(res, 'quota_exhausted', reason)
  // Billing not enabled, or a region the free tier does not serve: the key works, the account may not call.
  if (googleError(res)?.status === 'FAILED_PRECONDITION') return fail(res, 'forbidden', reason)
  return fail(res, undefined, reason)
}

export const geminiProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-gemini',
  service: 'gemini',
  label: 'Google Gemini',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://ai.google.dev/gemini-api/docs/generate-content/api-errors',
  dashboardUrl: 'https://aistudio.google.com/app/apikey',
  endpoint: 'GET generativelanguage.googleapis.com/v1beta/models',
  run: async ctx => parseGemini(await ctx.http(requestGemini(ctx.key))),
}

// ---------------------------------------------------------------------------
// C10 Mistral (also the Mistral preset of the OpenAI-compatible probe)
// ---------------------------------------------------------------------------

const CODESTRAL_NOTE = 'A Codestral key only works on codestral.mistral.ai; api.mistral.ai rejects it'

export function requestMistral(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://api.mistral.ai/v1/models', headers: bearer(key) }
}

export function parseMistral(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok) return ok
  // The error bodies vary ({"detail"} or {"object":"error",…}): the status decides.
  if (res.status === 401) return withNote(fail(res), CODESTRAL_NOTE)
  return fail(res)
}

export const mistralProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-mistral',
  service: 'mistral',
  label: 'Mistral AI',
  kind: 'validity',
  costNote: MODELS_COST,
  docsUrl: 'https://docs.mistral.ai/api/',
  dashboardUrl: 'https://admin.mistral.ai/',
  endpoint: 'GET api.mistral.ai/v1/models',
  run: async ctx => parseMistral(await ctx.http(requestMistral(ctx.key))),
}
