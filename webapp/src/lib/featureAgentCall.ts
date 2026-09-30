/**
 * Call an agent endpoint that runs one user's "Models by feature" model, and
 * turn every way it can fail into the shared code contract (lib/llmFeatures.ts).
 *
 * The version marker is the subtle part. An agent that predates per-feature
 * models ignores the model it is sent and runs on its old default, which looks
 * like success. The new endpoints echo `model_used` on every answer their
 * handler writes, so a missing or different echo is `agent_outdated`. Answers
 * FastAPI writes before the handler runs never carry it and are NOT outdated:
 * 401 (internal key mismatch), 429 (rate limit) and 422 (request validation).
 *
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import {
  agentCodedError,
  agentFailureCode,
  featureModelErrorResponse,
  modelUsedMismatch,
} from '@/lib/featureModels'
import type { FeatureId } from '@/lib/llmFeatures'

export type FeatureAgentResult =
  | { ok: true; status: number; body: Record<string, unknown> }
  | { ok: false; response: NextResponse; code?: string }

export interface FeatureAgentCall {
  featureId: FeatureId
  path: string
  model: string
  body: Record<string, unknown>
  timeoutMs: number
  /** A 404 means the endpoint does not exist on this agent (a brand-new one). */
  notFoundIsOutdated?: boolean
  /** A non-2xx answer that still carries a usable payload, returned as ok. */
  acceptStatus?: (status: number, body: Record<string, unknown>) => boolean
  /** Extra marker every handler answer must carry, beside `model_used`. */
  marker?: string
}

// A feature's own codes (seed_changed, busy, ...) reach the client as they
// are; anything else the agent sends in `code` is dropped rather than trusted.
const PASSTHROUGH_CODE = /^[a-z_]{1,40}$/

function errorText(body: Record<string, unknown>, fallback: string): string {
  if (typeof body.error === 'string' && body.error) return body.error
  if (typeof body.detail === 'string' && body.detail) return body.detail
  return fallback
}

export async function callFeatureAgent(call: FeatureAgentCall): Promise<FeatureAgentResult> {
  let res: Response
  try {
    res = await agentFetch(call.path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(call.body),
    }, { timeoutMs: call.timeoutMs })
  } catch (err) {
    if (err instanceof AgentUnreachableError) {
      const code = agentFailureCode(err)
      console.warn(`[${call.featureId}] agent call failed (${code}): ${err.message}`)
      return { ok: false, code, response: featureModelErrorResponse(code, call.featureId) }
    }
    throw err
  }

  const parsed = await res.json().catch(() => null)
  const body: Record<string, unknown> =
    parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}

  if (res.status === 401) {
    console.error(`[${call.featureId}] the agent refused the internal key`)
    return {
      ok: false,
      response: NextResponse.json(
        { error: 'The agent refused the webapp\'s internal key. Check INTERNAL_API_KEY on both services.' },
        { status: 502 },
      ),
    }
  }
  // The rate limiter's 429 comes before the handler and carries no marker; a
  // handler's own 429 (Multi mute's `busy`) does, and keeps its code.
  if (res.status === 429 && typeof body.model_used !== 'string') {
    return {
      ok: false,
      response: NextResponse.json({ error: errorText(body, 'Too many requests, try again in a moment') }, { status: 429 }),
    }
  }
  if (res.status === 422 && Array.isArray(body.detail)) {
    console.error(`[${call.featureId}] the agent rejected the request shape:`, body.detail)
    return {
      ok: false,
      response: NextResponse.json({ error: 'The agent rejected the request. Rebuild the agent and the webapp together.' }, { status: 502 }),
    }
  }
  // An exception the handler did not catch reaches us as Starlette's plain-text
  // 500, written after the handler died. No agent, new or old, can mark it, so
  // it says nothing about the version: it is a crash, and the log has it.
  if (res.status >= 500 && parsed === null) {
    console.error(`[${call.featureId}] the agent failed with a bare ${res.status}`)
    return {
      ok: false,
      response: NextResponse.json(
        { error: 'The agent failed while handling this request. The details are in the agent log.' },
        { status: 502 },
      ),
    }
  }
  if (res.status === 404 && call.notFoundIsOutdated) {
    return { ok: false, code: 'agent_outdated', response: featureModelErrorResponse('agent_outdated', call.featureId) }
  }
  if (modelUsedMismatch(body, call.model) || (call.marker && body[call.marker] !== 1)) {
    console.error(`[${call.featureId}] agent answered ${res.status} without model_used=${call.model}: outdated agent`)
    return { ok: false, code: 'agent_outdated', response: featureModelErrorResponse('agent_outdated', call.featureId) }
  }
  const coded = agentCodedError(res.status, body, call.featureId, call.model)
  if (coded) return { ok: false, code: String(body.code), response: coded }
  if (!res.ok && call.acceptStatus?.(res.status, body)) return { ok: true, status: res.status, body }
  if (!res.ok) {
    const code = typeof body.code === 'string' && PASSTHROUGH_CODE.test(body.code) ? body.code : undefined
    return {
      ok: false,
      ...(code ? { code } : {}),
      response: NextResponse.json(
        { error: errorText(body, `The agent answered ${res.status}`), ...(code ? { code } : {}) },
        { status: res.status },
      ),
    }
  }
  return { ok: true, status: res.status, body }
}
