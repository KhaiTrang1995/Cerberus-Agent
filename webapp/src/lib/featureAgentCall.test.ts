/**
 * `callFeatureAgent`: every way an agent call for a "Models by feature" feature
 * can fail maps to one code, and the version marker tells an outdated agent
 * apart from FastAPI's own pre-handler answers.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockAgentFetch = vi.fn()

vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {
    cause_: unknown
    constructor(cause: unknown) {
      super('agent unreachable')
      this.cause_ = cause
    }
  }
  return { agentFetch: (...a: unknown[]) => mockAgentFetch(...a), AgentUnreachableError }
})
vi.mock('@/lib/prisma', () => ({ default: {} }))

import { callFeatureAgent } from './featureAgentCall'
import { AgentUnreachableError } from '@/lib/agentFetch'

const CALL = { featureId: 'roe_parse' as const, path: '/roe/parse', model: 'gpt-5', body: { x: 1 }, timeoutMs: 1000 }

function answer(status: number, body: unknown) {
  mockAgentFetch.mockResolvedValue(new Response(JSON.stringify(body), { status }))
}

async function codeOf(result: Awaited<ReturnType<typeof callFeatureAgent>>) {
  if (result.ok) throw new Error('expected a failure')
  return { status: result.response.status, body: await result.response.json() }
}

beforeEach(() => vi.clearAllMocks())

describe('success', () => {
  test('a 2xx carrying the sent model is ok', async () => {
    answer(200, { command: 'ls', model_used: 'gpt-5' })
    const res = await callFeatureAgent(CALL)
    expect(res.ok).toBe(true)
    expect(mockAgentFetch.mock.calls[0][0]).toBe('/roe/parse')
    expect(mockAgentFetch.mock.calls[0][2]).toEqual({ timeoutMs: 1000 })
    expect(JSON.parse(mockAgentFetch.mock.calls[0][1].body)).toEqual({ x: 1 })
  })
})

describe('the version marker', () => {
  test('a 2xx without model_used is agent_outdated', async () => {
    answer(200, { command: 'ls' })
    expect((await codeOf(await callFeatureAgent(CALL)))).toMatchObject({ status: 502, body: { code: 'agent_outdated' } })
  })

  test('a 2xx with another model is agent_outdated', async () => {
    answer(200, { command: 'ls', model_used: 'claude-opus-4-6' })
    expect((await codeOf(await callFeatureAgent(CALL))).body.code).toBe('agent_outdated')
  })

  test('an old agent\'s uncoded 503 is agent_outdated, not a model problem', async () => {
    answer(503, { error: 'LLM not available for model gpt-5' })
    expect((await codeOf(await callFeatureAgent(CALL))).body.code).toBe('agent_outdated')
  })

  test('a crash\'s plain-text 500 is an agent failure, not an outdated agent (review: "rebuild the agent")', async () => {
    mockAgentFetch.mockResolvedValue(new Response('Internal Server Error', {
      status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    }))
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out.status).toBe(502)
    expect(out.body.code).toBeUndefined()
    expect(out.body.error).toBe('The agent failed while handling this request. The details are in the agent log.')
  })

  test('a 401 is a key mismatch, not outdated', async () => {
    answer(401, { detail: 'Unauthorized' })
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out.status).toBe(502)
    expect(out.body.code).toBeUndefined()
    expect(out.body.error).toContain('INTERNAL_API_KEY')
  })

  test('a 429 is a rate limit, not outdated', async () => {
    answer(429, { detail: 'Rate limit exceeded' })
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out.status).toBe(429)
    expect(out.body.code).toBeUndefined()
  })

  test('a FastAPI validation 422 is not outdated', async () => {
    answer(422, { detail: [{ loc: ['body', 'x'], msg: 'bad' }] })
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out.status).toBe(502)
    expect(out.body.code).toBeUndefined()
  })

  test('a 404 is outdated only when the endpoint itself is new', async () => {
    answer(404, { detail: 'Not Found' })
    expect((await codeOf(await callFeatureAgent({ ...CALL, notFoundIsOutdated: true }))).body.code).toBe('agent_outdated')
  })
})

describe('coded answers', () => {
  test('model_unavailable keeps the code and a fixed message', async () => {
    answer(503, { code: 'model_unavailable', error: 'provider said sk-LEAK', model_used: 'gpt-5' })
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out).toMatchObject({ status: 503, body: { code: 'model_unavailable', model: 'gpt-5' } })
    expect(JSON.stringify(out.body)).not.toContain('sk-LEAK')
  })

  test('providers_unreachable passes through', async () => {
    answer(503, { code: 'providers_unreachable', error: 'x', model_used: 'gpt-5' })
    expect((await codeOf(await callFeatureAgent(CALL))).body.code).toBe('providers_unreachable')
  })

  test('a feature\'s own code passes through; a malformed one is dropped', async () => {
    answer(409, { code: 'seed_changed', error: 'changed', model_used: 'gpt-5' })
    expect((await codeOf(await callFeatureAgent(CALL))).body).toEqual({ error: 'changed', code: 'seed_changed' })
    answer(409, { code: 'X<script>', error: 'changed', model_used: 'gpt-5' })
    expect((await codeOf(await callFeatureAgent(CALL))).body.code).toBeUndefined()
  })

  test('acceptStatus returns a non-2xx payload as ok', async () => {
    answer(502, { status: 'model_unreadable', groups: [1], model_used: 'gpt-5' })
    const res = await callFeatureAgent({ ...CALL, acceptStatus: (s, b) => s === 502 && b.status === 'model_unreadable' })
    expect(res.ok).toBe(true)
    if (res.ok) expect(res.status).toBe(502)
  })

  test('a required marker that is missing is agent_outdated', async () => {
    answer(200, { model_used: 'gpt-5' })
    expect((await codeOf(await callFeatureAgent({ ...CALL, marker: 'multi_mute' }))).body.code).toBe('agent_outdated')
    answer(200, { model_used: 'gpt-5', multi_mute: 1 })
    expect((await callFeatureAgent({ ...CALL, marker: 'multi_mute' })).ok).toBe(true)
  })

  test('an uncoded handler error keeps its status and text', async () => {
    answer(502, { error: 'The model call failed. Try again in a moment.', model_used: 'gpt-5' })
    const out = await codeOf(await callFeatureAgent(CALL))
    expect(out).toMatchObject({ status: 502, body: { error: 'The model call failed. Try again in a moment.' } })
    expect(out.body.code).toBeUndefined()
  })
})

describe('transport failures', () => {
  test('a timeout is agent_timeout', async () => {
    const timeout = Object.assign(new Error('t'), { name: 'TimeoutError' })
    mockAgentFetch.mockRejectedValue(new AgentUnreachableError(timeout))
    const res = await callFeatureAgent(CALL)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.code).toBe('agent_timeout')
    expect((await codeOf(res)).status).toBe(504)
  })

  test('anything else is agent_unreachable', async () => {
    mockAgentFetch.mockRejectedValue(new AgentUnreachableError(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })))
    const res = await callFeatureAgent(CALL)
    if (!res.ok) expect(res.code).toBe('agent_unreachable')
    expect((await codeOf(res))).toMatchObject({ status: 503, body: { code: 'agent_unreachable' } })
  })
})
