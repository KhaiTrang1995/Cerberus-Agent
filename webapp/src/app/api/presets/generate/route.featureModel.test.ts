/**
 * The preset generator runs on the user's saved "Recon preset generator" model
 * (Models by feature), never on a model named in the request body, and a
 * model it cannot use opens the model picker instead of a dead-end error.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProviders = vi.fn()
const mockSettings = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: { findMany: (...a: unknown[]) => mockProviders(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
  },
}))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'alice' }) }))

import { POST } from './route'

const ANTHROPIC = { providerType: 'anthropic', apiKey: 'sk-ant-alice', timeout: 30, maxTokens: 4096, temperature: 0.2 }
const fetchMock = vi.fn()

function generate(body: Record<string, unknown>) {
  return POST(new NextRequest('http://localhost/api/presets/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }))
}

function saved(model: string | null) {
  mockSettings.mockResolvedValue(model === null ? null : { featureModels: { preset_generator: model } })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProviders.mockResolvedValue([ANTHROPIC])
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockResolvedValue(new Response(JSON.stringify({
    content: [{ type: 'text', text: '{"naabuEnabled": true}' }],
  }), { status: 200 }))
})
afterEach(() => vi.unstubAllGlobals())

describe('the model is the saved one', () => {
  test('no saved model is 409 model_required and calls no provider', async () => {
    saved(null)
    const res = await generate({ model: 'claude-opus-4-6', prompt: 'stealthy' })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('model_required')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('a model in the body is ignored', async () => {
    saved('claude-haiku-9')
    await generate({ model: 'claude-opus-4-6', prompt: 'stealthy' })
    const sent = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string)
    expect(sent.model).toBe('claude-haiku-9')
  })

  test('the settings read is the session user\'s', async () => {
    saved('claude-haiku-9')
    await generate({ prompt: 'stealthy' })
    expect(mockSettings.mock.calls[0][0]).toMatchObject({ where: { userId: 'alice' } })
  })
})

describe('a model it cannot use opens the picker', () => {
  test('a deleted custom provider is model_unavailable', async () => {
    saved('custom/gone')
    const res = await generate({ prompt: 'stealthy' })
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ code: 'model_unavailable', model: 'custom/gone' })
  })

  test('a missing built-in provider is model_unavailable', async () => {
    saved('gpt-5')
    const res = await generate({ prompt: 'stealthy' })
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('model_unavailable')
  })

  test('a refused key is model_unavailable and never echoes the provider text', async () => {
    saved('claude-haiku-9')
    fetchMock.mockResolvedValue(new Response('invalid x-api-key sk-ant-LEAKED', { status: 401 }))
    const res = await generate({ prompt: 'stealthy' })
    const text = await res.text()
    expect(res.status).toBe(503)
    expect(JSON.parse(text).code).toBe('model_unavailable')
    expect(text).not.toContain('LEAKED')
  })

  test('a transient provider error keeps the model and hides the provider text', async () => {
    saved('claude-haiku-9')
    fetchMock.mockResolvedValue(new Response('overloaded sk-ant-LEAKED', { status: 529 }))
    const res = await generate({ prompt: 'stealthy' })
    const text = await res.text()
    expect(res.status).toBe(502)
    expect(JSON.parse(text).code).toBeUndefined()
    expect(text).not.toContain('LEAKED')
  })
})

describe('a provider refusal in the log', () => {
  test('carries its status and error type, never the body (review: a 401 body can quote the key)', async () => {
    saved('claude-haiku-9')
    const leak = 'sk-ant-alice-FRAGMENT-9f3a'
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      type: 'error', error: { type: 'authentication_error', message: `invalid x-api-key: ${leak}` },
    }), { status: 401 }))
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate({ prompt: 'stealthy' })
    expect(await res.json()).toMatchObject({ code: 'model_unavailable' })
    const lines = logged.mock.calls.map(args => args.map(String).join(' '))
    expect(lines.join('\n')).not.toContain(leak)
    expect(lines).toContain('Preset generation failed: Anthropic API returned 401: authentication_error')
    logged.mockRestore()
  })

  test('a body that is not JSON logs the status alone', async () => {
    saved('claude-haiku-9')
    fetchMock.mockResolvedValue(new Response('<html>502 Bad Gateway sk-ant-alice</html>', { status: 502 }))
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate({ prompt: 'stealthy' })
    expect(res.status).toBe(502)
    expect(logged.mock.calls.map(args => args.map(String).join(' ')))
      .toContain('Preset generation failed: Anthropic API returned 502: no error code')
    logged.mockRestore()
  })
})
