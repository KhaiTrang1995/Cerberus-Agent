/**
 * The first-use model gate (Models by feature §2.5).
 *
 * `ensureFeatureModel` must not open when a model is saved, and must hand back
 * exactly what the user picked (or null on Cancel). `fetchWithFeatureModel`
 * opens only for the two codes a different model can fix and retries once;
 * the agent_* and providers_unreachable codes must never open it, because the
 * user would pick a model and hit the same wall. Without the provider the
 * hook is a no-op, so components rendered on their own keep their behaviour.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useEffect } from 'react'
import { render, screen, cleanup, fireEvent, act, waitFor } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

import {
  FeatureModelGate,
  FeatureModelGateProvider,
  useFeatureModelGate,
  type FeatureModelGateApi,
} from './FeatureModelGate'

const MODELS = {
  Anthropic: [
    { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', context_length: 200000, description: '' },
    { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', context_length: 200000, description: '' },
  ],
  'AWS Bedrock': [
    { id: 'bedrock/anthropic.claude-3-5-sonnet', name: 'Bedrock Claude Sonnet', context_length: null, description: '' },
  ],
}

let saved: Record<string, string>
let modelsAnswer: () => { status: number; body: unknown }
const fetchMock = vi.fn()

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body }
}

beforeEach(() => {
  saved = {}
  modelsAnswer = () => ({ status: 200, body: MODELS })
  fetchMock.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/models') {
      const a = modelsAnswer()
      return json(a.status, a.body)
    }
    if (url === '/api/users/user-1/settings' && (!init || !init.method || init.method === 'GET')) {
      return json(200, { featureModels: { ...saved } })
    }
    if (url === '/api/users/user-1/settings' && init?.method === 'PUT') {
      const patch = JSON.parse(init.body as string).featureModels as Record<string, string>
      for (const [k, v] of Object.entries(patch)) {
        if (v) saved[k] = v
        else delete saved[k]
      }
      return json(200, { featureModels: { ...saved } })
    }
    return json(404, {})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function calls(url: string, method?: string) {
  return fetchMock.mock.calls.filter(([u, init]) =>
    u === url && (!method || ((init as RequestInit | undefined)?.method ?? 'GET') === method))
}

let api: FeatureModelGateApi
function Grab() {
  const gate = useFeatureModelGate()
  useEffect(() => { api = gate }, [gate])
  return null
}

function mountProvider() {
  render(<FeatureModelGateProvider><Grab /></FeatureModelGateProvider>)
}

async function pick(name: string) {
  fireEvent.click(await screen.findByText('Choose a model'))
  fireEvent.click(await screen.findByText(name))
}

function agentAnswer(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('ensureFeatureModel', () => {
  test('resolves the saved model without opening the gate', async () => {
    saved = { triage: 'claude-haiku-4-5' }
    mountProvider()
    let model: string | null = null
    await act(async () => { model = await api.ensureFeatureModel('triage') })
    expect(model).toBe('claude-haiku-4-5')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(calls('/api/models')).toHaveLength(0)
  })

  test('with no saved model it opens, and resolves the pick after Save', async () => {
    mountProvider()
    let result!: Promise<string | null>
    act(() => { result = api.ensureFeatureModel('triage') })
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Choose a model for Triage review' })).toBeInTheDocument()
    expect(screen.getByText("Checks each finding's evidence and words the fix list.")).toBeInTheDocument()

    const save = screen.getByRole('button', { name: 'Save and continue' })
    expect(save).toBeDisabled()
    await pick('Claude Haiku 4.5')
    expect(save).toBeEnabled()
    fireEvent.click(save)

    await expect(result).resolves.toBe('claude-haiku-4-5')
    const [, init] = calls('/api/users/user-1/settings', 'PUT')[0]
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ featureModels: { triage: 'claude-haiku-4-5' } })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  test('Cancel resolves null and saves nothing', async () => {
    mountProvider()
    let result!: Promise<string | null>
    act(() => { result = api.ensureFeatureModel('codefix') })
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await expect(result).resolves.toBeNull()
    expect(calls('/api/users/user-1/settings', 'PUT')).toHaveLength(0)
  })

  test('force opens even with a saved model, and shows the message', async () => {
    saved = { triage: 'claude-haiku-4-5' }
    mountProvider()
    act(() => { void api.ensureFeatureModel('triage', { force: true, message: 'Your model x could not be used' }) })
    expect(await screen.findByRole('alert')).toHaveTextContent('Your model x could not be used')
  })

  test('with no provider: the empty state, Add provider opens Global Settings in a new tab, Check again refetches', async () => {
    modelsAnswer = () => ({ status: 200, body: {} })
    const openSpy = vi.fn()
    vi.stubGlobal('open', openSpy)
    mountProvider()
    act(() => { void api.ensureFeatureModel('multi_mute') })
    expect(await screen.findByText('You have no LLM provider yet')).toBeInTheDocument()
    expect(screen.queryByText('Choose a model')).toBeNull()
    expect(screen.getByRole('button', { name: 'Save and continue' })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: /Add provider/ }))
    expect(openSpy).toHaveBeenCalledWith('/settings?tab=providers', '_blank', 'noopener')

    modelsAnswer = () => ({ status: 200, body: MODELS })
    fireEvent.click(screen.getByRole('button', { name: /Check again/ }))
    expect(await screen.findByText('Choose a model')).toBeInTheDocument()
    expect(calls('/api/models')).toHaveLength(2)
  })

  test('the gate lists only the models the feature may use: the preset generator never lists Bedrock', async () => {
    mountProvider()
    act(() => { void api.ensureFeatureModel('preset_generator') })
    fireEvent.click(await screen.findByText('Choose a model'))
    expect(await screen.findByText('Claude Haiku 4.5')).toBeInTheDocument()
    expect(screen.queryByText('Bedrock Claude Sonnet')).toBeNull()
    expect(screen.queryByText('AWS Bedrock')).toBeNull()
    // No free-text fallback either: a typed id could name a provider the user lacks.
    expect(screen.queryByPlaceholderText(/claude-opus-4-6, gpt-5.2/)).toBeNull()
  })

  test('a user whose only models are excluded is told so, with no picker', async () => {
    modelsAnswer = () => ({ status: 200, body: { 'AWS Bedrock': MODELS['AWS Bedrock'] } })
    mountProvider()
    act(() => { void api.ensureFeatureModel('preset_generator') })
    expect(await screen.findByText('None of your models can run Recon preset generator')).toBeInTheDocument()
    expect(screen.queryByText('Choose a model')).toBeNull()
  })

  test('a save the server refuses keeps the gate open with its error', async () => {
    mountProvider()
    let settled = false
    act(() => { void api.ensureFeatureModel('triage').then(() => { settled = true }) })
    await pick('Claude Opus 4.6')
    fetchMock.mockImplementationOnce(async () => json(400, { error: 'Unknown feature: triage' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }))
    expect(await screen.findByText('Unknown feature: triage')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(settled).toBe(false)
  })
})

describe('a gate replaced while it is saving', () => {
  test('its late save never answers the newer gate (review: a stale save settled the gate on screen)', async () => {
    mountProvider()
    let first!: Promise<string | null>
    act(() => { first = api.ensureFeatureModel('roe_parse') })
    await pick('Claude Opus 4.6')

    let release!: () => void
    const held = new Promise<void>(r => { release = r })
    const serve = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'PUT') await held
      return serve(url, init)
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }))

    let second!: Promise<string | null>
    let secondSettled = false
    act(() => {
      second = api.ensureFeatureModel('report_narratives')
      void second.then(() => { secondSettled = true })
    })
    await expect(first).resolves.toBeNull()
    expect(await screen.findByRole('heading', { name: 'Choose a model for Report narratives' })).toBeInTheDocument()

    await act(async () => { release() })
    await waitFor(() => expect(saved.roe_parse).toBe('claude-opus-4-6'))
    await act(async () => { await new Promise(r => setTimeout(r, 0)) })

    expect(secondSettled).toBe(false)
    expect(screen.getByRole('heading', { name: 'Choose a model for Report narratives' })).toBeInTheDocument()
    expect(saved.report_narratives).toBeUndefined()
  })
})

describe('fetchWithFeatureModel', () => {
  test('model_required: opens the gate and, after a pick, runs the request exactly once more', async () => {
    mountProvider()
    const doFetch = vi.fn()
      .mockResolvedValueOnce(agentAnswer(409, { error: 'x', code: 'model_required', featureId: 'report_narratives' }))
      .mockResolvedValueOnce(agentAnswer(200, { ok: true }))
    let result!: Promise<Response>
    act(() => { result = api.fetchWithFeatureModel('report_narratives', doFetch) })
    await pick('Claude Opus 4.6')
    fireEvent.click(screen.getByRole('button', { name: 'Save and continue' }))
    const res = await result
    expect(res.status).toBe(200)
    expect(doFetch).toHaveBeenCalledTimes(2)
    expect(saved).toEqual({ report_narratives: 'claude-opus-4-6' })
  })

  test('model_unavailable: opens with the fixed message naming the model; Cancel returns the original answer', async () => {
    saved = { roe_parse: 'claude-opus-4-6' }
    mountProvider()
    const doFetch = vi.fn().mockResolvedValue(
      agentAnswer(503, { error: 'x', code: 'model_unavailable', featureId: 'roe_parse', model: 'claude-opus-4-6' }))
    let result!: Promise<Response>
    act(() => { result = api.fetchWithFeatureModel('roe_parse', doFetch) })
    expect(await screen.findByRole('alert')).toHaveTextContent('Your model claude-opus-4-6 could not be used')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    const res = await result
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('model_unavailable')
    expect(doFetch).toHaveBeenCalledTimes(1)
  })

  for (const [code, status] of [
    ['agent_unreachable', 503],
    ['agent_timeout', 504],
    ['agent_outdated', 502],
    ['providers_unreachable', 503],
  ] as const) {
    test(`${code} never opens the gate and comes back untouched`, async () => {
      mountProvider()
      const doFetch = vi.fn().mockResolvedValue(agentAnswer(status, { error: 'x', code, featureId: 'triage' }))
      let res!: Response
      await act(async () => { res = await api.fetchWithFeatureModel('triage', doFetch) })
      expect(res.status).toBe(status)
      expect((await res.json()).code).toBe(code)
      expect(doFetch).toHaveBeenCalledTimes(1)
      expect(screen.queryByRole('dialog')).toBeNull()
      expect(calls('/api/models')).toHaveLength(0)
    })
  }

  test('a success or an uncoded error passes straight through', async () => {
    mountProvider()
    for (const answer of [agentAnswer(200, { ok: true }), agentAnswer(500, { error: 'boom' }), new Response('not json', { status: 502 })]) {
      const doFetch = vi.fn().mockResolvedValue(answer)
      let res!: Response
      await act(async () => { res = await api.fetchWithFeatureModel('triage', doFetch) })
      expect(res).toBe(answer)
      expect(doFetch).toHaveBeenCalledTimes(1)
    }
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('without the provider', () => {
  test('the context default is a no-op', async () => {
    render(<Grab />)
    let model: string | null = 'unset'
    await act(async () => { model = await api.ensureFeatureModel('triage') })
    expect(model).toBeNull()
    const answer = agentAnswer(409, { error: 'x', code: 'model_required', featureId: 'triage' })
    const doFetch = vi.fn().mockResolvedValue(answer)
    expect(await api.fetchWithFeatureModel('triage', doFetch)).toBe(answer)
    expect(doFetch).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('inline mode', () => {
  test('renders without a dialog, with the account note and a custom confirm label', async () => {
    const onSaved = vi.fn()
    render(
      <FeatureModelGate inline featureId="multi_mute" userId="user-1" confirmLabel="Save and run" onSaved={onSaved} onCancel={() => {}} />,
    )
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByText('Saved for your account; also in Global Settings → LLM Providers → Models by feature')).toBeInTheDocument()
    await pick('Claude Haiku 4.5')
    fireEvent.click(screen.getByRole('button', { name: 'Save and run' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith('claude-haiku-4-5'))
    expect(saved).toEqual({ multi_mute: 'claude-haiku-4-5' })
  })
})
