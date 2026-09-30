/**
 * The command whisperer and the user's "Command whisperer" model.
 *
 * The gate opens before the request when no model is saved; model_required
 * from the route opens it again and retries once; agent failures land in the
 * whisperer's error line as their message and never open the gate.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { SessionTerminal } from './SessionTerminal'

const WHISPER_URL = '/api/agent/command-whisperer'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderTerminal() {
  return render(
    <FeatureModelGateProvider>
      <SessionTerminal sessionId={1} sessionType="shell" agentBusy={false} projectId="p1" onInteract={vi.fn()} />
    </FeatureModelGateProvider>,
  )
}

function whisper(text: string) {
  const box = screen.getByPlaceholderText('Describe what you want to do...')
  fireEvent.change(box, { target: { value: text } })
  fireEvent.keyDown(box, { key: 'Enter' })
}

describe('command whisperer', () => {
  test('no saved model: the gate opens first, then the command fills the terminal input', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { command: 'ls -la', modelUsed: 'claude-haiku-4-5' }))
    renderTerminal()
    whisper('list files')
    await pickInGate('Claude Haiku 4.5')
    await waitFor(() => expect(screen.getByPlaceholderText('Type a command...')).toHaveValue('ls -la'))
    expect(stub.saved).toEqual({ command_whisperer: 'claude-haiku-4-5' })
    const calls = stub.calls(WHISPER_URL, 'POST')
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0][1]!.body as string)).toEqual({ prompt: 'list files', session_type: 'shell', project_id: 'p1' })
  })

  test('model_required from the route opens the gate and retries exactly once', async () => {
    let n = 0
    const stub = stubGateFetch({ command_whisperer: 'claude-opus-4-6' }, () => (++n === 1
      ? jsonResponse(409, { error: 'x', code: 'model_required', featureId: 'command_whisperer' })
      : jsonResponse(200, { command: 'id', modelUsed: 'claude-haiku-4-5' })))
    renderTerminal()
    whisper('who am i')
    await pickInGate('Claude Haiku 4.5')
    await waitFor(() => expect(screen.getByPlaceholderText('Type a command...')).toHaveValue('id'))
    expect(stub.calls(WHISPER_URL, 'POST')).toHaveLength(2)
  })

  test('cancelling the gate sends nothing', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { command: 'ls' }))
    renderTerminal()
    whisper('list files')
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(stub.calls(WHISPER_URL, 'POST')).toHaveLength(0)
  })

  for (const [code, status, message] of [
    ['agent_timeout', 504, 'The model took too long, try again'],
    ['agent_outdated', 502, 'The agent is older than the webapp: rebuild it'],
    ['providers_unreachable', 503, "Couldn't load your LLM providers, try again"],
  ] as const) {
    test(`${code} is shown in the whisperer and never opens the gate`, async () => {
      stubGateFetch({ command_whisperer: 'claude-haiku-4-5' },
        () => jsonResponse(status, { error: 'x', code, featureId: 'command_whisperer' }))
      renderTerminal()
      whisper('list files')
      expect(await screen.findByText(message)).toBeInTheDocument()
      expect(screen.queryByRole('dialog')).toBeNull()
    })
  }

  test('the Model line under the whisperer shows the saved model', async () => {
    stubGateFetch({ command_whisperer: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderTerminal()
    expect(await screen.findByText('claude-haiku-4-5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the Command whisperer model' })).toBeInTheDocument()
  })
})
