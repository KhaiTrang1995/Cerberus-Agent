/**
 * The AI preset generator runs on the user's saved "Recon preset generator"
 * model. The route ignores a model in the body, so none is sent; the gate
 * opens before Generate when none is saved; a non-gate code is shown as its
 * message.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { GeneratePresetModal } from './GeneratePresetModal'

const GENERATE_URL = '/api/presets/generate'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal() {
  render(
    <ToastProvider>
      <FeatureModelGateProvider>
        <GeneratePresetModal isOpen onClose={vi.fn()} onSaved={vi.fn()} userId={GATE_USER} />
      </FeatureModelGateProvider>
    </ToastProvider>,
  )
}

function generate(text: string) {
  fireEvent.change(screen.getByRole('textbox'), { target: { value: text } })
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
}

describe('Generate preset', () => {
  test('no saved model: the gate opens first; the request carries the prompt and no model', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { parameters: { naabuEnabled: true } }))
    renderModal()
    generate('fast passive OSINT')
    await pickInGate('Claude Opus 4.6')
    expect(await screen.findByText('Review Generated Preset')).toBeInTheDocument()
    const calls = stub.calls(GENERATE_URL, 'POST')
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0][1]!.body as string)).toEqual({ prompt: 'fast passive OSINT' })
    expect(stub.saved).toEqual({ preset_generator: 'claude-opus-4-6' })
  })

  test('the badge shows the saved model with a Change link', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderModal()
    expect(await screen.findByText('claude-haiku-4-5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the Recon preset generator model' })).toHaveTextContent('Change')
  })

  test('a non-gate code is shown as its message and never opens the gate', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' },
      () => jsonResponse(504, { error: 'x', code: 'agent_timeout', featureId: 'preset_generator' }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText('The model took too long, try again')).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1))
  })
})
