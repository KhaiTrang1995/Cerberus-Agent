/**
 * RoE upload and the user's "RoE parsing" model.
 *
 * The route reads the model itself and ignores any the form sends, so the
 * upload sends none. Without a saved model the gate opens BEFORE the upload; a
 * model_required answer (the model went away meanwhile) opens it again and
 * retries once; a cancelled gate uploads nothing; agent failures are shown as
 * their message and never open the gate.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch, type GateFetchStub } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { RoeSection } from './RoeSection'

const PROPOSAL = { changes: [], rejected: [], ignored: [], modelUsed: 'claude-opus-4-6' }
const REVIEW_TITLE = 'Review what this document would change'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderSection(onFileSelected = vi.fn()) {
  const utils = render(
    <FeatureModelGateProvider>
      <RoeSection
        data={{} as never}
        updateField={vi.fn()}
        updateMultipleFields={vi.fn()}
        mode="create"
        onFileSelected={onFileSelected}
      />
    </FeatureModelGateProvider>,
  )
  return { ...utils, onFileSelected }
}

function upload(container: HTMLElement) {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement
  const file = new File(['Scope: example.test only'], 'roe.txt', { type: 'text/plain' })
  fireEvent.change(input, { target: { files: [file] } })
}

function parseCalls(stub: GateFetchStub) {
  return stub.calls('/api/roe/parse', 'POST')
}

describe('RoE upload', () => {
  test('no saved model: the gate opens before the upload, then it parses once', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, PROPOSAL))
    const { container, onFileSelected } = renderSection()
    upload(container)
    await pickInGate('Claude Opus 4.6')

    expect(await screen.findByText(REVIEW_TITLE)).toBeInTheDocument()
    expect(stub.saved).toEqual({ roe_parse: 'claude-opus-4-6' })
    expect(parseCalls(stub)).toHaveLength(1)
    // The route reads the saved model; the form never carries one.
    expect((parseCalls(stub)[0][1]!.body as FormData).has('model')).toBe(false)
    expect(onFileSelected).toHaveBeenCalledTimes(1)
  })

  test('model_required from the route opens the gate and retries exactly once', async () => {
    let n = 0
    const stub = stubGateFetch({ roe_parse: 'claude-haiku-4-5' }, () => (++n === 1
      ? jsonResponse(409, { error: 'x', code: 'model_required', featureId: 'roe_parse' })
      : jsonResponse(200, PROPOSAL)))
    const { container } = renderSection()
    upload(container)
    await pickInGate('Claude Opus 4.6')
    expect(await screen.findByText(REVIEW_TITLE)).toBeInTheDocument()
    expect(parseCalls(stub)).toHaveLength(2)
  })

  test('cancelling the gate uploads nothing', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, PROPOSAL))
    const { container, onFileSelected } = renderSection()
    upload(container)
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(parseCalls(stub)).toHaveLength(0)
    expect(onFileSelected).not.toHaveBeenCalled()
  })

  test('an agent failure is shown as its message and never opens the gate', async () => {
    const stub = stubGateFetch({ roe_parse: 'claude-haiku-4-5' },
      () => jsonResponse(503, { error: 'x', code: 'agent_unreachable', featureId: 'roe_parse' }))
    const { container } = renderSection()
    upload(container)
    expect(await screen.findByText("The agent service isn't running")).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(parseCalls(stub)).toHaveLength(1)
  })

  test('the Model line shows the saved model, and Change opens the gate', async () => {
    stubGateFetch({ roe_parse: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderSection()
    expect(await screen.findByText('claude-haiku-4-5')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Change the RoE parsing model' }))
    await pickInGate('Claude Opus 4.6')
    expect(await screen.findByText('claude-opus-4-6')).toBeInTheDocument()
  })
})
