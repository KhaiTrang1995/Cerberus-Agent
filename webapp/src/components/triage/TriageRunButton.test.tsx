/**
 * The one triage button: its label, in all three places it appears.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/components/triage/TriageRunButton.test.tsx
 *
 * This component exists because triage used to be three buttons with three
 * names and three looks. Two ways that comes back, both pinned here:
 *
 *  - the LABEL was only decided from the preflight response, which is fetched
 *    on CLICK. So a project triaged last week still read "Start Triage" until
 *    you opened the dialog once, and reverted on every reload.
 *  - the COLOUR came from a class each call site passed, so the Priority
 *    Board's button was a plain secondary control and CypherFix's was the
 *    accent one. The component owns it now; no call site may re-skin it.
 */

import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const alertSpies = vi.hoisted(() => ({ confirm: vi.fn(), alertError: vi.fn() }))
const gateSpies = vi.hoisted(() => ({ ensureFeatureModel: vi.fn() }))

vi.mock('@/components/ui', () => ({
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => gateSpies,
}))

import { TriageRunButton, buildDialog, reviewsKeptLine, type TriagePreflight } from './TriageRunButton'
import { TriageRunBanner } from './TriageRunBanner'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the label says what pressing it will do', () => {
  test('a project that has never been triaged offers to start', () => {
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} />)
    expect(screen.getByRole('button')).toHaveTextContent('Start Triage')
  })

  test('a project that has been triaged offers to re-triage, before any click', () => {
    // THE BUG: this used to need a click first, because the only source of the
    // answer was the preflight fetch inside the click handler.
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} hasPreviousRun />)
    expect(screen.getByRole('button')).toHaveTextContent('Re-triage')
  })

  test('a run in flight outranks both', () => {
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} hasPreviousRun running />)
    expect(screen.getByRole('button')).toHaveTextContent('Triage running...')
    expect(screen.getByRole('button')).toBeDisabled()
  })

  test('it is disabled with no project, so it cannot be pressed into a 400', () => {
    render(<TriageRunButton projectId={null} onConfirm={vi.fn()} />)
    expect(screen.getByRole('button')).toBeDisabled()
  })
})

describe('the component owns its appearance', () => {
  test('it always carries its own class, whatever the caller passes', () => {
    const { container } = render(
      <TriageRunButton projectId="p1" onConfirm={vi.fn()} className="layout-only" />)
    const button = container.querySelector('button')!
    // vitest.config maps CSS modules to non-scoped names, so this is the
    // component's own `.button` rule, not a caller's skin.
    expect(button.className).toContain('button')
    expect(button.className).toContain('layout-only')
  })
})

const PREFLIGHT: TriagePreflight = {
  projectName: 'Lab',
  model: 'claude-haiku-4-5',
  hasModelKey: true,
  inScope: 12,
  newSinceLastRun: 0,
  openFindings: 12,
  reviewBudget: 150,
  estimatedAiCalls: 1,
  estimatedReviewed: 12,
  pendingRemediations: 0,
  inProgressRemediations: 0,
  lastRun: null,
  liveRun: null,
  blockedReason: null,
  defaultRepo: '',
}

function answer(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/**
 * A review budget above 0 needs the owner's Triage review model. The
 * preflight answers model_required without one; the button must ask for the
 * model and preflight AGAIN, so the dialog names the model that will review.
 */
describe('the Triage review model', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    alertSpies.confirm.mockReset().mockResolvedValue(true)
    alertSpies.alertError.mockReset().mockResolvedValue(undefined)
    gateSpies.ensureFeatureModel.mockReset()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  test('model_required opens the gate, then the preflight runs again and the dialog follows', async () => {
    fetchMock
      .mockResolvedValueOnce(answer(409, { error: 'x', code: 'model_required', featureId: 'triage' }))
      .mockResolvedValueOnce(answer(200, PREFLIGHT))
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-haiku-4-5')
    const onConfirm = vi.fn()
    render(<TriageRunButton projectId="p1" onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button'))

    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1))
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('triage', { force: true })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    for (const [url] of fetchMock.mock.calls) expect(url).toBe('/api/triage/preflight?projectId=p1')
    expect(gateSpies.ensureFeatureModel.mock.invocationCallOrder[0])
      .toBeLessThan(fetchMock.mock.invocationCallOrder[1])
    expect(alertSpies.confirm).toHaveBeenCalledTimes(1)
    expect(alertSpies.alertError).not.toHaveBeenCalled()
  })

  test('cancelling the gate aborts: no second preflight, no dialog, no run, no error', async () => {
    fetchMock.mockResolvedValueOnce(answer(409, { error: 'x', code: 'model_required', featureId: 'triage' }))
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    const onConfirm = vi.fn()
    render(<TriageRunButton projectId="p1" onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button'))

    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByRole('button')).toBeEnabled())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(alertSpies.confirm).not.toHaveBeenCalled()
    expect(alertSpies.alertError).not.toHaveBeenCalled()
    expect(onConfirm).not.toHaveBeenCalled()
  })

  test('a preflight that needs no model never opens the gate', async () => {
    fetchMock.mockResolvedValueOnce(answer(200, { ...PREFLIGHT, model: '', hasModelKey: false, reviewBudget: 0 }))
    const onConfirm = vi.fn()
    render(<TriageRunButton projectId="p1" onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(onConfirm).toHaveBeenCalled())
    expect(gateSpies.ensureFeatureModel).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('still model_required after a pick is shown as an error, not a loop', async () => {
    fetchMock.mockResolvedValue(answer(409, { error: 'x', code: 'model_required', featureId: 'triage' }))
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-haiku-4-5')
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} />)
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith('Choose a model for this feature first', 'Triage'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledTimes(1)
  })

  test('the dialog names the model from the preflight', () => {
    render(buildDialog(PREFLIGHT))
    expect(screen.getByText(/claude-haiku-4-5 receives/)).toBeInTheDocument()
  })

  test('with a review budget of 0 the dialog says the review is off, not that a key is missing', () => {
    render(buildDialog({ ...PREFLIGHT, model: '', hasModelKey: false, reviewBudget: 0 }))
    expect(screen.getByText(/Off for this project/)).toBeInTheDocument()
    expect(screen.queryByText(/No AI model key is configured/)).toBeNull()
  })
})

/**
 * The dialog carries the project's real review budget (U10: it always said
 * 150), and says what an earlier review is worth: a review whose evidence has
 * not changed is kept, including one an external agent wrote.
 */
describe('what the run keeps', () => {
  test('the real budget, and the reviews still valid, with the external ones named', () => {
    render(buildDialog({ ...PREFLIGHT, reviewBudget: 1000, reviewsKept: 5, externalReviews: 2 }))
    expect(screen.getByText(/Up to 1000 findings are reviewed/)).toBeInTheDocument()
    expect(screen.getByText('5 reviews still valid will be kept, 2 of them by an external agent.'))
      .toBeInTheDocument()
  })

  test('one kept review, none external, reads as a sentence', () => {
    expect(reviewsKeptLine({ reviewsKept: 1, externalReviews: 0 })).toBe('1 review still valid will be kept.')
  })

  test('nothing kept says nothing', () => {
    render(buildDialog({ ...PREFLIGHT, reviewsKept: 0, externalReviews: 0 }))
    expect(screen.queryByText(/still valid will be kept/)).toBeNull()
  })
})

describe('a run started over MCP says so', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    alertSpies.confirm.mockReset().mockResolvedValue(true)
    alertSpies.alertError.mockReset().mockResolvedValue(undefined)
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  const MCP_RUN = {
    id: 'run-9', status: 'running', startedAt: '2026-09-29T10:00:00Z', trigger: 'mcp',
    phase: 'reviewing', progress: 50, tokenPrefix: 'rdm_ab12',
  }

  test('pressing Run during it names the token that started it', async () => {
    fetchMock.mockResolvedValueOnce(answer(200, {
      ...PREFLIGHT, liveRun: MCP_RUN,
      blockedReason: 'A triage run is already in progress for this project.',
    }))
    const onConfirm = vi.fn()
    render(<TriageRunButton projectId="p1" onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith(
      'A triage run is already in progress for this project. Started over MCP · rdm_ab12.',
      'Triage cannot start yet'))
    expect(onConfirm).not.toHaveBeenCalled()
  })

  test('the live-run banner reads the origin from the preflight', async () => {
    fetchMock.mockResolvedValue(answer(200, { ...PREFLIGHT, liveRun: MCP_RUN }))
    render(<TriageRunBanner projectId="p1" label="Triage running" phase="reviewing" onStop={vi.fn()} />)
    expect(await screen.findByText('Started over MCP · rdm_ab12')).toBeInTheDocument()
    expect(screen.getByText(/Reviewing the evidence/)).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/triage/preflight?projectId=p1')
    expect(screen.getByRole('button', { name: 'Stop' })).toBeEnabled()
  })

  test('a run started in the app names no origin', async () => {
    fetchMock.mockResolvedValue(answer(200, { ...PREFLIGHT, liveRun: { ...MCP_RUN, trigger: 'app', tokenPrefix: null } }))
    render(<TriageRunBanner projectId="p1" label="Triage running" phase="scoring" />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(screen.queryByText(/Started over MCP/)).toBeNull()
  })

  test('Stop is disabled while the run publishes, and a refusal is shown', async () => {
    fetchMock.mockResolvedValue(answer(200, { ...PREFLIGHT, liveRun: null }))
    render(
      <TriageRunBanner
        projectId="p1" label="Triage running" phase="publishing" onStop={vi.fn()}
        notice="The run is publishing and will finish in moments."
      />)
    const stop = screen.getByRole('button', { name: 'Stop' })
    expect(stop).toBeDisabled()
    expect(stop.getAttribute('title')).toContain('publishing')
    expect(screen.getByText('The run is publishing and will finish in moments.')).toBeInTheDocument()
  })
})
