/**
 * Starting CodeFix asks for the user's CodeFix model first.
 *
 * CodeFix runs on the user's own model; without one the agent refuses the run
 * after the socket is up. So the gate runs BEFORE startFix, a cancelled gate
 * starts nothing, and an agent that still answers model_required (the model
 * was cleared elsewhere after the check) offers the picker again.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const gateSpies = vi.hoisted(() => ({ ensureFeatureModel: vi.fn() }))
const codefix = vi.hoisted(() => ({
  state: {} as Record<string, unknown>,
  startFix: vi.fn(),
}))

vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => gateSpies,
}))
vi.mock('@/hooks/useCypherFixCodeFixWS', () => ({
  useCypherFixCodeFixWS: () => codefix.state,
}))
vi.mock('./ActivityLog', () => ({ ActivityLog: () => null }))

import { DiffViewer } from './DiffViewer'
import type { Remediation } from '@/lib/cypherfix-types'

const REMEDIATION = { id: 'rem-1', title: 'Upgrade openssl' } as Remediation

function renderViewer() {
  return render(
    <DiffViewer remediation={REMEDIATION} projectId="p1" userId="u1" onBack={vi.fn()} onRefresh={vi.fn()} />,
  )
}

beforeEach(() => {
  gateSpies.ensureFeatureModel.mockReset()
  codefix.startFix.mockReset()
  codefix.state = {
    status: 'connected',
    diffBlocks: [],
    activityLog: [],
    error: null,
    errorCode: null,
    startFix: codefix.startFix,
    sendBlockDecision: vi.fn(),
    stopFix: vi.fn(),
  }
})

afterEach(cleanup)

describe('Start CodeFix', () => {
  test('the gate runs before startFix', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-opus-4-6')
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Start CodeFix' }))
    await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix')
    expect(gateSpies.ensureFeatureModel.mock.invocationCallOrder[0])
      .toBeLessThan(codefix.startFix.mock.invocationCallOrder[0])
  })

  test('cancelling the gate starts nothing', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Start CodeFix' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalled())
    await Promise.resolve()
    expect(codefix.startFix).not.toHaveBeenCalled()
  })

  test('Restart after a run goes through the gate too', async () => {
    codefix.state = { ...codefix.state, activityLog: [{ id: 1, type: 'complete', completionStatus: 'completed' }] }
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Restart CodeFix' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix'))
    expect(codefix.startFix).not.toHaveBeenCalled()
  })
})

describe('the agent answers model_required', () => {
  beforeEach(() => {
    codefix.state = {
      ...codefix.state,
      status: 'error',
      error: 'No CodeFix model is set',
      errorCode: 'model_required',
      activityLog: [{ id: 1, type: 'error', message: 'No CodeFix model is set' }],
    }
  })

  test('it offers the picker, forced open, then starts again', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-opus-4-6')
    renderViewer()
    expect(screen.getByText(/Choose a model for this feature first/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Choose a model and start' }))
    await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix', { force: true })
  })

  test('cancelling that picker starts nothing', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Choose a model and start' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalled())
    await Promise.resolve()
    expect(codefix.startFix).not.toHaveBeenCalled()
  })

  test('any other agent error does not offer it', () => {
    codefix.state = { ...codefix.state, errorCode: null, error: 'boom' }
    renderViewer()
    expect(screen.queryByRole('button', { name: 'Choose a model and start' })).toBeNull()
  })
})
