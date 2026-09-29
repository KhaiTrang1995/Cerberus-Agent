/**
 * The run progress panel: the phases the run really reports, and the stopped
 * state.
 *
 * Run: npx vitest run src/app/graph/components/CypherFixTab/TriageProgress/TriageProgress.test.tsx
 *
 * U5: the run reports six phases (authorizing, scoring, grouping, reviewing,
 * writing_remediations, publishing) and none of them had a label, so the panel
 * printed raw ids. A stopped run had no state of its own, so the panel had no
 * Close button for it.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { TriageProgress, PHASE_LABELS } from './TriageProgress'
import { TRIAGE_PHASES } from '@/lib/cypherfix-types'

afterEach(cleanup)

function panel(props: Partial<Parameters<typeof TriageProgress>[0]> = {}) {
  const onClose = vi.fn()
  const onStop = vi.fn()
  render(
    <TriageProgress
      isVisible phase="reviewing" progress={50} findings={[]} thinking="" error={null}
      status="running" title="Priority Board" onClose={onClose} onStop={onStop}
      {...props}
    />,
  )
  return { onClose, onStop }
}

describe('TriageProgress', () => {
  test('every phase the run reports has a human label, in run order', () => {
    expect(TRIAGE_PHASES).toEqual([
      'authorizing', 'scoring', 'grouping', 'reviewing', 'writing_remediations', 'publishing',
    ])
    for (const phase of TRIAGE_PHASES) {
      expect(PHASE_LABELS[phase]).toBeTruthy()
      expect(PHASE_LABELS[phase]).not.toContain('_')
    }
  })

  test('the current phase is labelled and marked among the six', () => {
    panel({ phase: 'writing_remediations' })
    const steps = screen.getByRole('list', { name: 'Run phases' })
    expect(steps.querySelectorAll('li')).toHaveLength(6)
    const current = steps.querySelector('[aria-current="step"]')
    expect(current).toHaveTextContent('Writing fix items')
    expect(screen.queryByText('writing_remediations')).toBeNull()
  })

  test('Stop is refused in the UI while the run publishes', () => {
    panel({ phase: 'publishing', notice: 'The run is publishing and will finish in moments.' })
    expect(screen.getByRole('button', { name: 'Stop' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('will finish in moments')
  })

  test('a running panel can be hidden without stopping the run', () => {
    const { onClose, onStop } = panel()
    fireEvent.click(screen.getByRole('button', { name: 'Hide' }))
    expect(onClose).toHaveBeenCalled()
    expect(onStop).not.toHaveBeenCalled()
  })

  test('a stopped run says so and can be closed', () => {
    const { onClose } = panel({ status: 'stopped' })
    expect(screen.getByText('Priority Board stopped')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
    expect(screen.getByText(/nothing from this run reached the board/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })
})
