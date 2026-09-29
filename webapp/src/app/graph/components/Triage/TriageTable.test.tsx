/**
 * Component test for the Priority Board's factor line (strategy row 10).
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/Triage/TriageTable.test.tsx
 *
 * One claim: the evidence behind each factor is reachable from the row. The
 * "real" factor now carries what the operator's own Real / False positive
 * clicks taught it, and a number that moved with no visible reason is one
 * nobody can disagree with.
 */

import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const mockDangerConfirm = vi.fn()
const mockAddToast = vi.fn()

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: mockDangerConfirm }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), addToast: mockAddToast }),
  WikiInfoButton: () => null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'u1' }),
}))
vi.mock('@/hooks/useCypherFixTriageWS', () => ({
  useCypherFixTriageWS: () => ({
    status: 'idle', currentPhase: null, progress: null, findings: [],
    error: null, thinking: '', startTriage: vi.fn(), stopTriage: vi.fn(),
    disconnect: vi.fn(),
  }),
}))
vi.mock('@/components/triage/TriageRunButton', () => ({
  TriageRunButton: () => null,
  default: () => null,
}))
vi.mock('../CypherFixTab/TriageProgress/TriageProgress', () => ({
  TriageProgress: () => null,
  PHASE_LABELS: {},
}))

import { TriageTable } from './TriageTable'

const factors = {
  C: { value: 0.34, evidence: 'detected by nuclei; you judged 2 of 10 of these real' },
  L: { value: 0.5, evidence: 'the misconfiguration class prior' },
  I: { value: 0.45, evidence: 'severity medium' },
  R: { value: 0.8, evidence: 'no reachability evidence either way' },
}

const ranked = {
  id: 'f1', label: 'Vulnerability', name: 'Missing header', severity: 'low',
  source: 'nuclei', section: 0, triage_state: 'open',
  triage_status: 'unreviewed', triage_confidence: null, triage_reason: null,
  triage_priority_score: 34.4, triage_tier: 'T3',
  triage_factors: JSON.stringify(factors), triage_signals: [],
  triage_source: null, triage_ai_verdict: null, triage_run_id: 'run-1',
  triaged_at: '2026-09-12T00:00:00Z',
}

function ok(body: unknown) {
  return Promise.resolve({ ok: true, json: () => Promise.resolve(body) })
}

describe('TriageTable factor line', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) =>
      url.includes('/api/triage/muted')
        ? ok({ findings: [] })
        : ok({ findings: [ranked], total: 1 })))
  })
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  test('the hover carries the reason the real factor moved', async () => {
    render(<TriageTable projectId="p1" />)
    const line = await screen.findByText(/real 34%/)
    expect(line.getAttribute('title')).toContain('you judged 2 of 10')
    // Every factor's evidence is there, not just C's.
    expect(line.getAttribute('title')).toContain('reach: no reachability evidence')
  })

  test('a row from an older run with no factors says so instead of inventing them', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string) =>
      url.includes('/api/triage/muted')
        ? ok({ findings: [] })
        : ok({ findings: [{ ...ranked, triage_factors: null }], total: 1 })))
    render(<TriageTable projectId="p1" />)
    expect(await screen.findByText('math only')).toBeInTheDocument()
  })
})


describe('Priority Board no longer carries the muted list', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  test('opening the board never fetches the muted findings', async () => {
    // X10: the board loaded EVERY muted row on each visit, which fails once a
    // filter rule mutes thousands. Muted Nodes pages them instead.
    const fetchMock = vi.fn((url: string) => ok({ findings: [ranked], total: 1 }))
    vi.stubGlobal('fetch', fetchMock)
    render(<TriageTable projectId="p1" onViewMuted={vi.fn()} />)
    await screen.findByText(/real 34%/)
    const urls = fetchMock.mock.calls.map(c => String(c[0]))
    expect(urls.some(u => u.includes('/api/triage/muted'))).toBe(false)
    expect(screen.queryByText(/Show muted/)).toBeNull()
  })

  test('the mute toast offers a way to the muted list', async () => {
    const onViewMuted = vi.fn()
    vi.stubGlobal('fetch', vi.fn((url: string) =>
      url.includes('/api/triage/mute')
        ? ok({ muted: true, label: 'Vulnerability' })
        : ok({ findings: [ranked], total: 1 })))
    mockDangerConfirm.mockResolvedValue(true)
    render(<TriageTable projectId="p1" onViewMuted={onViewMuted} />)
    fireEvent.click(await screen.findByTitle(/Hide this finding/))
    await waitFor(() => expect(mockAddToast).toHaveBeenCalled())
    const toast = mockAddToast.mock.calls[0][0]
    expect(toast.action.label).toBe('View muted')
    toast.action.onClick()
    expect(onViewMuted).toHaveBeenCalledOnce()
  })
})


describe('Priority Board Node ID column', () => {
  const withNodeId = { ...ranked, node_id: '4711' }

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  test('it is the leftmost column, ahead of the rank', async () => {
    vi.stubGlobal('fetch', vi.fn(() => ok({ findings: [withNodeId], total: 1 })))
    render(<TriageTable projectId="p1" />)
    await screen.findByText(/real 34%/)
    const headers = screen.getAllByRole('columnheader')
    expect(headers[0]).toHaveTextContent('Node ID')
    expect(headers[1]).toHaveTextContent('#')
    expect(screen.getByRole('button', { name: 'Copy node ID 4711' })).toBeInTheDocument()
  })

  test('a row from an agent that predates the column shows "-"', async () => {
    vi.stubGlobal('fetch', vi.fn(() => ok({ findings: [ranked], total: 1 })))
    render(<TriageTable projectId="p1" />)
    await screen.findByText(/real 34%/)
    expect(screen.queryByRole('button', { name: /Copy node ID/ })).toBeNull()
    expect(screen.getAllByRole('row')[1].querySelector('td')).toHaveTextContent('-')
  })

  test('a verdict is still written against the id property, never the graph id', async () => {
    // The graph id changes on import and version-activate; a verdict keyed on
    // it would land on whatever node reuses that number.
    const fetchMock = vi.fn((url: string) =>
      url.includes('/api/triage/verdict')
        ? ok({ updated: true })
        : ok({ findings: [withNodeId], total: 1 }))
    vi.stubGlobal('fetch', fetchMock)
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByTitle(/Mark this real/))
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(c => String(c[0]).includes('/api/triage/verdict'))).toBe(true))
    const call = fetchMock.mock.calls.find(c => String(c[0]).includes('/api/triage/verdict'))!
    const body = JSON.parse((call as unknown as [string, { body: string }])[1].body)
    expect(body.nodeId).toBe('f1')
  })
})
