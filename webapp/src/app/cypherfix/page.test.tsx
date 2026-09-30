/**
 * The CypherFix page sees a triage run it did not start (U11).
 *
 * Run: npx vitest run src/app/cypherfix/page.test.tsx
 *
 * The page used the triage socket without `autoConnect`, so a run started on
 * the Priority Board or over MCP was invisible here: pressing Run during it hit
 * the preflight's "already in progress" and never connected. It also dropped
 * the socket on every close of the progress panel.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const triageSpy = vi.hoisted(() => ({ hook: vi.fn(), disconnect: vi.fn(), stop: vi.fn() }))
const remediationsState = vi.hoisted(() => ({ list: [] as unknown[] }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ projectId: 'p1', userId: 'u1', isLoading: false }),
}))
vi.mock('@/components/ui', () => ({
  WikiInfoButton: () => null,
  ExternalLink: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  useAlertModal: () => ({ confirm: vi.fn(), alertError: vi.fn(), dangerConfirm: vi.fn() }),
}))
vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => ({ ensureFeatureModel: vi.fn() }),
}))
vi.mock('@/hooks/useProjects', () => ({ useProjectById: () => ({ data: null }) }))
vi.mock('@/hooks', () => ({
  useRemediations: () => ({
    remediations: remediationsState.list, isLoading: false, error: null,
    refetch: vi.fn(), updateRemediation: vi.fn(), deleteRemediation: vi.fn(),
  }),
  useCypherFixTriageWS: triageSpy.hook,
}))

import CypherFixPage from './page'

function triageState(overrides: Record<string, unknown> = {}) {
  return {
    status: 'connected', currentPhase: null, progress: 0, findings: [], thinking: '',
    error: null, notice: null, startTriage: vi.fn(), stopTriage: triageSpy.stop,
    disconnect: triageSpy.disconnect, ...overrides,
  }
}

const MCP_RUN = {
  id: 'run-9', status: 'running', startedAt: '2026-09-29T10:00:00Z', trigger: 'mcp',
  phase: 'reviewing', progress: 50, tokenPrefix: 'rdm_ab12',
}

const REMEDIATION = {
  id: 'r1', title: 'Patch the admin panel', severity: 'high', priority: 1, status: 'pending',
  remediationType: 'code_fix', cveIds: [], exploitAvailable: false, cisaKev: false,
  updatedAt: '2026-09-29T10:00:00Z',
}

beforeEach(() => {
  remediationsState.list = []
  triageSpy.hook.mockReset().mockReturnValue(triageState())
  vi.stubGlobal('fetch', vi.fn(async () => new Response(
    JSON.stringify({ liveRun: MCP_RUN }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('/cypherfix and a run it did not start', () => {
  test('the page connects on open, so the server can re-attach it to a live run', () => {
    render(<CypherFixPage />)
    expect(triageSpy.hook).toHaveBeenCalledWith(expect.objectContaining({
      userId: 'u1', projectId: 'p1', enabled: true, autoConnect: true,
    }))
  })

  test('a live run shows the banner with who started it, and Run waits for it', async () => {
    triageSpy.hook.mockReturnValue(triageState({ status: 'running', currentPhase: 'reviewing' }))
    render(<CypherFixPage />)
    expect(await screen.findByText('Started over MCP · rdm_ab12')).toBeInTheDocument()
    const banner = screen.getByRole('status')
    expect(banner).toHaveTextContent('Triage running · Started over MCP · rdm_ab12 — Reviewing the evidence')
    const run = screen.getByRole('button', { name: /Triage running\.\.\./ })
    expect(run).toBeDisabled()
  })

  test('the dashboard shows the same banner once fix items exist', async () => {
    remediationsState.list = [REMEDIATION]
    triageSpy.hook.mockReturnValue(triageState({ status: 'running', currentPhase: 'scoring' }))
    render(<CypherFixPage />)
    expect(await screen.findByText('Patch the admin panel')).toBeInTheDocument()
    expect(await screen.findByText('Started over MCP · rdm_ab12')).toBeInTheDocument()
  })

  test('closing the panel keeps the socket while the run is live, and drops it after', async () => {
    triageSpy.hook.mockReturnValue(triageState({ status: 'running', currentPhase: 'reviewing' }))
    const { rerender } = render(<CypherFixPage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Details' }))
    fireEvent.click(screen.getByRole('button', { name: 'Hide' }))
    // Hidden over a live run: back to the banner, and the socket stays.
    expect(await screen.findByRole('button', { name: 'Details' })).toBeInTheDocument()
    expect(triageSpy.disconnect).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Details' }))
    triageSpy.hook.mockReturnValue(triageState({ status: 'stopped', currentPhase: 'reviewing' }))
    rerender(<CypherFixPage />)
    expect(screen.getByText('Vulnerability Triage stopped')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(triageSpy.disconnect).toHaveBeenCalledTimes(1))
  })

  test('no live run, no banner', () => {
    render(<CypherFixPage />)
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.queryByText(/Started over MCP/)).toBeNull()
    expect(screen.getByRole('button', { name: /Start Triage/ })).toBeEnabled()
  })
})
