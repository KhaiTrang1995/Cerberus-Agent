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
  useOptionalProject: () => ({ userId: 'u1' }),
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


// ---------------------------------------------------------------------------
// The three-layer board (plan 5.5): rules, review, decision.
// ---------------------------------------------------------------------------

import { within } from '@testing-library/react'
import { MuteNodeProvider } from '../MuteNode'

const ruleFactors = {
  C: { value: 0.8, evidence: 'detected by nuclei' },
  L: { value: 0.5, evidence: 'the misconfiguration class prior' },
  I: { value: 0.45, evidence: 'severity medium' },
  R: { value: 0.8, evidence: 'no reachability evidence either way' },
}

/** Rules scored it 62.5 (Act soon); the built-in AI called it doubtful. */
const reviewed = {
  ...ranked,
  id: 'f2', name: 'Exposed admin panel', label: 'Vulnerability',
  triage_math_score: 62.5, triage_base_tier: 'T2',
  triage_base_factors: JSON.stringify(ruleFactors),
  triage_priority_score: 30.0, triage_tier: 'T3',
  triage_factors: JSON.stringify({ ...ruleFactors, C: { value: 0.25, evidence: 'the review doubts it' } }),
  triage_decided_by: 'review', reviewed_via: 'builtin', review_state: 'current',
  triage_ai_verdict: 'doubtful', triage_ai_model: 'claude-haiku-4-5',
  triage_ai_why: 'The login page is a vendor default with no admin behind it.',
  triage_fix_lever: 'Restrict /admin to the VPN',
}

/** A person marked it real in the app. */
const decided = {
  ...reviewed,
  id: 'f3', name: 'SQL injection in /search',
  triage_status: 'confirmed', triage_source: 'human', decided_via: 'app',
  triage_decided_by: 'person', triage_reason: 'Reproduced by hand',
  triage_priority_score: 88.0, triage_tier: 'T1',
  triage_factors: JSON.stringify({ ...ruleFactors, C: { value: 1, evidence: 'you marked it real' } }),
}

type Handler = (url: string, init?: RequestInit) => { body: unknown; status?: number } | Promise<never>

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

/** One fetch mock for the board, the panel's two reads and the verdict. */
function serve(routes: {
  findings?: Handler
  finding?: Handler
  evidence?: Handler
  verdict?: Handler
}) {
  const fn = vi.fn((url: string, init?: RequestInit) => {
    const pick = url.includes('/api/triage/findings') ? routes.findings
      : url.includes('/api/triage/finding?') ? routes.finding
        : url.includes('/api/triage/evidence') ? routes.evidence
          : url.includes('/api/triage/verdict') ? routes.verdict
            : undefined
    if (!pick) return reply({}, 404)
    const out = pick(url, init)
    if (out instanceof Promise) return out
    return reply(out.body, out.status ?? 200)
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

function board(rows: unknown[], extra: Record<string, unknown> = {}): Handler {
  return () => ({ body: { findings: rows, total: rows.length, latestRunId: 'run-1', ...extra } })
}

function callsTo(fn: ReturnType<typeof vi.fn>, path: string) {
  return fn.mock.calls.filter(c => String(c[0]).includes(path))
}

function rowOf(name: string): HTMLElement {
  return screen.getByRole('button', { name }).closest('tr') as HTMLElement
}

const EVIDENCE = {
  found: true, finding_id: 'f2', label: 'Vulnerability',
  evidence: 'HTTP/1.1 200 OK\n<title>Admin</title>', evidence_hash: 'a'.repeat(40),
  matches_last_run: true, reviewable: true, not_reviewable_because: null,
  review_survives_rescan: true, current_review: null, contract: {},
}

function detailOf(row: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    found: true, row, group: [], detector: { key: 'nuclei:admin-panel', real: 2, fp: 8 },
    review_survives_rescan: true, ...extra,
  }
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('the row names the layer that decided it', () => {
  test('a review that moved the score shows the rules score, the delta and who moved it', async () => {
    serve({ findings: board([reviewed]) })
    render(<TriageTable projectId="p1" />)
    const chip = await screen.findByText('AI: Doubtful')
    expect(chip.getAttribute('title')).toContain('claude-haiku-4-5')

    const base = screen.getByText(/rules 62\.5 · Act soon/)
    expect(within(base).getByText('−32.5')).toBeInTheDocument()
    expect(base.getAttribute('title')).toContain('The AI review moved it to 30.0')

    // Only the factor the review changed is marked, with the rules' value on hover.
    const moved = screen.getByText('25%')
    expect(moved.tagName).toBe('MARK')
    expect(moved.getAttribute('title')).toBe('rules: 80%')
    expect(document.querySelectorAll('mark')).toHaveLength(1)

    // Why: the review's reason, with the fix lever.
    expect(screen.getByText(/vendor default with no admin/)).toBeInTheDocument()
    expect(screen.getByText('Restrict /admin to the VPN')).toBeInTheDocument()
  })

  test('an external review names the agent, not the AI, and says when it is out of date', async () => {
    serve({ findings: board([{
      ...reviewed, reviewed_via: 'mcp', triage_ai_by: 'rdm_ab12', review_state: 'stale',
      triage_ai_model: '',
    }]) })
    render(<TriageTable projectId="p1" />)
    const chip = await screen.findByText('Agent: Doubtful')
    expect(chip.getAttribute('title')).toContain('rdm_ab12')
    expect(screen.getByText('out of date')).toBeInTheDocument()
    expect(screen.queryByText(/^AI:/)).toBeNull()
  })

  test("a person's decision gets a You chip, with the MCP token when decided over MCP", async () => {
    serve({ findings: board([
      decided,
      { ...decided, id: 'f4', name: 'Open redirect', decided_via: 'mcp',
        triage_verdict_token: 'rdm_cd34', triage_status: 'confirmed' },
    ]) })
    render(<TriageTable projectId="p1" />)
    expect(await screen.findByText('You: Real')).toBeInTheDocument()
    expect(screen.getByText('You via MCP · rdm_cd34: Real')).toBeInTheDocument()
    // The person's reason wins the Why column over the review's.
    expect(screen.getAllByText('Reproduced by hand')).toHaveLength(2)
    expect(screen.queryByText(/vendor default with no admin/)).toBeNull()
  })

  test('a reset row has no You chip and no Reset button (B8)', async () => {
    serve({ findings: board([{
      ...ranked, triage_status: 'unreviewed', triage_source: null, triage_reason: null,
      triage_decided_by: 'rules', reviewed_via: 'none',
    }]) })
    render(<TriageTable projectId="p1" />)
    await screen.findByText(/real 34%/)
    expect(within(rowOf('Missing header')).getByText('Rules only')).toBeInTheDocument()
    expect(within(rowOf('Missing header')).queryByText(/^You/)).toBeNull()
    expect(screen.queryByRole('button', { name: /Reset/ })).toBeNull()
  })

  test('a legacy row with no rules-only factors shows no base line', async () => {
    serve({ findings: board([{
      ...reviewed, triage_base_factors: null, triage_math_score: 62.5,
    }]) })
    render(<TriageTable projectId="p1" />)
    await screen.findByText('AI: Doubtful')
    expect(screen.queryByText(/^rules /)).toBeNull()
    expect(document.querySelectorAll('mark')).toHaveLength(0)
  })

  test('the Decided by column replaces Verdict', async () => {
    serve({ findings: board([ranked]) })
    render(<TriageTable projectId="p1" />)
    await screen.findByText(/real 34%/)
    expect(screen.getByRole('columnheader', { name: 'Decided by' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Verdict' })).toBeNull()
  })
})

describe('the Decided by filter is applied by the server', () => {
  test('picking a choice re-fetches with the filter, and the menu shows uncapped counts', async () => {
    const fetchMock = serve({
      findings: url => ({
        body: url.includes('decidedBy=person')
          ? { findings: [decided], total: 1, latestRunId: 'run-1' }
          : {
              findings: [ranked, reviewed], total: 2, latestRunId: 'run-1',
              facets: {
                total: 250,
                decided_by: { person: 3, review: 40, rules: 207 },
                reviewed_via: { builtin: 38, mcp: 2, none: 210 },
                review_current: { current: 30, stale: 10, none: 210 },
                tiers: { T1: 7, T2: 11, T3: 90, T4: 12 },
              },
            },
      }),
    })
    render(<TriageTable projectId="p1" />)
    await screen.findByText('AI: Doubtful')
    const menu = screen.getByRole('combobox', { name: 'Decided by' })
    expect(within(menu).getByRole('option', { name: 'You (3)' })).toBeInTheDocument()
    expect(within(menu).getByRole('option', { name: 'An external agent (MCP) (2)' })).toBeInTheDocument()
    expect(within(menu).getByRole('option', { name: 'Nobody (not reviewed) (210)' })).toBeInTheDocument()
    expect(within(menu).getByRole('option', { name: 'Review out of date (10)' })).toBeInTheDocument()

    fireEvent.change(menu, { target: { value: 'decidedBy:person' } })
    expect(await screen.findByText('You: Real')).toBeInTheDocument()
    const urls = callsTo(fetchMock, '/api/triage/findings').map(c => String(c[0]))
    expect(urls).toHaveLength(2)
    expect(urls[1]).toContain('decidedBy=person')
    expect(urls[1]).toContain('projectId=p1')
    expect(screen.queryByRole('button', { name: 'Exposed admin panel' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Missing header' })).toBeNull()
  })

  test('tier chips count ranked rows from the facets, past the cap (U6)', async () => {
    serve({ findings: board([ranked], {
      total: 120, facets: { tiers: { T1: 7, T2: 0, T3: 12, T4: 3 } },
    }) })
    render(<TriageTable projectId="p1" />)
    await screen.findByText(/real 34%/)
    expect(screen.getByRole('button', { name: 'Act now (7)' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Plan (12)' })).toBeInTheDocument()
    expect(screen.getByText(/Showing the 1 highest-ranked findings of 120/)).toBeInTheDocument()
  })

  test('without facets, an untriaged row is not counted under Track', async () => {
    serve({ findings: board([
      { ...ranked, id: 'u1', name: 'Fresh finding', section: 1, triage_run_id: '',
        triage_priority_score: null, triage_tier: '' },
    ]) })
    render(<TriageTable projectId="p1" />)
    await screen.findByRole('button', { name: 'Fresh finding' })
    expect(screen.getByRole('button', { name: 'Track (0)' })).toBeInTheDocument()
  })

  test('the older-run tag follows the server latestRunId, not the newest triaged_at (B9)', async () => {
    const older = { ...ranked, id: 'f9', name: 'Older one', triage_run_id: 'run-0',
                    triaged_at: '2026-09-01T00:00:00Z' }
    // The newest triaged_at belongs to run-0 here, as after a verdict bumped it.
    const bumped = { ...ranked, triaged_at: '2026-08-01T00:00:00Z' }
    serve({ findings: board([bumped, older], { latestRunId: 'run-1' }) })
    render(<TriageTable projectId="p1" />)
    await screen.findByRole('button', { name: 'Older one' })
    expect(within(rowOf('Older one')).getByText(/^from /)).toBeInTheDocument()
    expect(within(rowOf('Missing header')).queryByText(/^from /)).toBeNull()
  })
})

describe('a verdict replaces its row in place', () => {
  test('the row comes back from the answer, with no reload, and the reason is sent (U9, B10)', async () => {
    const fetchMock = serve({
      findings: board([ranked]),
      verdict: () => ({ body: {
        updated: true, label: 'Vulnerability', rescored: true, before: {}, after: {},
        row: { ...ranked, triage_status: 'confirmed', triage_source: 'human', decided_via: 'app',
               triage_decided_by: 'person', triage_priority_score: 91.0, triage_tier: 'T1' },
      } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByTitle(/Mark this real/))
    expect(await screen.findByText('You: Real')).toBeInTheDocument()
    expect(screen.getByText('91.0')).toBeInTheDocument()
    expect(callsTo(fetchMock, '/api/triage/findings')).toHaveLength(1)

    const body = JSON.parse(String((callsTo(fetchMock, '/api/triage/verdict')[0][1] as RequestInit).body))
    expect(body).toMatchObject({ projectId: 'p1', nodeId: 'f1', status: 'confirmed', reason: '', label: 'Vulnerability' })
  })

  test('a refusal is shown on the row, not in a modal, and nothing reloads', async () => {
    const fetchMock = serve({
      findings: board([ranked]),
      verdict: () => ({ status: 409, body: {
        code: 'busy', error: 'A version switch is in progress on this project; nothing was written.',
      } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByTitle(/Mark this real/))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('A version switch is in progress')
    expect(within(rowOf('Missing header')).getByRole('alert')).toBe(alert)
    expect(callsTo(fetchMock, '/api/triage/findings')).toHaveLength(1)
  })

  test('a finding gone since the page loaded says so on the row and offers a reload', async () => {
    const fetchMock = serve({
      findings: board([ranked]),
      verdict: () => ({ status: 404, body: { code: 'not_found', error: 'No such finding' } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByTitle(/Mark this real/))
    expect(await screen.findByRole('alert')).toHaveTextContent(/no longer on the board/)
    fireEvent.click(screen.getByRole('button', { name: 'Reload' }))
    await waitFor(() => expect(callsTo(fetchMock, '/api/triage/findings')).toHaveLength(2))
  })
})

describe('Reset', () => {
  test('is offered only on a decided row, and its confirm names what the finding loses', async () => {
    const fetchMock = serve({
      findings: board([decided, reviewed]),
      verdict: () => ({ body: { updated: true, row: { ...reviewed, id: 'f3', name: 'SQL injection in /search' } } }),
    })
    mockDangerConfirm.mockResolvedValueOnce(false)
    render(<TriageTable projectId="p1" />)
    await screen.findByText('You: Real')
    expect(within(rowOf('Exposed admin panel')).queryByRole('button', { name: /Reset/ })).toBeNull()

    fireEvent.click(within(rowOf('SQL injection in /search')).getByRole('button', { name: /Reset/ }))
    await waitFor(() => expect(mockDangerConfirm).toHaveBeenCalledTimes(1))
    const [text, title] = mockDangerConfirm.mock.calls[0]
    expect(title).toBe('Reset your decision')
    expect(text).toContain('SQL injection in /search')
    expect(text).toContain('Mute Rules may mute it')
    expect(text).toContain('a scan that no longer reports it removes it')
    // Cancelled: nothing is sent.
    expect(callsTo(fetchMock, '/api/triage/verdict')).toHaveLength(0)

    mockDangerConfirm.mockResolvedValueOnce(true)
    fireEvent.click(within(rowOf('SQL injection in /search')).getByRole('button', { name: /Reset/ }))
    await waitFor(() => expect(callsTo(fetchMock, '/api/triage/verdict')).toHaveLength(1))
    const body = JSON.parse(String((callsTo(fetchMock, '/api/triage/verdict')[0][1] as RequestInit).body))
    expect(body.status).toBe('unreviewed')
    await waitFor(() => expect(screen.queryByText('You: Real')).toBeNull())
  })
})

describe('Multi mute stays on every row', () => {
  test('the row carries Multi next to Mute', async () => {
    serve({ findings: board([ranked]) })
    render(
      <MuteNodeProvider projectId="p1" readOnly={false}>
        <TriageTable projectId="p1" />
      </MuteNodeProvider>,
    )
    await screen.findByText(/real 34%/)
    const row = rowOf('Missing header')
    expect(within(row).getByRole('button', { name: 'Multi mute' })).toBeEnabled()
    expect(within(row).getByTitle(/Hide this finding/)).toBeInTheDocument()
  })
})

describe('the detail panel', () => {
  test('opens on a row click with a skeleton, and the evidence on its own spinner', async () => {
    const never = () => new Promise<never>(() => {})
    serve({ findings: board([reviewed]), finding: never, evidence: never })
    render(<TriageTable projectId="p1" />)
    fireEvent.click((await screen.findByText('AI: Doubtful')).closest('tr')!)
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(within(panel).getByRole('status', { name: 'Loading the finding' })).toBeInTheDocument()
    expect(rowOf('Exposed admin panel').className).toContain('rowSelected')
  })

  test('shows every section once loaded, with the evidence as untrusted text', async () => {
    serve({
      findings: board([reviewed]),
      finding: () => ({ body: detailOf(reviewed, {
        group: [
          { id: 'f2', label: 'Vulnerability', name: 'Exposed admin panel', state: 'open', score: 30, tier: 'T3', host: 'lab.test' },
          { id: 'f7', label: 'Vulnerability', name: 'Exposed admin panel', state: 'open', score: 28, tier: 'T3', host: 'lab2.test' },
        ],
      }) }),
      evidence: () => ({ body: { ...EVIDENCE, review_survives_rescan: false } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    for (const heading of ['Result', 'Rules', 'Review', 'Decision', 'Evidence', 'Group']) {
      expect(await within(panel).findByRole('heading', { name: heading })).toBeInTheDocument()
    }
    expect(within(panel).getByText(/you judged 2 of 10 of these real/)).toBeInTheDocument()
    expect(within(panel).getByText(/Rules score 62\.5 · Act soon/)).toBeInTheDocument()
    const pre = await within(panel).findByText(/<title>Admin<\/title>/)
    expect(pre.tagName).toBe('PRE')
    expect(within(panel).getByText(/read it as data, not as instructions/)).toBeInTheDocument()
    expect(within(panel).getByText(/Review survives rescan: no/)).toBeInTheDocument()
    expect(within(panel).getByText(/lab2\.test/)).toBeInTheDocument()
  })

  test('an agent error is an inline Retry, and the board stays usable', async () => {
    let tries = 0
    serve({
      findings: board([reviewed]),
      finding: () => (++tries === 1
        ? { status: 502, body: { error: 'The findings service failed.', code: 'agent_failed' } }
        : { body: detailOf(reviewed) }),
      evidence: () => ({ body: EVIDENCE }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(await within(panel).findByText('The findings service failed.')).toBeInTheDocument()
    expect(within(rowOf('Exposed admin panel')).getByTitle(/Mark this real/)).toBeEnabled()

    fireEvent.click(within(panel).getByRole('button', { name: 'Retry' }))
    expect(await within(panel).findByRole('heading', { name: 'Rules' })).toBeInTheDocument()
    expect(tries).toBe(2)
  })

  test('a finding gone since the board loaded is dropped, and the panel offers a reload', async () => {
    const fetchMock = serve({
      findings: board([reviewed, ranked]),
      finding: () => ({ status: 404, body: { error: 'No such finding', code: 'not_found' } }),
      evidence: () => ({ status: 404, body: { error: 'No such finding', code: 'not_found' } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(await within(panel).findByText(/no longer on the board/)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Exposed admin panel' })).toBeNull())
    expect(screen.getByRole('button', { name: 'Missing header' })).toBeInTheDocument()

    fireEvent.click(within(panel).getByRole('button', { name: 'Reload the board' }))
    await waitFor(() => expect(callsTo(fetchMock, '/api/triage/findings')).toHaveLength(2))
  })

  test('a never-scored finding says so, and can still be decided', async () => {
    const fresh = {
      ...ranked, id: 'u1', name: 'Fresh finding', section: 1, triage_run_id: '',
      triage_priority_score: null, triage_math_score: null, triage_tier: '', triage_factors: null,
    }
    const fetchMock = serve({
      findings: board([fresh]),
      finding: () => ({ body: detailOf(fresh) }),
      evidence: () => ({ body: { ...EVIDENCE, reviewable: false, not_reviewable_because: 'not_scored' } }),
      verdict: () => ({ body: { updated: true, rescored: false, rescoreReason: 'not_scored',
        row: { ...fresh, triage_status: 'likely_noise', triage_source: 'human', section: 2 } } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Fresh finding' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(await within(panel).findByText('Not triaged yet.')).toBeInTheDocument()
    expect(await within(panel).findByText(/No run has scored it yet/)).toBeInTheDocument()

    fireEvent.change(within(panel).getByRole('textbox'), { target: { value: 'Staging only' } })
    fireEvent.click(within(panel).getByRole('button', { name: /False positive/ }))
    await waitFor(() => expect(callsTo(fetchMock, '/api/triage/verdict')).toHaveLength(1))
    const body = JSON.parse(String((callsTo(fetchMock, '/api/triage/verdict')[0][1] as RequestInit).body))
    expect(body).toMatchObject({ status: 'likely_noise', reason: 'Staging only', nodeId: 'u1' })
  })

  test('a legacy row shows the math score and promises the breakdown', async () => {
    const legacy = { ...reviewed, triage_base_factors: null, triage_math_score: 41.5 }
    serve({
      findings: board([legacy]),
      finding: () => ({ body: detailOf(legacy) }),
      evidence: () => ({ body: EVIDENCE }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(await within(panel).findByText(/Rules score 41\.5\. The breakdown comes with the next run\./))
      .toBeInTheDocument()
  })

  test('a finding no review may touch says why', async () => {
    serve({
      findings: board([reviewed]),
      finding: () => ({ body: detailOf(reviewed) }),
      evidence: () => ({ body: { ...EVIDENCE, reviewable: false, not_reviewable_because: 'proven' } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    expect(await within(panel).findByText(/Not reviewable: It is proven/)).toBeInTheDocument()
  })

  test('a decision made in the panel updates the row and the panel together', async () => {
    serve({
      findings: board([reviewed]),
      finding: () => ({ body: detailOf(reviewed) }),
      evidence: () => ({ body: EVIDENCE }),
      verdict: () => ({ body: { updated: true, rescored: true,
        row: { ...decided, id: 'f2', name: 'Exposed admin panel', triage_reason: 'Checked by hand' } } }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    const panel = screen.getByRole('complementary', { name: 'Finding details' })
    await within(panel).findByRole('heading', { name: 'Decision' })
    fireEvent.click(within(panel).getByRole('button', { name: /^Real$/ }))
    expect(await within(panel).findByText('You: Real')).toBeInTheDocument()
    expect(within(rowOf('Exposed admin panel')).getByText('You: Real')).toBeInTheDocument()
    expect(within(panel).getByRole('button', { name: /Reset/ })).toBeInTheDocument()
  })

  test('Escape closes it', async () => {
    serve({
      findings: board([reviewed]),
      finding: () => ({ body: detailOf(reviewed) }),
      evidence: () => ({ body: EVIDENCE }),
    })
    render(<TriageTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Exposed admin panel' }))
    expect(screen.getByRole('complementary', { name: 'Finding details' })).toBeInTheDocument()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('complementary', { name: 'Finding details' })).toBeNull()
  })
})
