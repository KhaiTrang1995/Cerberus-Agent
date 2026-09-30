/**
 * Muted Nodes: its states, unmuting, and the link from a rule mute to its rule.
 *
 * Run: npx vitest run src/app/graph/components/MutedNodes/MutedNodesTable.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const toast = { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() }
const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError }),
  useToast: () => toast,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

import { MutedNodesTable } from './MutedNodesTable'

const row = (over: Record<string, unknown> = {}) => ({
  id: 'v1', label: 'Vulnerability', name: 'tech-detect:nginx', severity: 'info', source: 'nuclei',
  host: 'api.example.com', muted_at: '2026-09-23T10:00:00Z', muted_by: 'rule:vuln.nuclei/k3f9a2',
  muted_via: 'rule', muted_reason: 'Filter rule: Informational templates', stale_since: null,
  triage_status: 'unreviewed', triage_reason: null, rule_kind: 'vuln.nuclei', rule_id: 'k3f9a2',
  rule_name: 'Informational templates', rule_deleted: false, ...over,
})

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('MutedNodesTable', () => {
  test('an agent\'s mute is badged with its token, keeps its reason, and can be filtered by token', async () => {
    fetchMock.mockReturnValue(reply({
      total: 1,
      findings: [row({
        muted_by: 'u1', muted_via: 'mcp', muted_channel: 'mcp', muted_token: 'rdmn_mcp_ab12cd34',
        muted_reason: 'dev-only banner, per the owner', rule_kind: null, rule_id: null, rule_name: null,
      })],
      facets: {
        total: 1, by_person: 0, by_mcp: 1, labels: { Vulnerability: 1 }, rules: [],
        tokens: [{ token: 'rdmn_mcp_ab12cd34', count: 1 }],
      },
    }))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText('Agent (MCP) · rdmn_mcp_ab12cd34')).toBeInTheDocument()
    expect(screen.queryByText('you')).not.toBeInTheDocument()
    expect(screen.getByText('dev-only banner, per the owner')).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Agent (MCP) (1)' })).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Token'), { target: { value: 'rdmn_mcp_ab12cd34' } })
    await waitFor(() => {
      const last = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0])
      expect(last).toContain('token=rdmn_mcp_ab12cd34')
    })
  })

  test('lists rule and person mutes, and says which', async () => {
    fetchMock.mockReturnValue(reply({
      total: 3,
      findings: [
        row(),
        row({ id: 'v2', name: 'aws key', label: 'Secret', source: 'jsluice', muted_by: 'u1', muted_via: 'person',
              rule_kind: null, rule_id: null, rule_name: null }),
        row({ id: 'v3', name: 'GHSA on lodash', muted_by: 'rule:vuln.osv/gone01', rule_name: null, rule_deleted: true,
              muted_reason: 'Filter rule: Old advisories', stale_since: '2026-09-22T00:00:00Z' }),
      ],
      facets: { total: 3, by_person: 1, labels: { Vulnerability: 2, Secret: 1 }, rules: [] },
    }))
    const onOpenRule = vi.fn()
    render(<MutedNodesTable projectId="p1" onOpenRule={onOpenRule} />)
    expect(await screen.findByText('tech-detect:nginx')).toBeInTheDocument()
    expect(screen.getByText('you')).toBeInTheDocument()
    expect(screen.getByText('Rule (deleted): Filter rule: Old advisories')).toBeInTheDocument()
    expect(screen.getByText('resolved: no longer reported')).toBeInTheDocument()
    // A live rule links to it; a deleted one cannot.
    fireEvent.click(screen.getByText('Rule: Informational templates'))
    expect(onOpenRule).toHaveBeenCalledWith('vuln.nuclei', 'k3f9a2')
    const first = String(fetchMock.mock.calls[0][0])
    expect(first).toContain('/api/triage/muted?projectId=p1&offset=0&limit=50')
    expect(first).toContain('facets=1')
  })

  test('nothing muted at all', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [], facets: { total: 0, by_person: 0, labels: {}, rules: [] } }))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText('Nothing is muted in this project.')).toBeInTheDocument()
  })

  test('nothing matching the filters offers to clear them', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('Nothing is muted in this project.')
    fireEvent.change(screen.getByLabelText('Muted by'), { target: { value: 'rule' } })
    expect(await screen.findByText('No muted nodes match these filters.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Clear filters'))
    await screen.findByText('Nothing is muted in this project.')
    expect(String(fetchMock.mock.calls.at(-1)![0])).not.toContain('mutedVia')
  })

  test('a failed load offers a retry', async () => {
    fetchMock.mockReturnValueOnce(reply({ error: 'agent down' }, 503))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText('agent down')).toBeInTheDocument()
    fetchMock.mockReturnValue(reply({ total: 1, findings: [row()] }))
    fireEvent.click(screen.getByText('Retry'))
    expect(await screen.findByText('tech-detect:nginx')).toBeInTheDocument()
  })

  test('Unmute sends the key as JSON and reloads', async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 1, items: [{ key: 'v1' }], exempted: 1 })
        : reply({ total: 1, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    fireEvent.click((await screen.findAllByText('Unmute'))[0])
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')!
    expect(post[0]).toBe('/api/triage/unmute')
    expect(post[1].headers).toEqual({ 'Content-Type': 'application/json' })
    expect(JSON.parse(post[1].body)).toEqual({ projectId: 'p1', keys: ['v1'] })
  })

  test('a selection is unmuted in one request', async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 2, items: [{ key: 'v1' }, { key: 'v2' }], exempted: 2 })
        : reply({ total: 2, findings: [row(), row({ id: 'v2', name: 'other' })] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('other')
    fireEvent.click(screen.getByLabelText('Select all on this page'))
    fireEvent.click(screen.getByText(/Unmute selected \(2\)/))
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Unmuted 2 findings.'))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')!
    expect(JSON.parse(post[1].body).keys).toEqual(['v1', 'v2'])
  })

  test('an unmute whose exemption was not saved warns', async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 1, items: [{ key: 'v1' }], exempted: 0, exemptionError: 'a mute rule may mute it again' })
        : reply({ total: 1, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    fireEvent.click((await screen.findAllByText('Unmute'))[0])
    await waitFor(() => expect(toast.warning).toHaveBeenCalledWith('a mute rule may mute it again'))
  })

  test('unmute_empties_last_page: unmuting every row on the last page steps back to one with rows', async () => {
    // The reload kept the old offset, past the new end: an empty table, the
    // "nothing muted" state, and no pager to get back with.
    let unmuted = false
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        unmuted = true
        return reply({ unmuted: 1, items: [{ key: 'v51' }], exempted: 1 })
      }
      const onSecondPage = String(url).includes('offset=50')
      if (!unmuted) return reply({ total: 51, findings: [onSecondPage ? row({ id: 'v51', name: 'the last one' }) : row()] })
      return reply({ total: 50, findings: onSecondPage ? [] : [row()] })
    })
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText(/1 of 2/)
    fireEvent.click(screen.getByLabelText('Next page'))
    await screen.findByText('the last one')
    fireEvent.click(screen.getAllByText('Unmute')[0])
    await waitFor(() => expect(unmuted).toBe(true))
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('offset=0'))
    expect(await screen.findByText('tech-detect:nginx')).toBeInTheDocument()
    expect(screen.queryByText('Nothing is muted in this project.')).toBeNull()
  })

  test('search_debounce_resets_paging: paging right after the table opens is not bounced back', async () => {
    // The debounce ran once on mount and reset the offset 350 ms later, with no
    // search typed: a page turned in that window snapped back to page 1.
    fetchMock.mockReturnValue(reply({ total: 120, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText(/1 of 3/)
    fireEvent.click(screen.getByLabelText('Next page'))
    await new Promise(resolve => setTimeout(resolve, 500))
    expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('offset=50')
    expect(screen.getByText(/2 of 3/)).toBeInTheDocument()
  })

  test('filters_survive_project_switch: another project opens unfiltered, on its first page', async () => {
    fetchMock.mockReturnValue(reply({
      total: 120, findings: [row()],
      facets: { total: 120, by_person: 0, labels: { Vulnerability: 100, Secret: 20 }, rules: [] },
    }))
    const { rerender } = render(<MutedNodesTable projectId="p1" />)
    await screen.findByText(/1 of 3/)
    fireEvent.change(screen.getByLabelText('Kind'), { target: { value: 'Secret' } })
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('label=Secret'))
    fireEvent.click(screen.getByLabelText('Next page'))
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('offset=50'))

    rerender(<MutedNodesTable projectId="p2" />)
    await waitFor(() => expect(fetchMock.mock.calls.some(c => String(c[0]).includes('projectId=p2'))).toBe(true))
    const forP2 = fetchMock.mock.calls.map(c => String(c[0])).filter(u => u.includes('projectId=p2'))
    expect(forP2.every(u => u.includes('offset=0') && !u.includes('label='))).toBe(true)
  })

  test('the Node ID sits right after the selection column', async () => {
    fetchMock.mockReturnValue(reply({ total: 2, findings: [row({ node_id: '812' }), row({ id: 'v2', name: 'other' })] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('other')
    const headers = screen.getAllByRole('columnheader')
    expect(headers[1]).toHaveTextContent('Node ID')
    expect(headers[2]).toHaveTextContent('Kind')
    expect(screen.getByRole('button', { name: 'Copy node ID 812' })).toBeInTheDocument()
    // The row without one shows the placeholder, not an empty cell.
    expect(screen.getAllByRole('row')[2].querySelectorAll('td')[1]).toHaveTextContent('-')
  })

  test('copying a Node ID neither selects the row nor unmutes it', async () => {
    fetchMock.mockReturnValue(reply({ total: 1, findings: [row({ node_id: '812' })] }))
    const writeText = vi.fn(() => Promise.resolve())
    Object.assign(navigator, { clipboard: { writeText } })
    render(<MutedNodesTable projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Copy node ID 812' }))
    expect(writeText).toHaveBeenCalledWith('812')
    expect((screen.getByLabelText('Select tech-detect:nginx') as HTMLInputElement).checked).toBe(false)
    expect(fetchMock.mock.calls.some(c => c[1]?.method === 'POST')).toBe(false)
  })

  test('a Multi mute is badged with its batch, and the filter counts them', async () => {
    fetchMock.mockReturnValue(reply({
      total: 1,
      findings: [row({
        muted_by: 'u1', muted_via: 'multi', muted_channel: 'multi', muted_token: 'mm-3f9a2c1d',
        muted_reason: 'Multi mute mm-3f9a2c1d · Same detector · like "nginx"',
        rule_kind: null, rule_id: null, rule_name: null,
      })],
      facets: {
        total: 1, by_person: 0, by_mcp: 0, by_multi: 1, labels: { Vulnerability: 1 }, rules: [],
        tokens: [], batches: [{ batch: 'mm-3f9a2c1d', count: 1 }],
      },
    }))
    render(<MutedNodesTable projectId="p1" />)
    const badge = await screen.findByText('you · Multi mute mm-3f9a2c1d')
    expect(badge.getAttribute('title')).toMatch(/not judged one by one/)
    expect(screen.queryByText('you')).not.toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Multi mute (1)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'mm-3f9a2c1d (1)' })).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Muted by'), { target: { value: 'multi' } })
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('mutedVia=multi'))
  })

  test('opened on one batch, the first request already asks for it alone', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [] }))
    render(<MutedNodesTable projectId="p1" focus={{ token: 'mm-3f9a2c1d' }} />)
    await screen.findByText('No muted nodes match these filters.')
    const first = new URL(`http://x${String(fetchMock.mock.calls[0][0])}`)
    expect(first.searchParams.get('token')).toBe('mm-3f9a2c1d')
    expect(first.searchParams.get('mutedVia')).toBe('multi')
    // A batch unmuted since is missing from the facets but stays selected.
    expect((screen.getByLabelText('Token') as HTMLSelectElement).value).toBe('mm-3f9a2c1d')
  })

  test('a new focus re-applies it; leaving it unset keeps what the person chose', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [] }))
    const { rerender } = render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('Nothing is muted in this project.')
    rerender(<MutedNodesTable projectId="p1" focus={{ token: 'mm-00000001' }} />)
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('token=mm-00000001'))
    const calls = fetchMock.mock.calls.length
    rerender(<MutedNodesTable projectId="p1" focus={null} />)
    await new Promise(r => setTimeout(r, 20))
    expect(fetchMock.mock.calls.length).toBe(calls)
  })

  test('pages forward', async () => {
    fetchMock.mockReturnValue(reply({ total: 120, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText(/1 of 3/)).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('Next page'))
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('offset=50'))
  })
})
