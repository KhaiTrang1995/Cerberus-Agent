/**
 * Scan Timeline — Recon Delta table (Section 6.2/6.3).
 *
 * The behavior that matters beyond rendering: it needs two comparable versions,
 * it surfaces a comparison error instead of silently showing nothing, and — the
 * one that bites in production — a failing overlay fetch must NOT retry forever.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

// The force-graph canvas needs a real WebGL/2D context; jsdom has none. The
// overlay's contract here is the payload it hands over, so stand it in with a
// probe that reports what it was given.
vi.mock('../GraphCanvas', () => ({
  AUTO_2D_THRESHOLD: 1500,
  GraphCanvas: ({ data }: { data?: { nodes: unknown[]; links: unknown[] } }) => (
    <div data-testid="canvas" data-nodes={data?.nodes.length ?? 0} data-links={data?.links.length ?? 0} />
  ),
}))

import { ReconDeltaTable } from './ReconDeltaTable'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'

const v = (over: Partial<ScanVersionSummary>): ScanVersionSummary => ({
  id: 'v1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: false,
  nodeCount: 10, linkCount: 5, createdAt: '2026-07-01T10:00:00.000Z',
  snapshotBytes: 2048, activatable: true, ...over,
})

const versions = [
  v({ id: 'v2', seq: 2, label: 'Scan 2', isCurrent: true, snapshotBytes: 0, activatable: false }),
  v({ id: 'v1', seq: 1, label: 'Scan 1' }),
]

const DELTA = {
  from: { versionId: 'v1', label: 'Scan 1' },
  to: { versionId: 'current', label: 'Current' },
  addedNodes: [{ key: 'Port::number=6379', type: 'Port', name: '6379/tcp', properties: { number: 6379 } }],
  removedNodes: [],
  changedNodes: [{
    key: 'Technology::name=nginx', type: 'Technology', name: 'nginx', properties: { version: '1.25' },
    changes: [{ field: 'version', from: '1.20', to: '1.25' }],
  }],
  addedLinks: [], removedLinks: [],
  scorecard: [{ type: 'Port', added: 1, removed: 0, changed: 0, fromCount: 1, toCount: 2 }],
  totals: { fromNodes: 5, toNodes: 6, added: 1, removed: 0, changed: 1, stable: 4, addedLinks: 0, removedLinks: 0 },
  lenses: {
    newlyExposedPorts: [], closedPorts: [], newVulnerabilities: [], resolvedVulnerabilities: [],
    newCves: [], technologyVersionChanges: [], certificateChanges: [], newParameters: [],
  },
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const ok = (body: unknown) => ({ ok: true, json: async () => body })
const fail = (status: number, body: unknown) => ({ ok: false, status, json: async () => body })

describe('ReconDeltaTable', () => {
  test('needs two comparable versions before it will compare anything', () => {
    render(<ReconDeltaTable projectId="p1" versions={[versions[0]]} />)
    expect(screen.getByText(/needs at least two versions/i)).toBeTruthy()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('compares the newest past version against current by default', async () => {
    fetchMock.mockResolvedValue(ok(DELTA))
    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('from=v1')
    expect(url).toContain('to=current')
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    expect(screen.getByText(/1 changed/)).toBeTruthy()
  })

  test('shows the changed field old to new', async () => {
    fetchMock.mockResolvedValue(ok(DELTA))
    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    fireEvent.click(screen.getByRole('tab', { name: /Changed/ }))
    expect(screen.getByText('version')).toBeTruthy()
    expect(screen.getByText('1.20')).toBeTruthy()
    expect(screen.getByText('1.25')).toBeTruthy()
  })

  test('the Node ID column leads each node table, with "-" where no live node exists', async () => {
    fetchMock.mockResolvedValue(ok({
      ...DELTA,
      addedNodes: [{ ...DELTA.addedNodes[0], nodeId: '4711' }],
      removedNodes: [{ key: 'IP::address=10.0.0.9', type: 'IP', name: '10.0.0.9', properties: {}, nodeId: null }],
      changedNodes: [{
        ...DELTA.changedNodes[0], nodeId: '4712',
        changes: [{ field: 'version', from: '1.20', to: '1.25' }, { field: 'banner', from: 'a', to: 'b' }],
      }],
      totals: { ...DELTA.totals, removed: 1 },
    }))
    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())

    // After the +/- state glyph, ahead of every data column.
    expect(screen.getAllByRole('columnheader')[1].textContent).toBe('Node ID')
    expect(screen.getByRole('button', { name: 'Copy node ID 4711' })).toBeTruthy()

    fireEvent.click(screen.getByRole('tab', { name: /Removed/ }))
    expect(screen.queryByRole('button', { name: /Copy node ID/ })).toBeNull()
    expect(screen.getAllByRole('row')[1].querySelectorAll('td')[1].textContent).toBe('-')

    // One node spans several change rows; only its first carries the id.
    fireEvent.click(screen.getByRole('tab', { name: /Changed/ }))
    expect(screen.getAllByRole('columnheader')[0].textContent).toBe('Node ID')
    expect(screen.getAllByRole('button', { name: 'Copy node ID 4712' })).toHaveLength(1)
  })

  test('surfaces a comparison error instead of rendering an empty diff', async () => {
    fetchMock.mockResolvedValue(fail(409, { error: 'Version "Scan 1" has no stored snapshot' }))
    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/no stored snapshot/)).toBeTruthy())
  })

  test('a failing overlay fetch does NOT retry forever', async () => {
    // Regression: the overlay effect keyed on `overlay === null`, so an error
    // response (which never sets it) re-triggered the effect on every render —
    // an unbounded request loop against the server.
    fetchMock.mockImplementation(async (url: string) =>
      String(url).includes('overlay=1')
        ? fail(500, { error: 'boom' })
        : ok(DELTA))

    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    fireEvent.click(screen.getByRole('tab', { name: /Graph overlay/ }))

    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('overlay=1')).length)
        .toBeGreaterThan(0))
    // Give any runaway loop several turns to pile up requests.
    for (let i = 0; i < 10; i++) await new Promise(r => setTimeout(r, 5))
    const overlayCalls = fetchMock.mock.calls.filter(c => String(c[0]).includes('overlay=1')).length
    expect(overlayCalls).toBe(1)
  })

  test('the overlay actually renders once it arrives', async () => {
    // Regression: the overlay effect listed its own `overlayLoading` state in its
    // dependency array, so setting it re-ran the effect, whose cleanup cancelled
    // the in-flight request — the response was then always discarded and the
    // overlay never appeared (it just span forever).
    fetchMock.mockImplementation(async (url: string) =>
      String(url).includes('overlay=1')
        ? ok({
            ...DELTA,
            overlay: {
              nodes: [
                { id: 'IP::address=1.1.1.1', name: '1.1.1.1', type: 'IP', properties: {}, deltaState: 'added' },
                { id: 'IP::address=2.2.2.2', name: '2.2.2.2', type: 'IP', properties: {}, deltaState: 'stable' },
              ],
              links: [],
            },
          })
        : ok(DELTA))

    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    fireEvent.click(screen.getByRole('tab', { name: /Graph overlay/ }))

    // The overlay canvas renders once the payload arrives. Counts + the "show
    // unchanged" toggle live on the controls bar now (one bar less).
    await waitFor(() => expect(screen.getByTestId('canvas')).toBeTruthy())
    expect(screen.getByText(/Show unchanged/)).toBeTruthy()

    // "Changes only" is the default, so the unchanged overlay node is filtered out
    // of the render set even though the totals bar still counts the delta's stable
    // nodes (4 unchanged from the fixture).
    expect(screen.getByText(/4 unchanged/)).toBeTruthy()
    expect(screen.getByTestId('canvas').getAttribute('data-nodes')).toBe('1')
    fireEvent.click(screen.getByRole('checkbox'))
    await waitFor(() => expect(screen.getByTestId('canvas').getAttribute('data-nodes')).toBe('2'))
  })

  test('an overlay error is shown to the user, not left spinning', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      String(url).includes('overlay=1') ? fail(500, { error: 'overlay exploded' }) : ok(DELTA))
    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    fireEvent.click(screen.getByRole('tab', { name: /Graph overlay/ }))
    await waitFor(() => expect(screen.getByText(/overlay exploded/)).toBeTruthy())
  })

  test('the overlay is fetched once and only when its tab is opened', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      String(url).includes('overlay=1')
        ? ok({ ...DELTA, overlay: { nodes: [], links: [] } })
        : ok(DELTA))

    render(<ReconDeltaTable projectId="p1" versions={versions} />)
    await waitFor(() => expect(screen.getByText(/1 added/)).toBeTruthy())
    expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('overlay=1'))).toHaveLength(0)

    fireEvent.click(screen.getByRole('tab', { name: /Graph overlay/ }))
    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('overlay=1'))).toHaveLength(1))

    // Switching away and back must not refetch an overlay we already have.
    fireEvent.click(screen.getByRole('tab', { name: /^New/ }))
    fireEvent.click(screen.getByRole('tab', { name: /Graph overlay/ }))
    for (let i = 0; i < 5; i++) await new Promise(r => setTimeout(r, 5))
    expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('overlay=1'))).toHaveLength(1)
  })
})
