/**
 * Edge / regression / smoke tests for Node Inspector filtering.
 *
 * NodeFilterPanel.test.tsx covers the happy paths. This file goes after the
 * interactions that a filter feature bolted onto an existing table typically
 * gets wrong: stale pagination, filters on hidden columns, malformed input in a
 * number box, and the row set changing underneath an active filter.
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/NodeFilterPanel.edge.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { NodeDetailsTable } from './NodeDetailsTable'
import type { GraphData } from '../../types'

const exportCalls: { input: any }[] = []
vi.mock('./exportNodeDetails', () => ({
  exportNodeDetailsCsv: vi.fn(async (input: any) => { exportCalls.push({ input }) }),
  exportNodeDetailsJson: vi.fn(async () => {}),
  exportNodeDetailsMarkdown: vi.fn(async () => {}),
}))

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

function installFetchMock(prefs: Record<string, unknown> = {}) {
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
      return new Response(JSON.stringify(prefs), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    if (init?.method === 'PATCH') {
      const body = JSON.parse(init.body as string)
      return new Response(JSON.stringify({ [body.featureKey]: body.value }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch
}

/** `count` Subdomain nodes, half live / half dead, ports 1..count. */
function makeBulkData(count: number): GraphData {
  const nodes = Array.from({ length: count }, (_, i) => ({
    id: `s${i}`,
    name: `host${String(i).padStart(3, '0')}.example.com`,
    type: 'Subdomain',
    properties: { status: i % 2 === 0 ? 'live' : 'dead', port: i + 1, zone: `z${i % 4}` },
  }))
  return { nodes, links: [], projectId: 'p1' } as unknown as GraphData
}

function renderTable(data: GraphData) {
  return render(<NodeDetailsTable data={data} isLoading={false} error={null} />, { wrapper: makeWrapper() })
}

function bodyRowNames(container: HTMLElement): string[] {
  return [...container.querySelectorAll('tbody tr')]
    .filter(r => !r.className.includes('noMatchRow'))
    // Columns are [expand, Node ID, Name, ...].
    .map(r => r.querySelector('td:nth-child(3)')?.textContent?.trim() ?? '')
    .filter(Boolean)
}

async function openFilters() {
  fireEvent.click(screen.getByRole('button', { name: /Filters/i }))
  return screen.findByPlaceholderText('Find a column…')
}

function openColumnCard(label: string) {
  const header = screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return header
}

beforeEach(() => {
  exportCalls.length = 0
  installFetchMock()
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------

describe('pagination interaction', () => {
  // The classic bolt-on-filter bug: sitting on page 3, apply a filter that
  // leaves one page of results, and the table renders nothing at all because
  // pageIndex is still 2 - with no "no rows match" message either, because
  // there ARE matching rows, just not on that page.
  test('filtering while on a later page does not leave a blank table', async () => {
    const { container } = renderTable(makeBulkData(120))
    expect(bodyRowNames(container)).toHaveLength(50)

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(20)) // page 3 of 120

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    // 60 live rows -> at 50/page there is a page 2, but page 3 does not exist.
    await waitFor(() => expect(bodyRowNames(container).length).toBeGreaterThan(0))
  })

  test('the page count itself follows the filter', async () => {
    const { container } = renderTable(makeBulkData(120))
    expect(container.textContent).toContain('Page 1 of 3')

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    await waitFor(() => expect(container.textContent).toContain('Page 1 of 2'))
    expect(container.textContent).toContain('(60 rows)')
  })
})

describe('filters on hidden columns', () => {
  // Filtering by something you do not want displayed is a deliberate feature,
  // so it must actually filter - and the chip is the only thing telling the
  // user why the table shrank.
  test('a filter still applies when its column is hidden, and the chip explains it', async () => {
    installFetchMock({ nodeDetailsTable: { Subdomain: { hiddenColumns: ['zone'] } } })
    const { container } = renderTable(makeBulkData(8))

    // zone is hidden from the table…
    await waitFor(() => expect(container.querySelector('thead')?.textContent).not.toContain('zone'))

    // …but still filterable.
    await openFilters()
    openColumnCard('zone')
    fireEvent.click(await screen.findByRole('checkbox', { name: /z0/ }))

    await waitFor(() => expect(bodyRowNames(container)).toEqual([
      'host000.example.com', 'host004.example.com',
    ]))
    expect(screen.getByText('zone is z0')).toBeInTheDocument()
  })
})

describe('malformed numeric input', () => {
  // Number(<garbage>) is NaN. A NaN bound compares false against everything, so
  // the filter silently does nothing while the chip claims it is active - the
  // UI and the rows disagree, which is worse than rejecting the input.
  test('a non-numeric range bound is ignored rather than becoming an active NaN filter', async () => {
    const { container } = renderTable(makeBulkData(6))
    await openFilters()
    openColumnCard('port')

    const min = screen.getByLabelText('Minimum port') as HTMLInputElement
    fireEvent.change(min, { target: { value: 'abc' } })

    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(6))
    expect(screen.queryByText(/NaN/)).toBeNull()
  })

  test('a zero bound is a real bound, not a falsy no-op', async () => {
    const { container } = renderTable(makeBulkData(6))
    await openFilters()
    openColumnCard('port')

    fireEvent.change(screen.getByLabelText('Maximum port'), { target: { value: '0' } })

    // Ports are 1..6, so max=0 must exclude everything.
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(0))
    expect(screen.getByText(/No rows match the current filters/)).toBeInTheDocument()
    expect(screen.getByText('port <= 0')).toBeInTheDocument()
  })
})

describe('the row set changing under an active filter', () => {
  test('a refetch that drops the filtered property does not crash the table', async () => {
    const data = makeBulkData(6)
    const { container, rerender } = renderTable(data)

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))

    // Same node type, but `status` is gone from every node.
    const stripped = {
      ...data,
      nodes: data.nodes.map(n => ({ ...n, properties: { port: n.properties.port, zone: n.properties.zone } })),
    } as GraphData

    expect(() =>
      rerender(<NodeDetailsTable data={stripped} isLoading={false} error={null} />)
    ).not.toThrow()

    // TanStack ignores a filter for a column that no longer exists, so the rows
    // come back. The chip therefore MUST go too - a chip claiming "status is
    // live" over an unfiltered table is the filter bar lying about the data.
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(6))
    expect(screen.queryByText('status is live')).toBeNull()
    expect(screen.queryByText(/No rows match/)).toBeNull()
  })

  // The chip disappearing is not enough on its own: chips are derived from the
  // profiled columns, so they vanish whether or not the underlying filter state
  // was cleaned up. The state matters when the property COMES BACK - a filter
  // the user can no longer see must not silently re-apply itself.
  test('a filter does not resurrect when its property returns', async () => {
    const data = makeBulkData(6)
    const { container, rerender } = renderTable(data)

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))

    const stripped = {
      ...data,
      nodes: data.nodes.map(n => ({ ...n, properties: { port: n.properties.port, zone: n.properties.zone } })),
    } as GraphData
    rerender(<NodeDetailsTable data={stripped} isLoading={false} error={null} />)
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(6))

    // Property returns (next scan re-emits it). Nothing in the UI is claiming a
    // filter, so all 6 rows must stay.
    rerender(<NodeDetailsTable data={data} isLoading={false} error={null} />)
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(6))
    expect(screen.queryByText('status is live')).toBeNull()
  })

  test('new rows arriving are subject to the active filter', async () => {
    const data = makeBulkData(4)
    const { container, rerender } = renderTable(data)

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))

    const grown = {
      ...data,
      nodes: [
        ...data.nodes,
        { id: 'sX', name: 'new-live.example.com', type: 'Subdomain',
          properties: { status: 'live', port: 99, zone: 'z0' } },
        { id: 'sY', name: 'new-dead.example.com', type: 'Subdomain',
          properties: { status: 'dead', port: 98, zone: 'z0' } },
      ],
    } as unknown as GraphData

    rerender(<NodeDetailsTable data={grown} isLoading={false} error={null} />)

    await waitFor(() => {
      const names = bodyRowNames(container)
      expect(names).toContain('new-live.example.com')
      expect(names).not.toContain('new-dead.example.com')
    })
  })
})

describe('facet list behaviour', () => {
  // Ticking a box narrows the OTHER columns' counts, so a value can drop to
  // zero. If it vanished from the list the user could not untick it.
  test('a selected value stays listed even when its live count reaches zero', async () => {
    const { container } = renderTable(makeBulkData(8))
    await openFilters()

    openColumnCard('zone')
    fireEvent.click(await screen.findByRole('checkbox', { name: /z0/ }))

    openColumnCard('status')
    // z0 rows are host000 (live) and host004 (live) -> "dead" now counts 0.
    const dead = await screen.findByRole('checkbox', { name: /dead/ })
    expect(dead).toBeInTheDocument()

    fireEvent.click(dead)
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(0))

    // Still present, so it can be undone.
    fireEvent.click(screen.getByRole('checkbox', { name: /dead/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))
  })

  test('facet counts reflect the other active filters, not the raw totals', async () => {
    renderTable(makeBulkData(8))
    await openFilters()

    openColumnCard('status')
    // 8 rows: 4 live, 4 dead.
    expect((await screen.findByRole('checkbox', { name: /live/ })).parentElement?.textContent)
      .toContain('4')

    openColumnCard('zone')
    fireEvent.click(await screen.findByRole('checkbox', { name: /z0/ }))

    openColumnCard('status')
    // z0 is i%4===0 -> host000, host004, both even -> both live. live drops to 2.
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: /live/ }).parentElement?.textContent).toContain('2'))
  })
})

describe('smoke: a wide, deep node type', () => {
  test('opens, infers and filters a 400-row type without falling over', async () => {
    const nodes = Array.from({ length: 400 }, (_, i) => ({
      id: `n${i}`,
      name: `node-${i}.example.com`,
      type: 'Subdomain',
      properties: {
        status: ['live', 'dead', 'unknown'][i % 3],
        port: (i % 500) + 1,
        uid: `uuid-${i}-${Math.floor(i / 3)}`,   // high cardinality -> text
        tags: i % 2 === 0 ? ['even'] : ['odd', 'x'],
        seen: `2026-0${(i % 9) + 1}-01`,
      },
    }))
    const data = { nodes, links: [], projectId: 'p1' } as unknown as GraphData

    const { container } = renderTable(data)
    await openFilters()

    // Inference still picks the right control for each shape at this size.
    const kindOf = (label: string) =>
      screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) }).textContent
    expect(kindOf('status')).toContain('pick')
    expect(kindOf('uid')).toContain('text')
    expect(kindOf('tags')).toContain('tags')
    expect(kindOf('port')).toContain('range')

    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /unknown/ }))
    await waitFor(() => expect(container.textContent).toContain('(133 rows)'))

    fireEvent.click(screen.getByRole('button', { name: 'Export to CSV' }))
    await waitFor(() => expect(exportCalls).toHaveLength(1))
    expect(exportCalls[0].input.rows).toHaveLength(133)
  })
})

describe('degenerate data', () => {
  test('a single-row type still offers a usable picker', async () => {
    const data = {
      nodes: [{ id: 'x', name: 'only.example.com', type: 'Subdomain', properties: { status: 'live' } }],
      links: [], projectId: 'p1',
    } as unknown as GraphData

    const { container } = renderTable(data)
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['only.example.com']))
  })

  test('a property present on only some rows filters without excluding by accident', async () => {
    const data = {
      nodes: [
        { id: 'a', name: 'a.example.com', type: 'Subdomain', properties: { status: 'live', rare: 'yes' } },
        { id: 'b', name: 'b.example.com', type: 'Subdomain', properties: { status: 'live' } },
      ],
      links: [], projectId: 'p1',
    } as unknown as GraphData

    const { container } = renderTable(data)
    await openFilters()

    openColumnCard('rare')
    fireEvent.click(screen.getAllByRole('button', { name: 'Has value' })[0])
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com']))

    fireEvent.click(screen.getAllByRole('button', { name: 'Empty' })[0])
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['b.example.com']))
  })

  test('In/Out treat zero connections as a value, not as empty', async () => {
    const data = {
      nodes: [
        { id: 'a', name: 'a.example.com', type: 'Subdomain', properties: {} },
        { id: 'b', name: 'b.example.com', type: 'Subdomain', properties: {} },
      ],
      links: [], projectId: 'p1',
    } as unknown as GraphData

    const { container } = renderTable(data)
    await openFilters()
    openColumnCard('In')
    fireEvent.click(screen.getAllByRole('button', { name: 'Has value' })[0])
    // 0 is a real count; "Has value" must not silently drop every row.
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))
  })
})
