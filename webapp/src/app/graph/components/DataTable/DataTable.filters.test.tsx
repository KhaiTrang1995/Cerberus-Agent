/**
 * Per-column filtering on the All Nodes table.
 *
 * All Nodes is the one filterable view with a FIXED column set, so its accessor
 * is a hand-written map rather than a property read - and a wrong entry there
 * filters on one value while the cell displays another. These tests pin the
 * mapping through the rendered table, plus the persistence scope, which must be
 * its own (`allNodes`) and not shared with the Node Inspector.
 *
 * Run: npx vitest run src/app/graph/components/DataTable/DataTable.filters.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { DataTable } from './DataTable'
import { useTableData } from '../../hooks/useTableData'
import type { GraphData } from '../../types'

const PROJECT = 'p1'
const SCOPE = 'allNodes'

const DATA = {
  nodes: [
    { id: 'n1', name: 'a.example.com', type: 'Domain', properties: { status: 'live', port: 443 } },
    { id: 'n2', name: 'b.example.com', type: 'Domain', properties: { status: 'dead' } },
    { id: 'n3', name: '10.0.0.1', type: 'IP', properties: {} },
  ],
  links: [{ source: 'n1', target: 'n3', type: 'RESOLVES_TO' }],
} as unknown as GraphData

interface PatchCall { featureKey: string; value: any }

function installFetch(prefs: Record<string, unknown> = {}) {
  const patches: PatchCall[] = []
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
      return new Response(JSON.stringify(prefs), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    if (init?.method === 'PATCH') {
      const b = JSON.parse(init.body as string) as PatchCall
      patches.push(b)
      return new Response(JSON.stringify({ [b.featureKey]: b.value }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  return patches
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

/** Mirrors how the page builds rows, so the accessor is tested against real ones. */
function Harness({ data = DATA }: { data?: GraphData }) {
  const rows = useTableData(data)
  return (
    <DataTable
      data={data}
      isLoading={false}
      error={null}
      rows={rows}
      globalFilter=""
      onGlobalFilterChange={() => {}}
      projectId={PROJECT}
    />
  )
}

function renderTable(data?: GraphData) {
  return render(<Harness data={data} />, { wrapper: makeWrapper() })
}

/** Columns are [expand, Node ID, Type, Name, ...]. */
const NAME_TD = 3

function names(container: HTMLElement): string[] {
  return [...container.querySelectorAll('tbody tr')]
    .map(r => r.querySelectorAll('td')[NAME_TD]?.textContent?.trim() ?? '')
    .filter(Boolean)
}

async function openFilters() {
  fireEvent.click(await screen.findByRole('button', { name: /^Filters/i }))
  return screen.findByPlaceholderText('Find a column…')
}

function openColumnCard(label: string) {
  const header = screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return header
}

afterEach(() => { cleanup(); vi.clearAllMocks() })

describe('All Nodes column filters', () => {
  test('offers the fixed column set', async () => {
    installFetch()
    renderTable()
    await openFilters()
    for (const label of ['Node ID', 'Type', 'Name', 'Props', 'In', 'Out', 'Conns']) {
      expect(screen.getByRole('button', { name: new RegExp(`^Filter by ${label}`) })).toBeTruthy()
    }
  })

  test('Node ID leads after the expand toggle and sorts numerically', async () => {
    installFetch()
    // Graph ids as /api/graph builds them: numeric strings. Text order would
    // put "100" before "9".
    const data = {
      nodes: [
        { id: '100', name: 'c.example.com', type: 'Domain', properties: {} },
        { id: '9', name: 'a.example.com', type: 'Domain', properties: {} },
        { id: '10', name: 'b.example.com', type: 'Domain', properties: {} },
      ],
      links: [],
    } as unknown as GraphData
    const { container } = renderTable(data)
    await waitFor(() => expect(names(container)).toHaveLength(3))

    const headers = [...container.querySelectorAll('thead th')].map(th => th.textContent?.trim() ?? '')
    expect(headers.slice(0, 3)).toEqual(['', 'Node ID', 'Type'])

    const nodeIds = () => [...container.querySelectorAll('tbody tr')]
      .map(r => r.querySelectorAll('td')[1]?.querySelector('[data-node-id]')?.getAttribute('data-node-id'))
    fireEvent.click(container.querySelectorAll('thead th')[1])
    await waitFor(() => expect(nodeIds()).toEqual(['9', '10', '100']))
  })

  test('filtering by node type narrows the rows', async () => {
    installFetch()
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Type')
    fireEvent.click(await screen.findByRole('checkbox', { name: /^Domain/ }))
    await waitFor(() => expect(names(container)).toEqual(['a.example.com', 'b.example.com']))
  })

  test('the derived Props count is filterable as a number', async () => {
    installFetch()
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Props')
    // n1 has 2 properties, n2 has 1, n3 has none.
    fireEvent.change(screen.getByLabelText('Minimum Props'), { target: { value: '2' } })
    await waitFor(() => expect(names(container)).toEqual(['a.example.com']))
  })

  test('connection counts filter on the same numbers the cells show', async () => {
    installFetch()
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Conns')
    fireEvent.change(screen.getByLabelText('Minimum Conns'), { target: { value: '1' } })
    // Only the two ends of the single link.
    await waitFor(() => expect(names(container).sort()).toEqual(['10.0.0.1', 'a.example.com']))
  })

  test('saves under its own scope, not the Node Inspector\'s', async () => {
    const patches = installFetch()
    renderTable()
    await openFilters()
    openColumnCard('Type')
    fireEvent.click(await screen.findByRole('checkbox', { name: /^IP/ }))

    await waitFor(() => expect(patches.some(p => p.featureKey === 'tableFilters')).toBe(true))
    const value = patches.filter(p => p.featureKey === 'tableFilters').pop()!.value
    expect(Object.keys(value[PROJECT])).toEqual([SCOPE])
    expect(value[PROJECT][SCOPE].type.selected).toEqual(['IP'])
  })

  test('a saved filter is restored and announced', async () => {
    installFetch({
      tableFilters: {
        [PROJECT]: {
          [SCOPE]: {
            type: {
              presence: 'any', selected: ['IP'], listMode: 'any', min: null, max: null,
              from: '', to: '', q: '', textMode: 'contains', negate: false,
            },
          },
        },
      },
    })
    const { container } = renderTable()
    await waitFor(() => expect(names(container)).toEqual(['10.0.0.1']))
    expect(await screen.findByText(/Type is IP/)).toBeTruthy()
  })
})
