/**
 * The `Updated` column on All Nodes, tested through the rendered table.
 *
 * This exists because a source-grep smoke test is not enough here. All Nodes
 * reads a node's RAW property map, where the field is Neo4j's `updated_at`,
 * while every Red Zone route aliases the same value to `updatedAt` in Cypher.
 * Wiring All Nodes to the route-shaped key compiled, type-checked, passed the
 * wiring smoke test and rendered a column of dashes - so the assertion has to
 * be on the value that reaches the cell, not on the identifiers in the file.
 *
 * Run: npx vitest run src/app/graph/components/DataTable/DataTable.updatedAt.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { DataTable } from './DataTable'
import { useTableData } from '../../hooks/useTableData'
import type { GraphData } from '../../types'

/** A Cypher `datetime()` as it survives the JSON trip from /api/graph. */
function temporal(y: number, mo: number, d: number, h = 0, mi = 0, sec = 0) {
  const int = (n: number) => ({ low: n, high: 0 })
  return { year: int(y), month: int(mo), day: int(d), hour: int(h), minute: int(mi), second: int(sec) }
}

const DATA = {
  nodes: [
    // Deliberately out of order, and NOT alphabetical either, so a passing
    // sort assertion cannot be an accident of insertion order.
    { id: 'n1', name: 'mid.example.com', type: 'Domain',
      properties: { updated_at: temporal(2026, 5, 5, 12, 0, 0) } },
    { id: 'n2', name: 'newest.example.com', type: 'Domain',
      properties: { updated_at: temporal(2026, 8, 20, 14, 32, 58) } },
    { id: 'n3', name: 'oldest.example.com', type: 'Domain',
      properties: { updated_at: temporal(2026, 1, 1, 0, 0, 0) } },
    // A node written before the timestamp existed.
    { id: 'n4', name: 'undated.example.com', type: 'Domain', properties: {} },
    // Package is the largest label in a real graph and stamps first/last_seen
    // rather than updated_at; reading only updated_at blanked all of them.
    { id: 'n5', name: 'pkg:npm/left-pad', type: 'Package',
      properties: { first_seen: '2026-03-01T00:00:00Z', last_seen: '2026-07-01T08:00:00Z' } },
    // Attack-chain labels stamp created_at only.
    { id: 'n6', name: 'step-1', type: 'ChainStep',
      properties: { created_at: temporal(2026, 4, 4, 4, 4, 4) } },
  ],
  links: [],
} as unknown as GraphData

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

function Harness() {
  const rows = useTableData(DATA)
  return (
    <DataTable
      data={DATA} isLoading={false} error={null} rows={rows}
      globalFilter="" onGlobalFilterChange={() => {}} projectId="p1"
    />
  )
}

function installFetch() {
  globalThis.fetch = vi.fn(async () =>
    new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } })
  ) as typeof fetch
}

/** Text of the Updated cell of each body row: the last data cell, before the
 *  Mute action. */
function updatedCells(container: HTMLElement): string[] {
  return [...container.querySelectorAll('tbody tr')]
    .filter(r => r.querySelectorAll('td').length > 1)   // skip expanded detail rows
    .map(r => {
      const tds = r.querySelectorAll('td')
      return tds[tds.length - 2]?.textContent?.trim() ?? ''
    })
}

/** Columns are [expand, Node ID, Type, Name, ...]. */
const NAME_TD = 3

function nameCells(container: HTMLElement): string[] {
  return [...container.querySelectorAll('tbody tr')]
    .filter(r => r.querySelectorAll('td').length > 1)
    .map(r => r.querySelectorAll('td')[NAME_TD]?.textContent?.trim() ?? '')
}

afterEach(() => { cleanup(); vi.clearAllMocks() })

describe('All Nodes / Updated column', () => {
  test('resolves a Package via last_seen and a ChainStep via created_at', async () => {
    installFetch()
    const { container } = render(<Harness />, { wrapper: makeWrapper() })
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0))

    const cells = updatedCells(container)
    expect(cells).toContain('2026-07-01 08:00:00') // Package.last_seen
    expect(cells).toContain('2026-04-04 04:04:04') // ChainStep.created_at
  })

  test('renders the timestamp, not an empty cell', async () => {
    installFetch()
    const { container } = render(<Harness />, { wrapper: makeWrapper() })
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0))

    const cells = updatedCells(container)
    // The regression this file exists for: reading the wrong key made every one
    // of these '-'.
    expect(cells).toContain('2026-08-20 14:32:58')
    expect(cells.filter(c => c === '-')).toHaveLength(1) // only the undated node
  })

  test('is the rightmost data column, with only the Mute action after it', async () => {
    installFetch()
    const { container } = render(<Harness />, { wrapper: makeWrapper() })
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0))

    const headers = [...container.querySelectorAll('thead th')].map(th => th.textContent?.trim() ?? '')
    expect(headers[headers.length - 2]).toContain('Updated')
    expect(headers[headers.length - 1]).toBe('')
  })

  test('lands sorted newest-first, with the undated node last', async () => {
    installFetch()
    const { container } = render(<Harness />, { wrapper: makeWrapper() })
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0))

    expect(nameCells(container)).toEqual([
      'newest.example.com',      // 2026-08-20  updated_at
      'pkg:npm/left-pad',        // 2026-07-01  last_seen  (fallback)
      'mid.example.com',         // 2026-05-05  updated_at
      'step-1',                  // 2026-04-04  created_at (fallback)
      'oldest.example.com',      // 2026-01-01  updated_at
      'undated.example.com',     // no timestamp at all
    ])
  })

  test('never leaks the raw temporal object into the cell', async () => {
    installFetch()
    const { container } = render(<Harness />, { wrapper: makeWrapper() })
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0))

    expect(container.textContent).not.toContain('object Object')
    expect(container.textContent).not.toContain('"low"')
  })
})
