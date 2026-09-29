/**
 * Integration tests for Node Inspector per-column filtering.
 *
 * nodeFilterHelpers.test.ts covers the predicates in isolation; this drives the
 * real component, because the parts that break in practice are the wiring ones:
 * a filter that narrows the table but not the row counter, or narrows the table
 * but not the export.
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/NodeFilterPanel.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { NodeDetailsTable } from './NodeDetailsTable'
import type { GraphData } from '../../types'

// The export helpers do real DOM/file I/O; stub them and inspect what rows they
// were handed. That is the only way to assert the download contract.
const exportCalls: { fn: string; input: any }[] = []
vi.mock('./exportNodeDetails', () => ({
  exportNodeDetailsCsv: vi.fn(async (input: any) => { exportCalls.push({ fn: 'csv', input }) }),
  exportNodeDetailsJson: vi.fn(async (input: any) => { exportCalls.push({ fn: 'json', input }) }),
  exportNodeDetailsMarkdown: vi.fn(async (input: any) => { exportCalls.push({ fn: 'md', input }) }),
}))

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

function installFetchMock() {
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
      return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
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

/**
 * One node type with a deliberately mixed column set, so the inference has to
 * make a different choice per column:
 *   status  -> enum   (2 repeating values)
 *   port    -> number (range)
 *   tags    -> list   (arrays)
 *   seen    -> date
 *   note    -> mostly empty
 *   name    -> text   (unique)
 */
function makeData(): GraphData {
  const nodes = [
    { id: 's1', name: 'a.example.com', type: 'Subdomain',
      properties: { status: 'live', port: 443, tags: ['web', 'prod'], seen: '2026-01-05', note: 'first' } },
    { id: 's2', name: 'b.example.com', type: 'Subdomain',
      properties: { status: 'live', port: 80, tags: ['web'], seen: '2026-06-15', note: '' } },
    { id: 's3', name: 'c.example.com', type: 'Subdomain',
      properties: { status: 'dead', port: 8080, tags: ['api', 'prod'], seen: '2026-08-01' } },
    { id: 's4', name: 'd.other.com', type: 'Subdomain',
      properties: { status: 'dead', port: 22, tags: [], seen: '2026-08-08', note: 'last' } },
  ]
  return { nodes, links: [], projectId: 'p1' } as unknown as GraphData
}

function renderTable(data: GraphData = makeData()) {
  return render(<NodeDetailsTable data={data} isLoading={false} error={null} />, { wrapper: makeWrapper() })
}

/** Body rows only, excluding the "no rows match" placeholder. */
function bodyRowNames(container: HTMLElement): string[] {
  const rows = [...container.querySelectorAll('tbody tr')]
  return rows
    .filter(r => !r.className.includes('noMatchRow'))
    // Columns are [expand, Node ID, Name, ...].
    .map(r => r.querySelector('td:nth-child(3)')?.textContent?.trim() ?? '')
    .filter(Boolean)
}

async function openFilters() {
  fireEvent.click(screen.getByRole('button', { name: /Filters/i }))
  return screen.findByPlaceholderText('Find a column…')
}

/** Expand one column card in the panel by its label. */
function openColumnCard(label: string) {
  const header = screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return header
}

/** The card header element for a column, regardless of expansion state. */
function cardHeader(label: string) {
  return screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) })
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

describe('filter panel', () => {
  test('opens and lists every filterable column, including In/Out', async () => {
    renderTable()
    await openFilters()
    for (const label of ['Name', 'status', 'port', 'tags', 'seen', 'note', 'In', 'Out']) {
      expect(cardHeader(label)).toBeInTheDocument()
    }
  })

  // The heart of "decide wisely per column": each one advertises its own kind.
  test('infers a different control per column', async () => {
    renderTable()
    await openFilters()
    const kindOf = (label: string) => cardHeader(label).textContent

    expect(kindOf('status')).toContain('pick')
    expect(kindOf('port')).toContain('range')
    expect(kindOf('tags')).toContain('tags')
    expect(kindOf('seen')).toContain('dates')
    expect(kindOf('Name')).toContain('text')
  })

  test('a column search narrows the panel', async () => {
    renderTable()
    const search = await openFilters()
    fireEvent.change(search, { target: { value: 'por' } })
    expect(cardHeader('port')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Filter by status/ })).toBeNull()
  })
})

describe('filtering narrows the table', () => {
  test('an enum checkbox keeps only matching rows', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')

    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com', 'b.example.com']))
  })

  test('two values in one column are OR-ed', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /dead/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(4))
  })

  // The cumulative requirement: different columns must AND together.
  test('filters on different columns are cumulative', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '100' } })

    // live -> a(443) + b(80); port >= 100 -> only a survives both.
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com']))
  })

  test('a numeric range is inclusive at both ends', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '80' } })
    fireEvent.change(screen.getByLabelText('Maximum port'), { target: { value: '443' } })
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com', 'b.example.com']))
  })

  test('list "All of" demands every selected tag', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('tags')
    fireEvent.click(await screen.findByRole('checkbox', { name: /web/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /prod/ }))
    // Any of: a (web,prod), b (web), c (api,prod)
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))

    fireEvent.click(screen.getByRole('button', { name: 'All of' }))
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com']))
  })

  test('a date range narrows by day', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('seen')
    fireEvent.change(screen.getByLabelText('seen from'), { target: { value: '2026-06-01' } })
    await waitFor(() =>
      expect(bodyRowNames(container)).toEqual(['b.example.com', 'c.example.com', 'd.other.com']))
  })

  test('presence Empty finds rows missing a property', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('note')
    fireEvent.click(screen.getAllByRole('button', { name: 'Empty' })[0])
    // s2 has '' and s3 has no note at all - both count as empty.
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['b.example.com', 'c.example.com']))
  })

  test('text mode + negate excludes matches', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Name')
    fireEvent.change(screen.getByLabelText('Text filter for Name'), { target: { value: 'example' } })
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))

    fireEvent.click(screen.getByRole('checkbox', { name: 'not' }))
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['d.other.com']))
  })

  test('an invalid regex warns instead of crashing the table', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Name')
    fireEvent.change(screen.getByLabelText('Match mode for Name'), { target: { value: 'regex' } })
    fireEvent.change(screen.getByLabelText('Text filter for Name'), { target: { value: '([' } })

    expect(await screen.findByText(/Invalid regex/)).toBeInTheDocument()
    await waitFor(() => expect(bodyRowNames(container)).toEqual([]))
  })

  test('an over-narrow filter explains itself instead of showing a blank table', async () => {
    renderTable()
    await openFilters()
    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '99999' } })
    expect(await screen.findByText(/No rows match the current filters/)).toBeInTheDocument()
  })
})

describe('active filter chips', () => {
  test('a chip appears, describes the filter, and removing it restores the rows', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    const chip = await screen.findByText('status is live')
    expect(chip).toBeInTheDocument()
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))

    fireEvent.click(screen.getByRole('button', { name: /Remove filter: status is live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(4))
    expect(screen.queryByText('status is live')).toBeNull()
  })

  test('Clear all drops every filter at once', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '100' } })
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(1))

    // Two "Clear all" controls exist (panel + chip bar); either must work.
    fireEvent.click(screen.getAllByRole('button', { name: 'Clear all' })[0])
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(4))
  })
})

describe('the row counter and the export follow the filter', () => {
  test('the header count reflects filtered/total', async () => {
    const { container } = renderTable()
    expect(container.textContent).toContain('4')

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(container.textContent).toContain('2/4'))
  })

  // The download contract: what you see is what you download.
  test.each([
    ['CSV', 'Export to CSV'],
    ['JSON', 'Export to JSON'],
    ['MD', 'Export to Markdown'],
  ])('%s exports exactly the filtered rows', async (_format, buttonName) => {
    renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(screen.getByText('status is live')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: buttonName }))

    await waitFor(() => expect(exportCalls).toHaveLength(1))
    const names = exportCalls[0].input.rows.map((r: any) => r.node.name)
    expect(names).toEqual(['a.example.com', 'b.example.com'])
  })

  test('the export still honours the toolbar search on top of column filters', async () => {
    const { container } = renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    const search = container.querySelector('input[placeholder="Search…"]') as HTMLInputElement
    fireEvent.change(search, { target: { value: 'a.example' } })

    fireEvent.click(screen.getByRole('button', { name: 'Export to CSV' }))
    await waitFor(() => expect(exportCalls).toHaveLength(1))
    expect(exportCalls[0].input.rows.map((r: any) => r.node.name)).toEqual(['a.example.com'])
  })
})

describe('filters are scoped to the selected node type', () => {
  test('switching node type clears filters rather than carrying a meaningless one over', async () => {
    const data = makeData()
    data.nodes.push({
      id: 'i1', name: '10.0.0.1', type: 'IP', properties: { asn: 'AS1' },
    } as any)

    const { container } = renderTable(data)
    // Default selection is the first sorted type: IP.
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['10.0.0.1']))

    fireEvent.click(screen.getByRole('button', { name: /Select type|IP/ }))
    fireEvent.click(await screen.findByRole('option', { name: /Subdomain/ }))

    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))

    // Back to IP: the status filter must not still be applied.
    fireEvent.click(screen.getByRole('button', { name: /Subdomain/ }))
    fireEvent.click(await screen.findByRole('option', { name: /IP/ }))
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['10.0.0.1']))
    expect(screen.queryByText('status is live')).toBeNull()
  })
})
