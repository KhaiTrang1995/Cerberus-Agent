/**
 * Node Inspector filter PERSISTENCE.
 *
 * The filtering itself is covered by NodeFilterPanel.test.tsx. What is tested
 * here is the round trip through `users.ui_preferences`, and specifically the
 * four ways a "remembered filter" feature goes wrong in practice:
 *
 *   - it restores rows-narrowed but chips-empty, so the user cannot see or
 *     undo what is hiding their data
 *   - it leaks one node type's filters onto another
 *   - the restore lands AFTER the user starts typing and erases their input
 *   - it writes on every mount, so the row is churned by merely visiting
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/NodeFilterPanel.persistence.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { NodeDetailsTable } from './NodeDetailsTable'
import type { GraphData } from '../../types'

vi.mock('./exportNodeDetails', () => ({
  exportNodeDetailsCsv: vi.fn(),
  exportNodeDetailsJson: vi.fn(),
  exportNodeDetailsMarkdown: vi.fn(),
}))

const PROJECT = 'p1'

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

interface PatchCall {
  featureKey: string
  value: unknown
}

/**
 * @param prefs   the stored blob the GET resolves with
 * @param delayMs how long the GET takes - the point of the race tests
 */
function installFetchMock(prefs: Record<string, unknown> = {}, delayMs = 0) {
  const patches: PatchCall[] = []
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
      if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs))
      return new Response(JSON.stringify(prefs), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    if (init?.method === 'PATCH') {
      const body = JSON.parse(init.body as string) as PatchCall
      patches.push(body)
      return new Response(JSON.stringify({ [body.featureKey]: body.value }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  return patches
}

/** Two node types (Domain sorts first, so it is the default selection), so
 * cross-type leakage is observable. */
function makeData(): GraphData {
  const nodes = [
    { id: 's1', name: 'a.example.com', type: 'Domain', properties: { status: 'live', port: 443 } },
    { id: 's2', name: 'b.example.com', type: 'Domain', properties: { status: 'live', port: 80 } },
    { id: 's3', name: 'c.example.com', type: 'Domain', properties: { status: 'dead', port: 8080 } },
    { id: 'p1', name: 'pkg-alpha', type: 'Package', properties: { ecosystem: 'npm' } },
    { id: 'p2', name: 'pkg-beta', type: 'Package', properties: { ecosystem: 'pypi' } },
  ]
  return { nodes, links: [], projectId: PROJECT } as unknown as GraphData
}

function renderTable(projectId: string | null = PROJECT) {
  return render(
    <NodeDetailsTable data={makeData()} isLoading={false} error={null} projectId={projectId} />,
    { wrapper: makeWrapper() },
  )
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

async function selectNodeType(type: string) {
  fireEvent.click(screen.getByRole('button', { name: /^(Domain|Package|Select type)/ }))
  fireEvent.click(await screen.findByRole('option', { name: new RegExp(type) }))
}

/** The `tableFilters` value from the last PATCH, or null if none was sent. */
function lastTableFilters(patches: PatchCall[]): any {
  const relevant = patches.filter(p => p.featureKey === 'tableFilters')
  return relevant.length ? relevant[relevant.length - 1].value : null
}

const DOMAIN_SCOPE = 'nodeInspector:Domain'
const PACKAGE_SCOPE = 'nodeInspector:Package'

/** A stored blob holding one filter, in the shape the hook writes. */
function storedBlob(scope: string, filters: Record<string, unknown>) {
  return { tableFilters: { [PROJECT]: { [scope]: filters } } }
}

const LIVE_ONLY = { presence: 'any', selected: ['live'], listMode: 'any', min: null, max: null, from: '', to: '', q: '', textMode: 'contains', negate: false }

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------

describe('restoring saved filters', () => {
  beforeEach(() => { installFetchMock(storedBlob(DOMAIN_SCOPE, { 'prop:status': LIVE_ONLY })) })

  test('a saved filter narrows the table on mount, with no user action', async () => {
    const { container } = renderTable()
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com', 'b.example.com']))
  })

  test('a restored filter announces itself in the chip bar', async () => {
    renderTable()
    // Without this the table is narrowed by something invisible: no chip, no
    // count on the Filters button, and no way to find what to clear.
    expect(await screen.findByText(/status is live/)).toBeTruthy()
  })

  test('a restored filter can be cleared from the chip bar', async () => {
    const { container } = renderTable()
    const remove = await screen.findByRole('button', { name: /Remove filter: status is live/ })
    fireEvent.click(remove)
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))
  })

  test('the restored state is reflected in the panel controls themselves', async () => {
    renderTable()
    await screen.findByText(/status is live/)
    await openFilters()
    openColumnCard('status')
    const live = await screen.findByRole('checkbox', { name: /live/ })
    expect((live as HTMLInputElement).checked).toBe(true)
  })
})

describe('saving filters', () => {
  test('changing a filter writes it under project + node type', async () => {
    const patches = installFetchMock()
    renderTable()
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))

    await waitFor(() => expect(lastTableFilters(patches)).toBeTruthy())
    expect(lastTableFilters(patches)[PROJECT][DOMAIN_SCOPE]['prop:status'].selected).toEqual(['live'])
  })

  test('merely opening the panel writes nothing', async () => {
    const patches = installFetchMock()
    renderTable()
    await openFilters()
    openColumnCard('status')
    // Give the 400ms debounce room to fire if anything had been queued.
    await new Promise(r => setTimeout(r, 600))
    expect(patches.filter(p => p.featureKey === 'tableFilters')).toHaveLength(0)
  })

  test('clearing the last filter removes the scope rather than storing an empty object', async () => {
    const patches = installFetchMock(storedBlob(DOMAIN_SCOPE, { 'prop:status': LIVE_ONLY }))
    renderTable()
    fireEvent.click(await screen.findByRole('button', { name: /Remove filter: status is live/ }))

    await waitFor(() => expect(lastTableFilters(patches)).toBeTruthy())
    // Whole project key drops out once its last scope is gone.
    expect(lastTableFilters(patches)[PROJECT]).toBeUndefined()
  })

  test('without a project there is nothing to scope to, so nothing is written', async () => {
    const patches = installFetchMock()
    renderTable(null)
    await openFilters()
    openColumnCard('status')
    fireEvent.click(await screen.findByRole('checkbox', { name: /live/ }))
    await new Promise(r => setTimeout(r, 600))
    expect(patches.filter(p => p.featureKey === 'tableFilters')).toHaveLength(0)
  })
})

describe('scoping by node type', () => {
  test("one type's saved filter does not follow the user to another type", async () => {
    installFetchMock(storedBlob(DOMAIN_SCOPE, { 'prop:status': LIVE_ONLY }))
    const { container } = renderTable()
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))

    await selectNodeType('Package')
    // Package has no `status` column at all; carrying the filter over would
    // show an empty table for a type the user never filtered.
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['pkg-alpha', 'pkg-beta']))
    expect(screen.queryByText(/status is live/)).toBeNull()
  })

  test('each type restores its own saved filter', async () => {
    installFetchMock({
      tableFilters: {
        [PROJECT]: {
          [DOMAIN_SCOPE]: { 'prop:status': LIVE_ONLY },
          [PACKAGE_SCOPE]: { 'prop:ecosystem': { ...LIVE_ONLY, selected: ['pypi'] } },
        },
      },
    })
    const { container } = renderTable()
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(2))

    await selectNodeType('Package')
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['pkg-beta']))
  })
})

describe('races against the preferences fetch', () => {
  test('a late restore does not erase a filter the user already set', async () => {
    // The GET resolves well after the user has typed - the exact window in
    // which a naive hydration effect overwrites live input.
    installFetchMock(storedBlob(DOMAIN_SCOPE, { 'prop:status': LIVE_ONLY }), 300)
    const { container } = renderTable()
    await openFilters()
    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '8000' } })
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['c.example.com']))

    await new Promise(r => setTimeout(r, 500))
    expect(bodyRowNames(container)).toEqual(['c.example.com'])
  })

  test('two edits in quick succession both survive', async () => {
    installFetchMock({}, 250)
    const { container } = renderTable()
    await openFilters()
    openColumnCard('port')
    fireEvent.change(screen.getByLabelText('Minimum port'), { target: { value: '80' } })
    fireEvent.change(screen.getByLabelText('Maximum port'), { target: { value: '443' } })
    await waitFor(() => expect(bodyRowNames(container)).toEqual(['a.example.com', 'b.example.com']))

    await new Promise(r => setTimeout(r, 400))
    expect(bodyRowNames(container)).toEqual(['a.example.com', 'b.example.com'])
  })
})

describe('a hostile or stale stored blob', () => {
  test('garbage entries are ignored instead of crashing the table', async () => {
    installFetchMock({
      tableFilters: {
        [PROJECT]: {
          [DOMAIN_SCOPE]: {
            'prop:status': { presence: 'sideways', selected: 'live', textMode: 'lasers', q: 42 },
            'prop:port': null,
          },
        },
      },
    })
    const { container } = renderTable()
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))
    expect(screen.queryByText(/is live/)).toBeNull()
  })

  test('a filter for a column this type no longer has is dropped', async () => {
    installFetchMock(storedBlob(DOMAIN_SCOPE, {
      'prop:registrar': { ...LIVE_ONLY, selected: ['godaddy'] },
    }))
    const { container } = renderTable()
    // `registrar` exists on no Subdomain row here; the filter must not survive
    // as an invisible narrowing.
    await waitFor(() => expect(bodyRowNames(container)).toHaveLength(3))
  })
})
