/**
 * JevTokenPanel: the TypeSafe Jev token next to the AI Model picker.
 *
 * With no token it offers the same input as Global Settings, so the token can be
 * added without leaving the project form. With a token it only confirms it. The
 * other half of the contract is that saving here reaches every engine switch on
 * the page at once: one form holds several lookups, and a token added in one must
 * not leave the others reading "no token" until a reload.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/JevTokenPanel.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, within, renderHook } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  useAlertModal: () => ({ alert: vi.fn(), alertError: vi.fn(), alertWarning: vi.fn(), confirm: vi.fn(), dangerConfirm: vi.fn() }),
}))

import { JevTokenPanel } from './JevTokenPanel'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

const JEV_ROW = { id: 'jev1', providerType: 'jev', apiKey: '••••••••c0de', modelIdentifier: 'jev-1.13.0' }

let providers: unknown
let providersStatus: number
const fetchMock = vi.fn()

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  providers = [{ id: 'p1', providerType: 'anthropic' }]
  providersStatus = 200
  fetchMock.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/agent/health') return json(200, { status: 'healthy' })
    if (url === '/api/users/user-1/llm-providers' && method === 'GET') return json(providersStatus, providers)
    if (url === '/api/users/user-1/llm-providers' && method === 'POST') {
      providers = [...(providers as unknown[]), JEV_ROW]
      return json(201, JEV_ROW)
    }
    return json(404, {})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const panel = () => screen.getByTestId('jev-token-panel')

describe('JevTokenPanel', () => {
  test('no token: the same Jev input as Global Settings, with no Cancel and no type picker', async () => {
    render(<JevTokenPanel userId="user-1" />)
    const input = await within(panel()).findByPlaceholderText('apikey_...')
    expect(input).toHaveAttribute('type', 'password')
    expect(within(panel()).getByText('Not added')).toBeInTheDocument()
    expect(within(panel()).getByRole('link', { name: /Get API key/ }))
      .toHaveAttribute('href', 'https://console.typesafe.ai/keys')
    expect(within(panel()).getByRole('button', { name: 'Test Connection' })).toBeInTheDocument()
    expect(within(panel()).queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
    expect(screen.queryByText('Choose Provider Type')).not.toBeInTheDocument()
  })

  test('a token: only a confirmation, with the masked key and the pinned model, and no input', async () => {
    providers = [JEV_ROW]
    render(<JevTokenPanel userId="user-1" />)
    const ok = await screen.findByTestId('jev-token-connected')
    expect(ok).toHaveTextContent('Your Jev token is included')
    expect(ok).toHaveTextContent('••••••••c0de')
    expect(ok).toHaveTextContent('jev-1.13.0')
    expect(within(panel()).getByText('Connected')).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('apikey_...')).not.toBeInTheDocument()
    // Manage opens Global Settings in a new tab, so unsaved project edits survive.
    const manage = within(ok).getByRole('link', { name: /Manage/ })
    expect(manage).toHaveAttribute('href', '/settings?tab=providers')
    expect(manage).toHaveAttribute('target', '_blank')
  })

  test('a failed lookup says so with a Retry, and never offers the input as if there were no token', async () => {
    providersStatus = 500
    render(<JevTokenPanel userId="user-1" />)
    await within(panel()).findByText(/Couldn.t check your Jev token/)
    expect(screen.queryByPlaceholderText('apikey_...')).not.toBeInTheDocument()
    providersStatus = 200
    providers = [JEV_ROW]
    fireEvent.click(within(panel()).getByRole('button', { name: /Retry/ }))
    await screen.findByTestId('jev-token-connected')
  })

  test('saving the token here turns the panel into the confirmation AND reaches the other lookups on the page', async () => {
    render(<JevTokenPanel userId="user-1" />)
    const other = renderHook(() => useHasJevProvider())      // e.g. the FFuf section's engine switch
    await waitFor(() => expect(other.result.current).toBe('no'))

    fireEvent.change(await screen.findByPlaceholderText('apikey_...'), { target: { value: 'apikey_abc_def' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save token' }))

    await screen.findByTestId('jev-token-connected')
    await waitFor(() => expect(other.result.current).toBe('yes'))
    const post = fetchMock.mock.calls.find(([u, i]) => u === '/api/users/user-1/llm-providers' && (i as RequestInit)?.method === 'POST')!
    expect(JSON.parse((post[1] as RequestInit).body as string)).toEqual({
      providerType: 'jev', name: 'TypeSafe AI (Jev)', apiKey: 'apikey_abc_def', modelIdentifier: 'jev-1.13.0',
    })
  })
})
