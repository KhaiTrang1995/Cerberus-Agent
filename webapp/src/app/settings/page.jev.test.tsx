/**
 * Global Settings -> LLM Providers -> the TypeSafe AI (Jev) section.
 *
 * Jev is a non-chat provider: it lives in its own section, never in the chat
 * provider list, and never counts as a configured LLM. A providers fetch that
 * fails must say so instead of reading as "no token".
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams('tab=providers'),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/settings',
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => ({ isAdmin: false }) }))

const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))

const SettingsPage = (await import('./page')).default

const CHAT = { id: 'p1', userId: 'user-1', providerType: 'anthropic', name: 'My Anthropic', apiKey: '••••1234' }
const JEV = {
  id: 'jev1', userId: 'user-1', providerType: 'jev', name: 'TypeSafe AI (Jev)',
  apiKey: '••••••••c0de', modelIdentifier: 'jev-1.13.0', baseUrl: '',
}

let providersAnswer: () => Promise<{ status: number; body: unknown }>
let postAnswer: { status: number; body: unknown }
const fetchMock = vi.fn()

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body }
}

beforeEach(() => {
  alertSpies.confirm.mockClear()
  providersAnswer = async () => ({ status: 200, body: [CHAT] })
  postAnswer = { status: 201, body: JEV }
  fetchMock.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/users/user-1/llm-providers' && method === 'GET') {
      const a = await providersAnswer()
      return json(a.status, a.body)
    }
    if (url === '/api/users/user-1/llm-providers' && method === 'POST') return json(postAnswer.status, postAnswer.body)
    if (url.startsWith('/api/users/user-1/llm-providers/') && method === 'DELETE') return json(200, { success: true })
    if (url === '/api/models') return json(200, {})
    if (url === '/api/agent/health') return json(200, { status: 'healthy' })
    if (url === '/api/users/user-1/settings') return json(200, { featureModels: {}, rotationConfigs: {} })
    if (url === '/api/users/user-1/settings/api-usage') {
      return json(200, { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] })
    }
    if (/\/(attack-skills|chat-skills|tradecraft-resources)$/.test(url) || url === '/api/projects') return json(200, [])
    return json(404, {})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage() {
  return render(<ToastProvider><SettingsPage /></ToastProvider>)
}

const jevSection = () => screen.findByRole('region', { name: 'TypeSafe AI (Jev)' })

describe('TypeSafe AI (Jev) section', () => {
  test('loading: the section shows the loading state, not "no token"', async () => {
    providersAnswer = () => new Promise(() => {})
    renderPage()
    const section = await jevSection()
    expect(within(section).getByText('Loading...')).toBeInTheDocument()
    expect(within(section).queryByRole('button', { name: /Add token/ })).not.toBeInTheDocument()
  })

  test('a failed fetch says so with a Retry, in the section and in the list', async () => {
    providersAnswer = async () => ({ status: 500, body: { error: 'boom' } })
    renderPage()
    const section = await jevSection()
    await within(section).findByText("Couldn't load your providers.")
    expect(within(section).queryByRole('button', { name: /Add token/ })).not.toBeInTheDocument()
    expect(screen.queryByText('No providers configured. Add one to get started.')).not.toBeInTheDocument()

    providersAnswer = async () => ({ status: 200, body: [CHAT] })
    fireEvent.click(within(section).getByRole('button', { name: /Retry/ }))
    await within(section).findByRole('button', { name: /Add token/ })
  })

  test('a fetch that throws is an error too', async () => {
    providersAnswer = async () => { throw new TypeError('fetch failed') }
    renderPage()
    const section = await jevSection()
    await within(section).findByText("Couldn't load your providers.")
  })

  test('no Jev row: Add token and the key link; Add token opens the locked form', async () => {
    renderPage()
    const section = await jevSection()
    const add = await within(section).findByRole('button', { name: /Add token/ })
    expect(within(section).getByRole('link', { name: /Get an API key/ }))
      .toHaveAttribute('href', 'https://console.typesafe.ai/keys')

    fireEvent.click(add)
    expect(await within(section).findByPlaceholderText('apikey_...')).toBeInTheDocument()
    expect(screen.queryByText('Choose Provider Type')).not.toBeInTheDocument()
    // The rest of the tab steps aside while the form is open.
    expect(screen.queryByText('My Anthropic')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add Provider/ })).not.toBeInTheDocument()
  })

  test('a Jev row: one card in its own section, never in the chat list', async () => {
    providersAnswer = async () => ({ status: 200, body: [CHAT, JEV] })
    renderPage()
    const section = await jevSection()
    await within(section).findByTestId('jev-masked-key')
    expect(within(section).getByTestId('jev-masked-key')).toHaveTextContent('••••••••c0de')
    expect(screen.getAllByText('TypeSafe AI (Jev)').filter(el => el.closest('[class*="providerCard"]'))).toHaveLength(1)
    expect(within(section).queryByText('My Anthropic')).not.toBeInTheDocument()
    expect(screen.getByText('My Anthropic')).toBeInTheDocument()
  })

  test('a Jev-only user has no chat provider: empty list, and Models by feature asks for one', async () => {
    providersAnswer = async () => ({ status: 200, body: [JEV] })
    renderPage()
    await screen.findByText('No providers configured. Add one to get started.')
    expect(await screen.findByText('Add an LLM provider above to choose models for these features')).toBeInTheDocument()
  })

  test('Delete asks with the Jev wording, then deletes that row', async () => {
    providersAnswer = async () => ({ status: 200, body: [CHAT, JEV] })
    renderPage()
    const section = await jevSection()
    fireEvent.click(await within(section).findByRole('button', { name: 'Delete Jev token' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([u, i]) =>
      u === '/api/users/user-1/llm-providers/jev1' && (i as RequestInit)?.method === 'DELETE')).toBe(true))
    expect((alertSpies.confirm.mock.calls[0] as unknown[])[0]).toMatch(/static fallback/)
  })

  test('a refused save shows the server message from the form', async () => {
    postAnswer = { status: 409, body: { error: 'A TypeSafe AI (Jev) token is already saved. Edit it instead of adding another.' } }
    renderPage()
    const section = await jevSection()
    fireEvent.click(await within(section).findByRole('button', { name: /Add token/ }))
    fireEvent.change(await within(section).findByPlaceholderText('apikey_...'), { target: { value: 'apikey_a_b' } })
    fireEvent.click(within(section).getByRole('button', { name: 'Save Provider' }))
    expect(await screen.findByText(/already saved/)).toBeInTheDocument()
  })
})
