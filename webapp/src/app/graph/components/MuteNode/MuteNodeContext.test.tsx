/**
 * The Mute button every graph table and the node drawer share.
 *
 * What is pinned: it only appears inside the graph page's provider; it refuses
 * asset nodes and saved versions up front, with the reason on hover; a finding
 * is muted by its stored id when the row has one and by its graph id
 * otherwise; and a mute refreshes the whole page, not just the row it came from.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { useEffect, type ReactNode } from 'react'

const mockDangerConfirm = vi.fn()
const mockAlertError = vi.fn()
const mockAddToast = vi.fn()

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: mockAlertError, dangerConfirm: mockDangerConfirm }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), addToast: mockAddToast }),
}))

import {
  GraphNodeMuteButton,
  MuteNodeButton,
  MuteNodeProvider,
  useMuteNodeContext,
} from './index'
import type { GraphNode } from '../../types'

function ok(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>
const onGraphChanged = vi.fn()
const onViewMuted = vi.fn()
let epochs: number[] = []

/** Records every epoch the provider publishes, which is what tables refetch on. */
function EpochProbe() {
  const { epoch } = useMuteNodeContext()
  useEffect(() => { epochs.push(epoch) }, [epoch])
  return null
}

function Page({ children, readOnly = false }: { children: ReactNode; readOnly?: boolean }) {
  return (
    <MuteNodeProvider
      projectId="p1" readOnly={readOnly}
      onViewMuted={onViewMuted} onGraphChanged={onGraphChanged}
    >
      <EpochProbe />
      {children}
    </MuteNodeProvider>
  )
}

function sent(): { url: string; body: Record<string, unknown> } {
  const [url, init] = fetchMock.mock.calls[0]
  return { url, body: JSON.parse((init as RequestInit).body as string) }
}

beforeEach(() => {
  epochs = []
  fetchMock = vi.fn(() => ok({ muted: true, label: 'Vulnerability' }))
  vi.stubGlobal('fetch', fetchMock)
  mockDangerConfirm.mockResolvedValue(true)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('where the button appears', () => {
  test('nothing renders outside the graph page provider', () => {
    const { container } = render(<MuteNodeButton name="x" graphId="12" label="Vulnerability" />)
    expect(container.innerHTML).toBe('')
  })

  test('a row that is not one node (no id at all) gets no button', () => {
    const { container } = render(<Page><MuteNodeButton name="ASN 1" graphId={null} /></Page>)
    expect(container.querySelector('button')).toBeNull()
  })

  test('an asset row is disabled and says why on hover', () => {
    render(<Page><MuteNodeButton name="example.test" graphId="7" label="Domain" /></Page>)
    const button = screen.getByRole('button', { name: /Mute/ })
    expect(button).toBeDisabled()
    expect(button.getAttribute('title')).toMatch(/^Domain nodes cannot be muted/)
  })

  test('a saved version is read-only, so even a finding is disabled', () => {
    render(<Page readOnly><MuteNodeButton name="v" graphId="7" label="Vulnerability" /></Page>)
    const button = screen.getByRole('button', { name: /Mute/ })
    expect(button).toBeDisabled()
    expect(button.getAttribute('title')).toMatch(/saved version/)
  })

  test('a finding is enabled with the Priority Board wording', () => {
    render(<Page><MuteNodeButton name="v" graphId="7" label="Secret" /></Page>)
    const button = screen.getByRole('button', { name: /Mute/ })
    expect(button).toBeEnabled()
    expect(button.getAttribute('title')).toBe(
      'Hide this finding from the graph, reports and the AI agent')
  })
})

describe('what a click does', () => {
  test('a row with a stored id goes through the Priority Board route', async () => {
    render(<Page><MuteNodeButton name="XSS" graphId="7" nodeId="vuln-1" label="Vulnerability" /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    expect(sent()).toEqual({
      url: '/api/triage/mute', body: { projectId: 'p1', nodeId: 'vuln-1' },
    })
    expect(mockDangerConfirm.mock.calls[0][0]).toMatch(/^Mute "XSS"\?/)
  })

  test('a row with only a graph id is resolved server-side', async () => {
    render(<Page><MuteNodeButton name="WCP" graphId="42" label="Vulnerability" /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    expect(sent()).toEqual({
      url: '/api/triage/mute-by-graph-id', body: { projectId: 'p1', graphId: '42' },
    })
  })

  test('declining the confirm sends nothing', async () => {
    mockDangerConfirm.mockResolvedValue(false)
    render(<Page><MuteNodeButton name="v" graphId="7" label="Vulnerability" /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockDangerConfirm).toHaveBeenCalled())
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('a mute refreshes the graph and every table, and offers the muted list', async () => {
    const onMuted = vi.fn()
    render(<Page><MuteNodeButton name="v" graphId="7" label="Vulnerability" onMuted={onMuted} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockAddToast).toHaveBeenCalled())
    expect(onGraphChanged).toHaveBeenCalledOnce()
    expect(onMuted).toHaveBeenCalledOnce()
    expect(epochs).toEqual([0, 1])
    const toast = mockAddToast.mock.calls[0][0]
    expect(toast.message).toBe('Finding muted. It is now hidden from the agent.')
    toast.action.onClick()
    expect(onViewMuted).toHaveBeenCalledOnce()
  })

  test('a node gone since the table loaded reloads the page and says so', async () => {
    fetchMock.mockImplementation(() => ok({ error: 'gone' }, 409))
    const onMuted = vi.fn()
    render(<Page><MuteNodeButton name="v" graphId="7" label="Vulnerability" onMuted={onMuted} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockAlertError).toHaveBeenCalled())
    expect(mockAlertError.mock.calls[0][0]).toMatch(/changed while the page was open/)
    expect(onGraphChanged).toHaveBeenCalledOnce()
    expect(onMuted).not.toHaveBeenCalled()
    expect(mockAddToast).not.toHaveBeenCalled()
  })

  test('a mute refused during a version activation says so, and does not reload the page', async () => {
    // The route's activation 409 is not a stale node: reloading would not
    // help, and "this finding changed" would send the person looking for it.
    fetchMock.mockImplementation(() => ok({
      error: 'A version activation is in progress for this project.', activationInProgress: true,
    }, 409))
    const onMuted = vi.fn()
    render(<Page><MuteNodeButton name="v" graphId="7" label="Vulnerability" onMuted={onMuted} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockAlertError).toHaveBeenCalled())
    expect(mockAlertError.mock.calls[0][0]).toBe('A version activation is in progress for this project.')
    expect(onGraphChanged).not.toHaveBeenCalled()
    expect(onMuted).not.toHaveBeenCalled()
  })

  test('a finding already muted is not announced as this person\'s mute', async () => {
    fetchMock.mockImplementation(() => ok({ muted: true, already: true, label: 'Vulnerability' }))
    render(<Page><MuteNodeButton name="v" graphId="7" label="Vulnerability" /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockAddToast).toHaveBeenCalled())
    expect(mockAddToast.mock.calls[0][0].message).toBe('This finding was already muted, so it was left as it was.')
    // The view was stale, so it is refreshed all the same.
    expect(onGraphChanged).toHaveBeenCalledOnce()
  })

  test('a server refusal is shown as the server worded it', async () => {
    fetchMock.mockImplementation(() => ok({ error: 'IP nodes cannot be muted.' }, 422))
    render(<Page><MuteNodeButton name="10.0.0.1:443" graphId="7" /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(mockAlertError).toHaveBeenCalled())
    expect(mockAlertError.mock.calls[0][0]).toBe('IP nodes cannot be muted.')
    expect(onGraphChanged).not.toHaveBeenCalled()
  })

  test('the click does not reach the row, which may select or expand on click', async () => {
    const onRowClick = vi.fn()
    render(
      <Page>
        <table><tbody><tr onClick={onRowClick}><td>
          <MuteNodeButton name="v" graphId="7" label="Vulnerability" />
        </td></tr></tbody></table>
      </Page>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(onRowClick).not.toHaveBeenCalled()
  })
})

describe('GraphNodeMuteButton', () => {
  const node = (type: string, properties: Record<string, unknown>): GraphNode =>
    ({ id: '99', name: 'n', type, properties })

  test('a finding is muted by its stored id', async () => {
    render(<Page><GraphNodeMuteButton node={node('Vulnerability', { id: 'v-1' })} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    expect(sent().body).toEqual({ projectId: 'p1', nodeId: 'v-1' })
  })

  test('MalPackageFinding is muted by its finding_id', async () => {
    render(<Page><GraphNodeMuteButton node={node('MalPackageFinding', { finding_id: 'mf-1' })} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    expect(sent().body).toEqual({ projectId: 'p1', nodeId: 'mf-1' })
  })

  test('a finding with no stored id falls back to its graph id', async () => {
    render(<Page><GraphNodeMuteButton node={node('Secret', {})} /></Page>)
    fireEvent.click(screen.getByRole('button', { name: /Mute/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    expect(sent()).toEqual({
      url: '/api/triage/mute-by-graph-id', body: { projectId: 'p1', graphId: '99' },
    })
  })

  test('an asset node is disabled', () => {
    render(<Page><GraphNodeMuteButton node={node('IP', { id: 'ip-1' })} /></Page>)
    expect(screen.getByRole('button', { name: /Mute/ })).toBeDisabled()
  })
})
