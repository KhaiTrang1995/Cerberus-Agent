/**
 * The node drawer's Mute button: immediately left of delete, hidden on a saved
 * version like delete is, and the same confirm-then-mute the Priority Board
 * runs. Real alert and toast providers, so the confirm is the real modal.
 */
import React from 'react'
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { MuteNodeProvider } from '../MuteNode'
import { NodeDrawer } from './NodeDrawer'
import type { GraphNode } from '../../types'

const finding: GraphNode = {
  id: '11', type: 'Vulnerability', name: 'Reflected XSS',
  properties: { id: 'vuln-xss-1', severity: 'high' },
}
const asset: GraphNode = { id: '12', type: 'IP', name: '10.0.0.5', properties: { id: 'ip-1' } }

const onGraphChanged = vi.fn()

function renderDrawer(
  props: Partial<React.ComponentProps<typeof NodeDrawer>> = {},
  readOnly = false,
) {
  return render(
    <AlertProvider>
      <ToastProvider>
        <MuteNodeProvider projectId="p1" readOnly={readOnly} onGraphChanged={onGraphChanged}>
          <NodeDrawer node={finding} isOpen onClose={() => {}} onDeleteNode={vi.fn()} {...props} />
        </MuteNodeProvider>
      </ToastProvider>
    </AlertProvider>,
  )
}

/** The drawer's own Mute button; the confirm modal adds a second one. */
function drawerMute(): HTMLElement {
  const row = screen.getByRole('heading', { name: 'Basic Info' }).parentElement!
  return within(row).getByRole('button', { name: /Mute/ })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn(() => Promise.resolve({
    ok: true, status: 200, json: () => Promise.resolve({ muted: true, label: 'Vulnerability' }),
  }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('NodeDrawer Mute button', () => {
  it('sits immediately left of the delete button', () => {
    renderDrawer()
    const row = screen.getByRole('heading', { name: 'Basic Info' }).parentElement!
    const buttons = Array.from(row.querySelectorAll('button'))
    const del = screen.getByLabelText('Delete node')
    expect(buttons.indexOf(drawerMute())).toBe(buttons.indexOf(del) - 1)
  })

  it('is hidden on a saved version, like delete', () => {
    renderDrawer({ onDeleteNode: undefined }, true)
    const row = screen.getByRole('heading', { name: 'Basic Info' }).parentElement!
    expect(within(row).queryByRole('button', { name: /Mute/ })).toBeNull()
  })

  it('is disabled on an asset node, with the reason on hover', () => {
    renderDrawer({ node: asset })
    expect(drawerMute()).toBeDisabled()
    expect(drawerMute().getAttribute('title')).toMatch(/^IP nodes cannot be muted/)
  })

  it('confirms, mutes by the stored id, refreshes the graph and closes', async () => {
    const onClose = vi.fn()
    renderDrawer({ onClose })
    fireEvent.click(drawerMute())

    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('Mute "Reflected XSS"?')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Mute' }))

    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/triage/mute')
    expect(JSON.parse((init as RequestInit).body as string))
      .toEqual({ projectId: 'p1', nodeId: 'vuln-xss-1' })
    expect(onGraphChanged).toHaveBeenCalledOnce()
    expect(await screen.findByText('Finding muted. It is now hidden from the agent.'))
      .toBeInTheDocument()
  })
})
