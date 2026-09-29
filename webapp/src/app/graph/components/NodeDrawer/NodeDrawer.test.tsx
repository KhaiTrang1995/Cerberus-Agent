import React from 'react'
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { NodeDrawer } from './NodeDrawer'
import type { GraphData, GraphNode } from '../../types'

const cve: GraphNode = {
  id: '1', type: 'CVE', name: 'CVE-2000-0001',
  properties: { severity: 'MEDIUM', project_id: 'p-secret' },
}
const tech: GraphNode = { id: '2', type: 'Technology', name: 'nginx 1.0', properties: {} }
const graphData: GraphData = {
  projectId: 'p',
  nodes: [cve, tech],
  links: [{ source: '2', target: '1', type: 'HAS_VULNERABILITY' }],
}

function renderDrawer(props: Partial<React.ComponentProps<typeof NodeDrawer>> = {}) {
  return render(
    <AlertProvider>
      <ToastProvider>
        <NodeDrawer node={cve} isOpen onClose={() => {}} graphData={graphData} projectName="Lab" {...props} />
      </ToastProvider>
    </AlertProvider>,
  )
}

let writeText: ReturnType<typeof vi.fn>

beforeEach(() => {
  writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('NodeDrawer header actions', () => {
  it('shows copy and ask-agent buttons for a node', () => {
    renderDrawer({ onStartAgentSession: vi.fn() })
    expect(screen.getByLabelText('Copy node context')).toBeInTheDocument()
    expect(screen.getByLabelText('Ask agent about this node')).toBeInTheDocument()
  })

  it('sits on the Basic Info row, left of delete, sharing its button style', () => {
    renderDrawer({ onStartAgentSession: vi.fn(), onDeleteNode: vi.fn() })
    const copy = screen.getByLabelText('Copy node context')
    const ask = screen.getByLabelText('Ask agent about this node')
    const del = screen.getByLabelText('Delete node')

    const row = screen.getByRole('heading', { name: 'Basic Info' }).parentElement!
    const buttons: Element[] = Array.from(row.querySelectorAll('button'))
    expect(buttons.indexOf(copy)).toBeGreaterThanOrEqual(0)
    expect(buttons.indexOf(copy)).toBeLessThan(buttons.indexOf(ask))
    expect(buttons.indexOf(ask)).toBeLessThan(buttons.indexOf(del))

    // Not in the drawer's title bar any more (only its close button lives there).
    const titleBar = screen.getByRole('heading', { name: 'CVE: CVE-2000-0001' }).parentElement!
    expect(titleBar.contains(copy)).toBe(false)
    expect(titleBar.querySelectorAll('button')).toHaveLength(1)

    for (const b of [copy, ask, del]) expect(b.className).toContain('iconBtn')
  })

  it('shows the full name on hover only when the title is clipped', () => {
    renderDrawer()
    const heading = screen.getByRole('heading', { name: 'CVE: CVE-2000-0001' })
    const text = heading.querySelector('span')!
    // jsdom does no layout: fake the <h2> box's widths.
    const setWidths = (scroll: number, client: number) => {
      Object.defineProperty(heading, 'scrollWidth', { value: scroll, configurable: true })
      Object.defineProperty(heading, 'clientWidth', { value: client, configurable: true })
    }

    setWidths(200, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('')

    setWidths(420, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('CVE: CVE-2000-0001')

    setWidths(180, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('')
  })

  it('hides ask-agent when no session handler is given (past version)', () => {
    renderDrawer()
    expect(screen.getByLabelText('Copy node context')).toBeInTheDocument()
    expect(screen.queryByLabelText('Ask agent about this node')).toBeNull()
  })

  it('shows no node actions on a cluster list', () => {
    // jsdom has no Element.scrollTo; ClusterNodeList resets its scroll on mount.
    Object.defineProperty(Element.prototype, 'scrollTo', { value: () => {}, configurable: true })
    const cluster: GraphNode = {
      id: 'c', type: 'Subdomain', name: 'cluster', properties: {},
      isCluster: true, clusterChildType: 'Subdomain', clusterChildren: [tech],
    }
    renderDrawer({ node: cluster, onStartAgentSession: vi.fn() })
    expect(screen.queryByLabelText('Copy node context')).toBeNull()
    expect(screen.queryByLabelText('Ask agent about this node')).toBeNull()
  })

  it('copies the node context, relationships included, to the clipboard', async () => {
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const text = writeText.mock.calls[0][0] as string
    expect(text).toContain('Project: Lab')
    expect(text).toContain('- Type: CVE')
    expect(text).toContain('- (:Technology)-[:HAS_VULNERABILITY]->(this) x1:')
    expect(text).not.toContain('p-secret')
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('falls back to execCommand when the clipboard API is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
    const execCommand = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith('copy'))
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('falls back to execCommand when the Clipboard API rejects', async () => {
    writeText.mockRejectedValue(new Error('denied'))
    const execCommand = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith('copy'))
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('reports a clipboard failure instead of claiming success', async () => {
    writeText.mockRejectedValue(new Error('denied'))
    Object.defineProperty(document, 'execCommand', { value: vi.fn().mockReturnValue(false), configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    expect(await screen.findByText('Could not access the clipboard')).toBeInTheDocument()
  })
})

describe('NodeDrawer ask-agent modal', () => {
  it('starts a session with the typed request, the node context and its label', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))

    const start = screen.getByRole('button', { name: 'Start session' })
    expect(start).toBeDisabled()

    fireEvent.change(screen.getByLabelText('What should the agent do?'), {
      target: { value: '  Is this exploitable?  ' },
    })
    fireEvent.click(start)

    expect(onStart).toHaveBeenCalledTimes(1)
    const [request, context, label] = onStart.mock.calls[0]
    expect(request).toBe('Is this exploitable?')
    expect(context).toContain('- (:Technology)-[:HAS_VULNERABILITY]->(this) x1:')
    expect(label).toBe('CVE: CVE-2000-0001')
    expect(screen.queryByRole('button', { name: 'Start session' })).toBeNull()
  })

  it('submits on Ctrl+Enter and ignores a blank request', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))
    const textarea = screen.getByLabelText('What should the agent do?')

    fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true })
    expect(onStart).not.toHaveBeenCalled()

    fireEvent.change(textarea, { target: { value: 'Summarise' } })
    fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true })
    expect(onStart).toHaveBeenCalledWith('Summarise', expect.any(String), 'CVE: CVE-2000-0001')
  })

  it('cancel closes the modal without starting a session', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onStart).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('What should the agent do?')).toBeNull()
  })
})
