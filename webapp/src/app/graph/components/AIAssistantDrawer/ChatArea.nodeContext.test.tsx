import React, { createRef } from 'react'
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ChatArea } from './ChatArea'
import { wrapNodeContextQuery } from '@/lib/agentQueryEnvelope'
import type { Message } from './types'

afterEach(cleanup)

const userMsg = (content: string): Message => ({
  type: 'message', id: `m-${content.length}`, role: 'user', content, timestamp: new Date(),
})

function renderMessages(messages: Message[]) {
  return render(
    <ChatArea
      messagesContainerRef={createRef<HTMLDivElement>()}
      messagesEndRef={createRef<HTMLDivElement>()}
      checkIfAtBottom={() => true}
      chatItems={messages}
      groupedChatItems={messages.map(m => ({ type: 'message' as const, content: m }))}
      isLoading={false}
      todoList={[]}
      statusWord=""
      isConnected
      setInputValue={() => {}}
      missingApiKeys={new Set()}
      openApiKeyModal={() => {}}
      handleTimelineToolConfirmation={() => {}}
    />,
  )
}

describe('ChatArea node-context message', () => {
  it('shows the node label and request, with the context behind a disclosure', () => {
    const content = wrapNodeContextQuery('CVE: CVE-2000-0001', '## Properties\n- severity: MEDIUM', 'Is this exploitable?')
    const { container } = renderMessages([userMsg(content)])

    expect(screen.getByText('CVE: CVE-2000-0001')).toBeInTheDocument()
    expect(screen.getByText('Is this exploitable?')).toBeInTheDocument()
    expect(screen.getByText('Node context sent to the agent')).toBeInTheDocument()

    const details = container.querySelector('details')
    expect(details).not.toBeNull()
    expect(details!.open).toBe(false)
    expect(details!.querySelector('pre')!.textContent).toBe('## Properties\n- severity: MEDIUM')
    // The raw envelope markers never reach the rendered bubble.
    expect(container.textContent).not.toContain('[Graph Node Context')
    expect(container.textContent).not.toContain('[User Query]')
  })

  it('renders an ordinary user message unchanged', () => {
    const { container } = renderMessages([userMsg('scan example.test')])
    expect(screen.getByText('scan example.test')).toBeInTheDocument()
    expect(container.querySelector('details')).toBeNull()
  })

  it('does not treat an assistant message that quotes the envelope as node context', () => {
    const content = wrapNodeContextQuery('IP: 192.0.2.1', 'ctx', 'q')
    const assistant: Message = { ...userMsg(content), id: 'a1', role: 'assistant' }
    const { container } = renderMessages([assistant])
    expect(container.querySelector('details')).toBeNull()
  })
})
