import { describe, it, expect, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { usePendingNodeQuery } from './usePendingNodeQuery'
import type { PendingNodeQuery } from '../types'

const query = (token: number): PendingNodeQuery => ({
  token,
  nodeLabel: 'CVE: CVE-2000-0001',
  context: '## Node',
  request: 'Assess it',
})

type Props = { pendingNodeQuery: PendingNodeQuery | null; isConnected: boolean }

function setup(initial: Props) {
  const send = vi.fn()
  const onConsumed = vi.fn()
  const onArmed = vi.fn()
  const hook = renderHook((p: Props) => usePendingNodeQuery({ ...p, send, onConsumed, onArmed }), {
    initialProps: initial,
  })
  return { ...hook, send, onConsumed, onArmed }
}

describe('usePendingNodeQuery', () => {
  it('does not send on the stale "connected" of the previous session', () => {
    const { send, onArmed } = setup({ pendingNodeQuery: query(1), isConnected: true })
    expect(send).not.toHaveBeenCalled()
    expect(onArmed).toHaveBeenCalledTimes(1)
  })

  it('sends once after the reconnect (disconnect, then connect)', () => {
    const q = query(1)
    const { rerender, send, onConsumed } = setup({ pendingNodeQuery: q, isConnected: true })
    rerender({ pendingNodeQuery: q, isConnected: false })
    expect(send).not.toHaveBeenCalled()
    rerender({ pendingNodeQuery: q, isConnected: true })
    expect(send).toHaveBeenCalledTimes(1)
    expect(send).toHaveBeenCalledWith(q)
    expect(onConsumed).toHaveBeenCalledTimes(1)
  })

  it('sends when the drawer opens from closed (socket starts disconnected)', () => {
    const q = query(1)
    const { rerender, send } = setup({ pendingNodeQuery: q, isConnected: false })
    rerender({ pendingNodeQuery: q, isConnected: true })
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('never sends the same request twice, even across a later reconnect', () => {
    const q = query(1)
    const { rerender, send } = setup({ pendingNodeQuery: q, isConnected: false })
    rerender({ pendingNodeQuery: q, isConnected: true })
    rerender({ pendingNodeQuery: q, isConnected: true })
    rerender({ pendingNodeQuery: q, isConnected: false })
    rerender({ pendingNodeQuery: q, isConnected: true })
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('a new request waits for its own reconnect', () => {
    const { rerender, send, onArmed } = setup({ pendingNodeQuery: query(1), isConnected: false })
    rerender({ pendingNodeQuery: query(1), isConnected: true })
    expect(send).toHaveBeenCalledTimes(1)

    rerender({ pendingNodeQuery: null, isConnected: true })
    rerender({ pendingNodeQuery: query(2), isConnected: true })
    expect(send).toHaveBeenCalledTimes(1)
    expect(onArmed).toHaveBeenCalledTimes(2)
    rerender({ pendingNodeQuery: query(2), isConnected: false })
    rerender({ pendingNodeQuery: query(2), isConnected: true })
    expect(send).toHaveBeenCalledTimes(2)
    expect(send).toHaveBeenLastCalledWith(query(2))
  })

  it('does nothing without a pending request', () => {
    const { rerender, send, onArmed } = setup({ pendingNodeQuery: null, isConnected: false })
    rerender({ pendingNodeQuery: null, isConnected: true })
    expect(send).not.toHaveBeenCalled()
    expect(onArmed).not.toHaveBeenCalled()
  })
})
