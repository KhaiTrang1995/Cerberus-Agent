/**
 * The triage socket's terminal states and the publishing refusal.
 *
 * Run: npx vitest run src/hooks/useCypherFixTriageWS.test.tsx
 *
 * Two defects pinned here:
 *  - U4: a `stopped` message set the status back to `connected`, so nothing
 *    downstream could tell a stopped run from an idle socket: the board never
 *    reloaded on it and the progress panel had no way to close.
 *  - A Stop the agent refuses because the run is publishing arrives as an
 *    `error` with `code: 'publishing'`. It is not a failed run, and treating
 *    it as one flipped a still-running run to "failed".
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/cypherfix-triage' }))

import { useCypherFixTriageWS } from './useCypherFixTriageWS'

class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 1
  sent: Array<{ type: string }> = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null

  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  send(data: string) { this.sent.push(JSON.parse(data)) }
  close() { /* the hook detaches handlers before calling this */ }
  receive(msg: unknown) { this.onmessage?.({ data: JSON.stringify(msg) } as MessageEvent) }
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => ({ ticket: 'tkt' }),
  }) as unknown as Response))
})
afterEach(() => { vi.unstubAllGlobals() })

async function connectedRun() {
  const hook = renderHook(() => useCypherFixTriageWS({
    userId: 'u1', projectId: 'p1', autoConnect: true,
  }))
  await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
  const sock = FakeSocket.instances[0]
  act(() => { sock.onopen?.() })
  act(() => { sock.receive({ type: 'connected', session_id: 's1' }) })
  act(() => { sock.receive({ type: 'triage_phase', payload: { phase: 'reviewing', description: '', progress: 50 } }) })
  expect(hook.result.current.status).toBe('running')
  return { ...hook, sock }
}

describe('useCypherFixTriageWS terminal states', () => {
  test('a stopped run is `stopped`, not `connected` (U4)', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'stopped' }) })
    expect(result.current.status).toBe('stopped')
    expect(result.current.error).toBeNull()
    unmount()
  })

  test('a Stop refused while publishing leaves the run running and says why', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'triage_phase', payload: { phase: 'publishing', description: '', progress: 92 } }) })
    act(() => {
      sock.receive({ type: 'error', payload: {
        message: 'The run is publishing and will finish in moments.', recoverable: true, code: 'publishing',
      } })
    })
    expect(result.current.status).toBe('running')
    expect(result.current.error).toBeNull()
    expect(result.current.notice).toBe('The run is publishing and will finish in moments.')

    act(() => { sock.receive({ type: 'triage_complete', payload: { total_remediations: 1, by_severity: {}, by_type: {}, summary: '' } }) })
    expect(result.current.status).toBe('completed')
    expect(result.current.notice).toBeNull()
    unmount()
  })

  test('any other error still fails the run', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'error', payload: { message: 'Triage failed', code: 'internal_error' } }) })
    expect(result.current.status).toBe('error')
    expect(result.current.error).toBe('Triage failed')
    expect(result.current.notice).toBeNull()
    unmount()
  })

  test('starting again after a stop leaves the stopped state at once', async () => {
    const { result, sock, unmount } = await connectedRun()
    act(() => { sock.receive({ type: 'stopped' }) })
    act(() => { result.current.startTriage() })
    expect(result.current.status).toBe('connected')
    expect(sock.sent.map(m => m.type)).toContain('start_triage')
    unmount()
  })
})
