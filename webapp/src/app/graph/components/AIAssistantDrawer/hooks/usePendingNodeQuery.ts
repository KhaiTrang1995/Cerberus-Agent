import { useEffect, useRef } from 'react'
import type { PendingNodeQuery } from '../types'

interface PendingNodeQueryDeps {
  pendingNodeQuery: PendingNodeQuery | null | undefined
  isConnected: boolean
  send: (q: PendingNodeQuery) => void
  onConsumed?: () => void
  // Called once when a new request arrives, before it is sent.
  onArmed?: () => void
}

/**
 * Sends a node-scoped first message once the FRESH session's socket is up.
 *
 * The page points sessionId at a new session and hands over the request. Right
 * after that switch `isConnected` can still be true for the OLD socket for one
 * render (the socket hook's setStatus is async), and sending then would be
 * dropped by the auth guard or land on the previous session. So a request is
 * only sent after a disconnect has been observed since it arrived; the new
 * session id always forces a reconnect, so that disconnect is guaranteed.
 * Each request is sent at most once, keyed by its token.
 */
export function usePendingNodeQuery({ pendingNodeQuery, isConnected, send, onConsumed, onArmed }: PendingNodeQueryDeps) {
  const armedTokenRef = useRef<number | null>(null)
  const sentTokenRef = useRef<number | null>(null)
  const sawDisconnectRef = useRef(false)

  useEffect(() => {
    if (!pendingNodeQuery) return
    if (sentTokenRef.current === pendingNodeQuery.token) return
    if (armedTokenRef.current !== pendingNodeQuery.token) {
      armedTokenRef.current = pendingNodeQuery.token
      sawDisconnectRef.current = false
      onArmed?.()
    }
    if (!isConnected) {
      sawDisconnectRef.current = true
      return
    }
    if (!sawDisconnectRef.current) return
    sentTokenRef.current = pendingNodeQuery.token
    send(pendingNodeQuery)
    onConsumed?.()
  }, [pendingNodeQuery, isConnected, send, onConsumed, onArmed])
}
