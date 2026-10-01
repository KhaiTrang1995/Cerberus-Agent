'use client'

import { useEffect, useState } from 'react'
import { useProject } from '@/providers/ProjectProvider'

export type JevProviderStatus = 'loading' | 'yes' | 'no' | 'error'

/**
 * Whether the acting user has a TypeSafe Jev token saved.
 *
 * A failed fetch is 'error', never 'no': telling a user "you have no token" when
 * the lookup actually failed would push them to re-add a token they already have.
 * Don't copy ShodanSection's hook, which reports a failed fetch as "no key".
 *
 * This is a convenience signal for the form only; the server
 * (validateJevEngineChange) is the authority on whether a switch-on is allowed.
 */
export function useHasJevProvider(): JevProviderStatus {
  const { userId } = useProject()
  const [status, setStatus] = useState<JevProviderStatus>('loading')

  useEffect(() => {
    if (!userId) {
      setStatus('loading')
      return
    }
    let cancelled = false
    setStatus('loading')
    ;(async () => {
      try {
        const resp = await fetch(`/api/users/${userId}/llm-providers`)
        if (!resp.ok) {
          if (!cancelled) setStatus('error')
          return
        }
        const rows = await resp.json()
        if (cancelled) return
        // A 200 that is not a list (an error payload, a proxy page) tells us
        // nothing about the account, so it is a failed lookup, not "no token".
        if (!Array.isArray(rows)) {
          setStatus('error')
          return
        }
        setStatus(rows.some((r: { providerType?: string }) => r?.providerType === 'jev') ? 'yes' : 'no')
      } catch {
        if (!cancelled) setStatus('error')
      }
    })()
    return () => { cancelled = true }
  }, [userId])

  return status
}
