'use client'

/**
 * The mute action, for every place a node can be muted from: the Priority
 * Board, the node drawer and the graph tables. One implementation, so the
 * confirm, the stale-node handling and the toast are the same everywhere.
 *
 * Mute is deliberately a two-step action with a confirm: it changes what the AI
 * agent can see for the whole project, so it is not a click to make by accident.
 */
import { useCallback, useState } from 'react'
import { useAlertModal, useToast } from '@/components/ui'

/** A node to mute, by exactly one of its two keys. */
export interface MuteTarget {
  /** Shown in the confirm. */
  name: string
  /** The finding's stored key (see `muteKey`): what the Priority Board and the
   *  drawer have. */
  nodeId?: string
  /** Neo4j's internal id, the only key a graph table row carries; resolved to
   *  the stored key server-side. */
  graphId?: string
}

export interface MuteCallbacks {
  /** The graph write succeeded; drop the node from the view. */
  onMuted?: () => void
  /** The node changed under the page (rescan, version activation); reload. */
  onStale?: () => void | Promise<void>
}

export function useMuteNode(
  projectId: string | null | undefined,
  /** Switch the page to Muted Nodes; offered on the toast after a mute. */
  onViewMuted?: () => void,
) {
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()
  /** The key of the node being muted, for the button's spinner. */
  const [mutingKey, setMutingKey] = useState<string | null>(null)

  const mute = useCallback(
    async (target: MuteTarget, callbacks: MuteCallbacks = {}) => {
      const key = target.nodeId ?? target.graphId
      if (!projectId || !key) return
      const ok = await dangerConfirm(
        `Mute "${target.name || key}"?\n\n` +
          'It will be hidden from the graph, from reports, and from the AI agent, ' +
          'which will no longer be able to see or reason about it. You can restore ' +
          'it from Muted Nodes (in the All Nodes menu) at any time.',
        'Mute finding',
        { confirmLabel: 'Mute' },
      )
      if (!ok) return

      setMutingKey(key)
      try {
        const res = await fetch(
          target.nodeId ? '/api/triage/mute' : '/api/triage/mute-by-graph-id',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(target.nodeId
              ? { projectId, nodeId: target.nodeId }
              : { projectId, graphId: target.graphId }),
          },
        )
        const body = await res.json().catch(() => ({}))
        // A 409 that says so is the route refusing while a version activation
        // holds the graph: the node is fine, and reloading would not help.
        if (res.status === 409 && !body.activationInProgress) {
          // A rescan or a version activation replaced the node this view is
          // holding an id for. Silently doing nothing looked like success.
          await callbacks.onStale?.()
          throw new Error(
            'This finding changed while the page was open, so it was not muted. ' +
            'The list has been reloaded; try again.'
          )
        }
        if (!res.ok || !body.muted) {
          throw new Error(body.error || 'The finding could not be muted.')
        }
        callbacks.onMuted?.()
        toast.addToast({
          type: 'success',
          // Muted meanwhile by a rule, an agent or another tab: left exactly
          // as it was, so it is not this person's mute.
          message: body.already
            ? 'This finding was already muted, so it was left as it was.'
            : 'Finding muted. It is now hidden from the agent.',
          ...(onViewMuted ? { action: { label: 'View muted', onClick: onViewMuted } } : {}),
        })
      } catch (e) {
        await alertError(e instanceof Error ? e.message : 'Mute failed', 'Mute finding')
      } finally {
        setMutingKey(null)
      }
    },
    [projectId, dangerConfirm, alertError, toast, onViewMuted],
  )

  return { mute, mutingKey }
}
