'use client'

/**
 * What every Mute button on the graph page shares, provided once by the page
 * so the node drawer and ~20 tables need no extra props.
 *
 * `epoch` is how a table learns a mute happened: muted nodes are filtered out
 * server-side by every table route (`notMuted`), so refetching on a new epoch
 * is what removes the row.
 */
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { muteableLabel, muteKey } from '@/lib/muteTarget'
import type { GraphNode } from '../../types'
import { formatNodeId } from '../RedZoneTables/nodeId'
import { MuteButton } from './MuteButton'
import { useMuteNode } from './useMuteNode'

interface MuteNodeContextValue {
  projectId: string | null
  /** A saved version is a read-only snapshot, so nothing on it may be muted. */
  readOnly: boolean
  onViewMuted?: () => void
  /** Bumped after every mute and every stale-node reload. */
  epoch: number
  /** Refresh the graph and every table after a mute. */
  notifyMuted: () => void
}

const MuteNodeContext = createContext<MuteNodeContextValue>({
  projectId: null,
  readOnly: true,
  epoch: 0,
  notifyMuted: () => {},
})

interface MuteNodeProviderProps {
  projectId: string | null
  readOnly: boolean
  onViewMuted?: () => void
  /** Refetch the graph; the drawer, Node Inspector and All Nodes read from it. */
  onGraphChanged?: () => void
  children: ReactNode
}

export function MuteNodeProvider({
  projectId, readOnly, onViewMuted, onGraphChanged, children,
}: MuteNodeProviderProps) {
  const [epoch, setEpoch] = useState(0)
  const notifyMuted = useCallback(() => {
    setEpoch(e => e + 1)
    onGraphChanged?.()
  }, [onGraphChanged])
  const value = useMemo(
    () => ({ projectId, readOnly, onViewMuted, epoch, notifyMuted }),
    [projectId, readOnly, onViewMuted, epoch, notifyMuted],
  )
  return <MuteNodeContext.Provider value={value}>{children}</MuteNodeContext.Provider>
}

export function useMuteNodeContext(): MuteNodeContextValue {
  return useContext(MuteNodeContext)
}

/** Why a node cannot be muted, as the disabled button's tooltip. */
export function unmuteableReason(label: string): string {
  return `${label} nodes cannot be muted. Only findings can: an asset is context, ` +
    'and muting it would orphan the findings attached to it.'
}

const READ_ONLY_REASON =
  'You are viewing a saved version, which is read-only. Switch back to the ' +
  'active version to mute nodes.'

interface MuteNodeButtonProps {
  /** Names the node in the confirm. */
  name: string
  /** The node's graph id (a table's Node ID column, `GraphNode.id`). */
  graphId?: unknown
  /** The finding's stored key, when known; preferred over graphId because it
   *  survives an import or version activation. */
  nodeId?: string | null
  /** The node's label when known. An asset label disables the button up front
   *  instead of letting the server refuse after the confirm. */
  label?: string
  /** After the page has been told; the drawer closes itself here. */
  onMuted?: () => void
}

/**
 * The Mute button for one graph node, wired to the page's project and refresh.
 *
 * Renders nothing outside a `MuteNodeProvider` (a table embedded elsewhere) or
 * for a row that is not one node (an aggregate with no id).
 */
export function MuteNodeButton(props: MuteNodeButtonProps) {
  const { projectId } = useMuteNodeContext()
  if (!projectId || !(props.nodeId || formatNodeId(props.graphId))) return null
  return <ProvidedMuteButton {...props} />
}

/** Split out so the alert and toast hooks only run inside the page's providers. */
function ProvidedMuteButton({ name, graphId, nodeId, label, onMuted }: MuteNodeButtonProps) {
  const { projectId, readOnly, onViewMuted, notifyMuted } = useMuteNodeContext()
  const { mute, mutingKey } = useMuteNode(projectId, onViewMuted)
  const gid = formatNodeId(graphId)

  const reason = readOnly
    ? READ_ONLY_REASON
    : label && !muteableLabel([label]) ? unmuteableReason(label) : undefined

  return (
    <MuteButton
      busy={mutingKey !== null && mutingKey === (nodeId || gid)}
      disabled={!!reason}
      title={reason}
      onClick={() => void mute(
        nodeId ? { name, nodeId } : { name, graphId: gid ?? undefined },
        {
          onMuted: () => {
            notifyMuted()
            onMuted?.()
          },
          onStale: notifyMuted,
        },
      )}
    />
  )
}

/** `MuteNodeButton` for a graph node: the drawer, All Nodes, Node Inspector. */
export function GraphNodeMuteButton({ node, onMuted }: { node: GraphNode; onMuted?: () => void }) {
  const label = muteableLabel([node.type])
  return (
    <MuteNodeButton
      name={node.name}
      graphId={node.id}
      nodeId={label ? muteKey(label, node.properties ?? {}) : null}
      label={node.type}
      onMuted={onMuted}
    />
  )
}
