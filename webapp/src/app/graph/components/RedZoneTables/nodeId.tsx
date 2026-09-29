'use client'

/**
 * The `Node ID` column every graph table carries, pinned leftmost.
 *
 * The value is Neo4j's internal node id - `id(n)` in Cypher, the same number
 * the graph canvas uses as `GraphNode.id` and the node drawer shows as its
 * Graph ID. It is what makes a row addressable outside the table: a user can
 * hand it to an external agent, which looks the node up through the MCP
 * `query_graph` tool with `WHERE id(n) = <id>`.
 *
 * It is NOT a stable key. A rescan, an import or a version activation deletes
 * and recreates nodes, and Neo4j reuses freed ids, so an id is only good for
 * the graph as it is now. Anything persisted (triage verdicts, mutes) keys on
 * the stored `id` property instead; this column is for pointing, not storing.
 *
 * Routes project it as `toString(id(x)) AS nodeId`: a string, so the value
 * never passes through the driver's 64-bit Integer object or a JS float.
 */
import { useCallback, useEffect, useRef, useState, type MouseEvent } from 'react'
import { copyText } from '@/lib/copyText'
import type { RedZoneFilterColumn } from './useRedZoneFilters'
import styles from './RedZoneTableRow.module.css'

/** The row key every Red Zone / JS Recon API returns the id under. */
export const NODE_ID_KEY = 'nodeId'

/** Header text, shared so the column reads the same on every sheet. */
export const NODE_ID_HEADER = 'Node ID'

/** Filter + export descriptor. Prepend FIRST so it stays the leftmost column. */
export const NODE_ID_COLUMN: RedZoneFilterColumn = {
  key: NODE_ID_KEY,
  header: NODE_ID_HEADER,
}

/**
 * Prepends the Node ID column to a sheet's column list.
 *
 * Call this at module level on the existing `COLUMNS` constant rather than
 * inline in the component: `useRedZoneFilters` re-profiles every row when the
 * array identity changes.
 */
export function withNodeId(
  columns: readonly RedZoneFilterColumn[],
): RedZoneFilterColumn[] {
  return [NODE_ID_COLUMN, ...columns]
}

/**
 * Normalises whatever a row carries into the id's string form, or null.
 *
 * Accepts the driver's Integer object as well as a string or a number, so a
 * row built from a raw node (`GraphNode.id`) and one from a route projection
 * render and export identically.
 */
export function formatNodeId(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value === 'string') return /^\d+$/.test(value) ? value : null
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? String(value) : null
  if (typeof value === 'object' && 'low' in value && 'high' in value) {
    const { low, high } = value as { low: number; high: number }
    const n = high * 2 ** 32 + (low >>> 0)
    return Number.isSafeInteger(n) && n >= 0 ? String(n) : null
  }
  return null
}

const TITLE =
  'Graph node ID - click to copy. An external agent can read this node through ' +
  'the MCP query_graph tool with WHERE id(n) = <id>. Valid until the next rescan.'

/** The header, with the tooltip explaining what the number is for. */
export function NodeIdTh({ header = NODE_ID_HEADER }: { header?: string }) {
  return <th title={TITLE}>{header}</th>
}

type CopyStatus = { id: string; ok: boolean } | null

/**
 * The cell: the id as a click-to-copy button, `-` for a row with no node.
 *
 * The click never reaches the row, because several tables expand or select a
 * row on click and copying an id should do neither.
 *
 * The confirmation remembers WHICH id it confirms: tables keyed by index reuse
 * this cell for a different row after a sort or a refetch, and a bare flag
 * would then show "copied" on a node nobody copied.
 */
export function NodeIdCell({ value }: { value: unknown }) {
  const id = formatNodeId(value)
  const [status, setStatus] = useState<CopyStatus>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])

  const copy = useCallback((e: MouseEvent) => {
    e.stopPropagation()
    if (!id) return
    const show = (ok: boolean) => {
      setStatus({ id, ok })
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setStatus(null), 1200)
    }
    copyText(id).then(() => show(true), () => show(false))
  }, [id])

  if (!id) return <span className={styles.nullCell}>-</span>
  const shown = status?.id === id ? status : null
  return (
    <button
      type="button"
      className={styles.nodeIdBtn}
      onClick={copy}
      title={TITLE}
      aria-label={
        shown?.ok ? `Node ID ${id} copied`
          : shown ? `Could not copy node ID ${id}`
            : `Copy node ID ${id}`
      }
      data-node-id={id}
    >
      {shown ? (shown.ok ? 'copied' : 'copy failed') : id}
    </button>
  )
}
