/**
 * The pure half of Muted Nodes: the request it sends, and how a row reads.
 * Kept apart from the component so both are tested without rendering.
 */

import { formatNodeId } from '../RedZoneTables/nodeId'

export type MutedVia = 'all' | 'person' | 'rule' | 'deleted_rule'

export interface MutedRow {
  id: string
  /** Neo4j's internal id, for the Node ID column only. `id` stays the key the
   *  selection, unmute and exemptions use. */
  node_id?: string | null
  label: string
  name: string
  severity: string
  source: string
  host: string
  muted_at: string | null
  muted_by: string
  muted_via: 'person' | 'rule'
  muted_reason: string
  stale_since: string | null
  triage_status: string
  triage_reason: string | null
  rule_kind: string | null
  rule_id: string | null
  rule_name: string | null
  rule_deleted: boolean
}

export interface MutedFacets {
  total: number
  by_person: number
  labels: Record<string, number>
  rules: { muted_by: string; count: number; reason: string; rule_name: string | null; rule_deleted: boolean }[]
}

export interface MutedFilters {
  label: string
  mutedVia: MutedVia
  rule: string
  search: string
}

export const EMPTY_FILTERS: MutedFilters = { label: '', mutedVia: 'all', rule: '', search: '' }

export const PAGE_SIZE = 50

/** The largest export one request returns; the route's own cap. */
export const EXPORT_MAX = 5000

export function hasFilters(f: MutedFilters): boolean {
  return !!(f.label || f.mutedVia !== 'all' || f.rule || f.search.trim())
}

export function mutedQuery(
  projectId: string, filters: MutedFilters,
  page: { offset: number; limit: number }, facets = false,
): string {
  const q = new URLSearchParams({
    projectId, offset: String(page.offset), limit: String(page.limit),
  })
  if (filters.label) q.set('label', filters.label)
  if (filters.mutedVia !== 'all') q.set('mutedVia', filters.mutedVia)
  if (filters.rule) q.set('rule', filters.rule)
  if (filters.search.trim()) q.set('search', filters.search.trim())
  if (facets) q.set('facets', '1')
  return `/api/triage/muted?${q.toString()}`
}

/** "Vuln · nuclei": the functional label, plus the source when it adds something. */
export function kindLabel(row: Pick<MutedRow, 'label' | 'source'>): string {
  const short = row.label === 'Vulnerability' ? 'Vuln' : row.label
  return row.source ? `${short} · ${row.source}` : short
}

/**
 * Who, or which rule, muted a row, as the table and the export say it.
 * A rule that no longer exists shows the reason it wrote at the time, which
 * is all that is left of it.
 */
export function mutedByText(row: MutedRow, me: string | null | undefined): string {
  if (row.muted_via === 'rule') {
    if (row.rule_deleted) return `Rule (deleted): ${row.muted_reason || row.muted_by}`
    return `Rule: ${row.rule_name ?? row.muted_by}`
  }
  if (me && row.muted_by === me) return 'you'
  return row.muted_by || '-'
}

export function stateText(row: Pick<MutedRow, 'stale_since'>): string {
  return row.stale_since ? 'resolved: no longer reported' : ''
}

export const EXPORT_COLUMNS = [
  'node_id', 'id', 'kind', 'name', 'severity', 'host', 'muted_by', 'muted_via', 'rule', 'muted_reason',
  'muted_at', 'state',
] as const

/** The rows an export writes: what the table shows, one column per field. */
export function exportRows(rows: MutedRow[], me: string | null | undefined): Record<string, unknown>[] {
  return rows.map(row => ({
    node_id: formatNodeId(row.node_id) ?? '',
    id: row.id,
    kind: kindLabel(row),
    name: row.name,
    severity: row.severity,
    host: row.host,
    muted_by: mutedByText(row, me),
    muted_via: row.muted_via,
    rule: row.muted_via === 'rule' ? row.muted_by : '',
    muted_reason: row.muted_reason,
    muted_at: row.muted_at ?? '',
    state: stateText(row),
  }))
}
