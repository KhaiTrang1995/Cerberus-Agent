'use client'

import { memo, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import type { RedZoneExportConfig } from './exportCsv'
import { useRedZoneFilters, type RedZoneFilterColumn } from './useRedZoneFilters'
import {
  UPDATED_AT_COLUMN,
  UpdatedAtCell,
  UpdatedAtTh,
  useUpdatedAtSort,
} from './updatedAt'
import { NODE_ID_COLUMN, NodeIdCell, NodeIdTh } from './nodeId'
import { MuteNodeButton } from '../MuteNode'
import {
  Mono,
  Truncated,
  UrlCell,
  NumCell,
  BoolChip,
  ListCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface GraphqlRow {
  nodeId: string | null
  endpointUrl: string | null
  path: string | null
  baseUrl: string | null
  subdomain: string | null
  introspection: boolean | null
  graphiqlExposed: boolean | null
  fieldSuggestions: boolean | null
  getAllowed: boolean | null
  batching: boolean | null
  tracing: boolean | null
  queriesCount: number | null
  mutationsCount: number | null
  subscriptionsCount: number | null
  schemaHash: string | null
  schemaExtractedAt: string | null
  copScannedAt: string | null
  lastError: string | null
  sensitiveFieldsSample: string | null
  vulnTypes: string[]
  vulnSeverities: string[]
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'endpointUrl', header: 'Endpoint' },
  { key: 'subdomain', header: 'Subdomain' },
  { key: 'introspection', header: 'Introspection' },
  { key: 'graphiqlExposed', header: 'GraphiQL' },
  { key: 'fieldSuggestions', header: 'FieldSuggestions' },
  { key: 'getAllowed', header: 'GET allowed' },
  { key: 'batching', header: 'Batching' },
  { key: 'tracing', header: 'Tracing' },
  { key: 'queriesCount', header: 'Queries' },
  { key: 'mutationsCount', header: 'Mutations' },
  { key: 'subscriptionsCount', header: 'Subscriptions' },
  { key: 'vulnTypes', header: 'Vulns' },
  { key: 'vulnSeverities', header: 'VulnSeverities' },
  { key: 'sensitiveFieldsSample', header: 'Sensitive Fields' },
  { key: 'schemaHash', header: 'Schema Hash' },
  { key: 'copScannedAt', header: 'Last graphql-cop scan' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const GraphqlLedgerTable = memo(function GraphqlLedgerTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<GraphqlRow>('graphql', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'graphql',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'GraphQL',
          fileSlug: 'redzone-graphql',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  const introCount = rows.filter(r => r.introspection).length
  const meta = rows.length ? `${introCount} with introspection enabled` : undefined

  return (
    <RedZoneTableShell
      title="GraphQL & Modern API Risk Ledger"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search endpoint, subdomain, vuln type..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No GraphQL endpoints discovered yet. Enable GraphQL scan in project settings."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Endpoint</th>
            <th>Introspect</th>
            <th>GraphiQL</th>
            <th>Fld Sugg</th>
            <th>GET</th>
            <th>Batch</th>
            <th>Trace</th>
            <th>Q</th>
            <th>M</th>
            <th>S</th>
            <th>Vulns</th>
            <th>Sensitive fields</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.endpointUrl}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><UrlCell url={r.endpointUrl || r.path} max={280} /></td>
              <td><BoolChip value={r.introspection} /></td>
              <td><BoolChip value={r.graphiqlExposed} /></td>
              <td><BoolChip value={r.fieldSuggestions} /></td>
              <td><BoolChip value={r.getAllowed} /></td>
              <td><BoolChip value={r.batching} /></td>
              <td><BoolChip value={r.tracing} /></td>
              <td><NumCell value={r.queriesCount} /></td>
              <td><NumCell value={r.mutationsCount} /></td>
              <td><NumCell value={r.subscriptionsCount} /></td>
              <td><ListCell items={r.vulnTypes} max={3} /></td>
              <td><Truncated text={r.sensitiveFieldsSample} max={260} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.endpointUrl || r.path || ''} graphId={r.nodeId} label="Endpoint" /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {limit < filtered.length && (
        <div className={rowStyles.loadMoreBar}>
          <button className={rowStyles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
            Showing {sliced.length} of {filtered.length} - Load more
          </button>
        </div>
      )}
    </RedZoneTableShell>
  )
})
