'use client'

import { memo, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { normalizeSeverity } from './types'
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
  SeverityBadge,
  Mono,
  Truncated,
  UrlCell,
  NumCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface WcpRow {
  nodeId: string | null
  endpointUrl: string | null
  baseUrl: string | null
  cacheHeader: string | null
  cacheParam: string | null
  vectorType: string | null
  impact: string | null
  severity: string | null
  cvss: number | null
  confidence: number | null
  tier: string | null
  detectionMode: string | null
  technique: string | null
  engine: string | null
  cacheBuster: string | null
  crossVantage: boolean | null
  pocLink: string | null
  curlVerify: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'endpointUrl', header: 'Endpoint' },
  { key: 'cacheHeader', header: 'Header' },
  { key: 'cacheParam', header: 'Param' },
  { key: 'vectorType', header: 'Vector type' },
  { key: 'impact', header: 'Impact' },
  { key: 'severity', header: 'Severity' },
  { key: 'cvss', header: 'CVSS' },
  { key: 'tier', header: 'Confidence tier' },
  { key: 'confidence', header: 'Confidence' },
  { key: 'detectionMode', header: 'Detection mode' },
  { key: 'technique', header: 'Technique' },
  { key: 'engine', header: 'Engine' },
  { key: 'cacheBuster', header: 'Cache buster' },
  { key: 'crossVantage', header: 'Cross-vantage' },
  { key: 'pocLink', header: 'PoC link' },
  { key: 'curlVerify', header: 'curl PoC' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const WebCachePoisonTable = memo(function WebCachePoisonTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<WcpRow>('webCachePoison', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'webCachePoison',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'WebCachePoisoning',
          fileSlug: 'redzone-web-cache-poisoning',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  const confirmed = rows.filter(r => r.tier === 'Confirmed').length
  const critical = rows.filter(r => normalizeSeverity(r.severity) === 'critical').length
  const meta = rows.length
    ? `${confirmed} Confirmed · ${critical} critical · ${rows.length} total`
    : undefined

  return (
    <RedZoneTableShell
      title="Web Cache Poisoning"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search endpoint, header, impact, tier..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No web cache poisoning findings yet. Enable Web Cache Poisoning in project settings and run a scan."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Endpoint</th>
            <th>Unkeyed input</th>
            <th>Impact</th>
            <th>Sev</th>
            <th>CVSS</th>
            <th>Tier</th>
            <th>Mode</th>
            <th>Conf</th>
            <th>PoC</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.endpointUrl}-${r.cacheHeader || r.cacheParam}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><UrlCell url={r.endpointUrl} max={300} /></td>
              <td><Mono>{r.cacheHeader || (r.cacheParam ? `?${r.cacheParam}` : '-')}</Mono></td>
              <td><Mono>{r.impact || '-'}</Mono></td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><NumCell value={r.cvss} /></td>
              <td><Mono>{r.tier || '-'}</Mono></td>
              <td><Mono>{r.detectionMode || '-'}</Mono></td>
              <td><NumCell value={r.confidence} /></td>
              <td>
                {r.pocLink
                  ? <a href={r.pocLink} target="_blank" rel="noreferrer" title={r.curlVerify || r.pocLink}>PoC</a>
                  : <Truncated text={r.curlVerify} max={40} />}
              </td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.endpointUrl || r.baseUrl || 'cache poisoning finding'} graphId={r.nodeId} label="Vulnerability" /></td>
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
