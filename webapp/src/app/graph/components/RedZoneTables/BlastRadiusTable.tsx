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
  NumCell,
  CvssCell,
  ListCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface BlastRadiusRow {
  nodeId: string | null
  techName: string
  techVersion: string | null
  cveCount: number
  maxCvss: number | null
  kevCount: number
  baseUrlCount: number
  ipCount: number
  severities: string[]
  topCveIds: string[]
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'techName', header: 'Technology' },
  { key: 'techVersion', header: 'Version' },
  { key: 'cveCount', header: 'CVE Count' },
  { key: 'maxCvss', header: 'Max CVSS' },
  { key: 'kevCount', header: 'KEV Count' },
  { key: 'baseUrlCount', header: 'BaseURLs' },
  { key: 'ipCount', header: 'IPs' },
  { key: 'severities', header: 'Severities' },
  { key: 'topCveIds', header: 'Top CVE IDs' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const BlastRadiusTable = memo(function BlastRadiusTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<BlastRadiusRow>('blastRadius', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'blastRadius',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'Blast-Radius',
          fileSlug: 'redzone-blast-radius',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  return (
    <RedZoneTableShell
      title="Technology Blast Radius"
      meta={rows.length ? `${rows.length} technologies with known CVEs` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search tech name, CVE, version..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No technologies with mapped CVEs. Run nmap + vuln scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Technology</th>
            <th>Version</th>
            <th>CVEs</th>
            <th>Max CVSS</th>
            <th>KEV</th>
            <th>BaseURLs</th>
            <th>IPs</th>
            <th>Top CVEs</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.techName}-${r.techVersion || ''}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><Truncated text={r.techName} max={200} /></td>
              <td>{r.techVersion ? <Mono>{r.techVersion}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><NumCell value={r.cveCount} /></td>
              <td><CvssCell score={r.maxCvss} /></td>
              <td>
                {r.kevCount > 0 ? (
                  <span className={rowStyles.kevChip}>{r.kevCount} KEV</span>
                ) : (
                  <span className={rowStyles.nullCell}>-</span>
                )}
              </td>
              <td><NumCell value={r.baseUrlCount} /></td>
              <td><NumCell value={r.ipCount} /></td>
              <td><ListCell items={r.topCveIds} max={3} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.techName} graphId={r.nodeId} label="Technology" /></td>
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
