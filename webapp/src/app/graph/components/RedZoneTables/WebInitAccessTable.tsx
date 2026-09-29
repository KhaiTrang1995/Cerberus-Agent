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
  ListCell,
  UrlCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface WebInitAccessRow {
  nodeId: string | null
  baseUrl: string
  scheme: string | null
  statusCode: number | null
  server: string | null
  subdomain: string | null
  authEndpointPaths: string[]
  authEndpointMethods: string[]
  authCategories: string[]
  authEndpointCount: number
  totalEndpointCount: number
  vulnTags: string[]
  headerGrid: Record<string, boolean>
  grade: string
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

const HEADER_CHECKS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
const HEADER_SHORT: Record<string, string> = {
  'Content-Security-Policy': 'CSP',
  'Strict-Transport-Security': 'HSTS',
  'X-Frame-Options': 'XFO',
  'X-Content-Type-Options': 'XCTO',
  'Referrer-Policy': 'Ref-Pol',
  'Permissions-Policy': 'Perm-Pol',
}

const GRADE_CLASS: Record<string, string> = {
  A: rowStyles.sevLow,
  B: rowStyles.sevLow,
  C: rowStyles.sevMedium,
  D: rowStyles.sevHigh,
  F: rowStyles.sevCritical,
}

function GradeChip({ grade }: { grade: string }) {
  const cls = GRADE_CLASS[grade] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`} style={{ minWidth: 20, display: 'inline-block', textAlign: 'center' }}>{grade}</span>
}

function HeaderCell({ present }: { present: boolean }) {
  return (
    <span className={present ? rowStyles.boolTrue : rowStyles.boolFalse} title={present ? 'present' : 'MISSING'}>
      {present ? '✓' : '✗'}
    </span>
  )
}

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'baseUrl', header: 'BaseURL' },
  { key: 'subdomain', header: 'Subdomain' },
  { key: 'scheme', header: 'Scheme' },
  { key: 'statusCode', header: 'Status' },
  { key: 'server', header: 'Server' },
  { key: 'grade', header: 'Grade' },
  { key: 'authEndpointCount', header: 'Auth Endpoints' },
  { key: 'totalEndpointCount', header: 'Total Endpoints' },
  { key: 'authEndpointPaths', header: 'Auth Paths' },
  { key: 'authCategories', header: 'Auth Categories' },
  { key: 'vulnTags', header: 'Vuln Tags' },
  { key: 'CSP', header: 'CSP' },
  { key: 'HSTS', header: 'HSTS' },
  { key: 'X-Frame-Options', header: 'X-Frame-Options' },
  { key: 'X-Content-Type-Options', header: 'X-Content-Type-Options' },
  { key: 'Referrer-Policy', header: 'Referrer-Policy' },
  { key: 'Permissions-Policy', header: 'Permissions-Policy' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const WebInitAccessTable = memo(function WebInitAccessTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<WebInitAccessRow>('webInitAccess', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'webInitAccess',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() => {
    if (rows.length === 0) return undefined
    const flat = sortedRows.map(r => ({
      nodeId: r.nodeId,
      baseUrl: r.baseUrl,
      subdomain: r.subdomain,
      scheme: r.scheme,
      statusCode: r.statusCode,
      server: r.server,
      grade: r.grade,
      authEndpointCount: r.authEndpointCount,
      totalEndpointCount: r.totalEndpointCount,
      authEndpointPaths: r.authEndpointPaths,
      authCategories: r.authCategories,
      vulnTags: r.vulnTags,
      CSP: r.headerGrid['Content-Security-Policy'],
      HSTS: r.headerGrid['Strict-Transport-Security'],
      'X-Frame-Options': r.headerGrid['X-Frame-Options'],
      'X-Content-Type-Options': r.headerGrid['X-Content-Type-Options'],
      'Referrer-Policy': r.headerGrid['Referrer-Policy'],
      'Permissions-Policy': r.headerGrid['Permissions-Policy'],
      updatedAt: r.updatedAt,
    }))
    return {
      rows: flat,
      sheetName: 'Web-Init-Access',
      fileSlug: 'redzone-web-init-access',
      columns: COLUMNS,
    }
  }, [sortedRows, rows.length])

  return (
    <RedZoneTableShell
      title="Web Initial-Access Panel"
      meta={rows.length ? `${rows.length} BaseURLs with auth endpoints or header/auth findings` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search BaseURL, subdomain, vuln, auth path..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No auth endpoints or web-layer security findings yet. Run resource_enum + vuln_scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>BaseURL</th>
            <th>Subdomain</th>
            <th>Auth EPs</th>
            <th>Grade</th>
            {HEADER_CHECKS.map(h => <th key={h} title={h}>{HEADER_SHORT[h]}</th>)}
            <th>Vuln Tags</th>
            <th>Server</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.baseUrl}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><UrlCell url={r.baseUrl} max={260} /></td>
              <td>{r.subdomain ? <HostCell host={r.subdomain} /> : <Truncated text={r.subdomain} max={160} />}</td>
              <td>
                {r.authEndpointCount > 0 ? (
                  <span title={r.authEndpointPaths.slice(0, 5).join('\n')}>
                    <span className={rowStyles.numCell}>{r.authEndpointCount}</span>
                  </span>
                ) : <span className={rowStyles.nullCell}>0</span>}
              </td>
              <td><GradeChip grade={r.grade} /></td>
              {HEADER_CHECKS.map(h => (
                <td key={h} style={{ textAlign: 'center' }}><HeaderCell present={!!r.headerGrid[h]} /></td>
              ))}
              <td><ListCell items={r.vulnTags} max={3} /></td>
              <td><Truncated text={r.server} max={120} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.baseUrl} graphId={r.nodeId} label="BaseURL" /></td>
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
