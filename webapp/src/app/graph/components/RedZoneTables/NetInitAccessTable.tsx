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
  BoolChip,
  IpCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface NetInitAccessRow {
  /** The Port for a port row; the Vulnerability (or its IP) for an IP-level finding. */
  nodeId: string | null
  origin: string
  ipAddress: string
  port: number | null
  protocol: string
  category: string | null
  serviceName: string | null
  serviceProduct: string | null
  serviceVersion: string | null
  techs: string[]
  subdomains: string[]
  vulnTags: string[]
  isCdn: boolean | null
  cdnName: string | null
  asn: string | null
  country: string | null
  isp: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

const CATEGORY_CLASS: Record<string, string> = {
  database: rowStyles.sevCritical,
  k8s: rowStyles.sevCritical,
  ssh: rowStyles.sevHigh,
  rdp: rowStyles.sevHigh,
  telnet: rowStyles.sevCritical,
  winrm: rowStyles.sevHigh,
  smtp: rowStyles.sevMedium,
  snmp: rowStyles.sevMedium,
  ipmi: rowStyles.sevHigh,
  smb: rowStyles.sevHigh,
  vnc: rowStyles.sevHigh,
}

function CategoryChip({ category }: { category: string | null }) {
  if (!category) return <span className={rowStyles.nullCell}>-</span>
  const cls = CATEGORY_CLASS[category] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{category}</span>
}

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'ipAddress', header: 'IP' },
  { key: 'port', header: 'Port' },
  { key: 'protocol', header: 'Proto' },
  { key: 'category', header: 'Category' },
  { key: 'serviceName', header: 'Service' },
  { key: 'serviceProduct', header: 'Product' },
  { key: 'serviceVersion', header: 'Version' },
  { key: 'techs', header: 'Technologies' },
  { key: 'subdomains', header: 'Subdomains' },
  { key: 'vulnTags', header: 'Findings' },
  { key: 'isCdn', header: 'CDN' },
  { key: 'cdnName', header: 'CDN Name' },
  { key: 'asn', header: 'ASN' },
  { key: 'country', header: 'Country' },
  { key: 'isp', header: 'ISP' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const NetInitAccessTable = memo(function NetInitAccessTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<NetInitAccessRow>('netInitAccess', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'netInitAccess',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'Net-Init-Access',
          fileSlug: 'redzone-net-init-access',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  return (
    <RedZoneTableShell
      title="Network Initial-Access Surface"
      meta={rows.length ? `${rows.length} sensitive exposures (DB / mgmt / origin)` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search IP, port, tag, service, country..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No sensitive network exposures yet. Run port scan + security checks to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>IP</th>
            <th>Port</th>
            <th>Category</th>
            <th>Service</th>
            <th>Subdomains</th>
            <th>Findings</th>
            <th>CDN</th>
            <th>ASN / Country</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.ipAddress}-${r.port}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><IpCell ip={r.ipAddress} port={r.port ?? undefined} /></td>
              <td>
                {r.port != null ? <Mono>{r.port}/{r.protocol}</Mono> : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><CategoryChip category={r.category} /></td>
              <td>
                <Truncated
                  text={[r.serviceName, r.serviceProduct, r.serviceVersion].filter(Boolean).join(' ')}
                  max={180}
                />
              </td>
              <td><ListCell items={r.subdomains} max={2} /></td>
              <td><ListCell items={r.vulnTags} max={3} /></td>
              <td>
                <BoolChip value={r.isCdn} trueLabel={r.cdnName || 'yes'} falseLabel="direct" />
              </td>
              <td>
                <Truncated text={[r.asn, r.country].filter(Boolean).join(' · ')} max={140} />
              </td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              {/* A vuln row points at its Vulnerability when it is alone and at
                  the IP otherwise, which only the server can tell apart. */}
              <td><MuteNodeButton name={`${r.ipAddress}:${r.port ?? ''}`} graphId={r.nodeId} label={r.origin === 'port' ? 'Port' : undefined} /></td>
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
