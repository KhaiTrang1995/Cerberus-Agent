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
import { ExternalLink } from '@/components/ui'
import { capecToUrl, cveToUrl, cweToUrl } from '@/lib/url-utils'
import {
  SeverityBadge,
  Mono,
  Truncated,
  CvssCell,
  KevChip,
  HostCell,
  IpCell,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

interface KillChainRow {
  /** The Technology carrying the CVE; CVE nodes are global and unaddressable by id. */
  nodeId: string | null
  subdomain: string | null
  ipAddress: string | null
  port: number | null
  protocol: string | null
  serviceName: string | null
  serviceProduct: string | null
  serviceVersion: string | null
  techName: string | null
  techVersion: string | null
  cveId: string
  cvss: number | null
  cveSeverity: string
  cisaKev: boolean
  cweId: string | null
  cweName: string | null
  capecId: string | null
  capecName: string | null
  capecSeverity: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'subdomain', header: 'Subdomain' },
  { key: 'ipAddress', header: 'IP' },
  { key: 'port', header: 'Port' },
  { key: 'protocol', header: 'Proto' },
  { key: 'serviceName', header: 'Service' },
  { key: 'serviceProduct', header: 'Product' },
  { key: 'serviceVersion', header: 'SvcVer' },
  { key: 'techName', header: 'Technology' },
  { key: 'techVersion', header: 'TechVer' },
  { key: 'cveId', header: 'CVE' },
  { key: 'cvss', header: 'CVSS' },
  { key: 'cveSeverity', header: 'Severity' },
  { key: 'cisaKev', header: 'CISA KEV' },
  { key: 'cweId', header: 'CWE' },
  { key: 'cweName', header: 'CWE Name' },
  { key: 'capecId', header: 'CAPEC' },
  { key: 'capecName', header: 'CAPEC Name' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const KillChainTable = memo(function KillChainTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<KillChainRow>('killChain', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'killChain',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'Kill-Chain',
          fileSlug: 'redzone-kill-chain',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  const kevCount = (data?.meta?.kevCount as number | undefined) ?? 0
  const meta = rows.length ? `${kevCount} KEV match${kevCount === 1 ? '' : 'es'}` : undefined

  return (
    <RedZoneTableShell
      title="Kill-Chain Explorer"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search subdomain, CVE, tech, CWE..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No Subdomain → IP → Port → Tech → CVE chains found. Run recon + vuln scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Subdomain</th>
            <th>IP</th>
            <th>Port</th>
            <th>Service</th>
            <th>Technology</th>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Sev</th>
            <th>KEV</th>
            <th>CWE</th>
            <th>CAPEC</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.subdomain}-${r.port}-${r.cveId}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td>{r.subdomain ? <HostCell host={r.subdomain} /> : <Truncated text={r.subdomain} max={180} />}</td>
              <td>{r.ipAddress ? <IpCell ip={r.ipAddress} port={r.port ?? undefined} /> : <Mono>-</Mono>}</td>
              <td>
                {r.port != null ? <Mono>{r.port}/{r.protocol || 'tcp'}</Mono> : '-'}
              </td>
              <td>
                <Truncated
                  text={[r.serviceName, r.serviceProduct, r.serviceVersion].filter(Boolean).join(' ')}
                  max={160}
                />
              </td>
              <td>
                <Truncated
                  text={[r.techName, r.techVersion].filter(Boolean).join(' ')}
                  max={160}
                />
              </td>
              <td><Mono>{r.cveId ? <ExternalLink href={cveToUrl(r.cveId)}>{r.cveId}</ExternalLink> : '-'}</Mono></td>
              <td><CvssCell score={r.cvss} /></td>
              <td><SeverityBadge severity={normalizeSeverity(r.cveSeverity)} /></td>
              <td><KevChip value={r.cisaKev} /></td>
              <td>
                {r.cweId ? (
                  <span className={rowStyles.truncate} style={{ maxWidth: 180 }} title={r.cweName || r.cweId}>
                    <ExternalLink href={cweToUrl(r.cweId)}>{r.cweId}</ExternalLink>
                    {r.cweName ? ` ${r.cweName}` : ''}
                  </span>
                ) : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td>
                {r.capecId ? (
                  <span className={rowStyles.truncate} style={{ maxWidth: 180 }} title={r.capecName || r.capecId}>
                    <ExternalLink href={capecToUrl(r.capecId)}>{r.capecId}</ExternalLink>
                    {r.capecName ? ` ${r.capecName}` : ''}
                  </span>
                ) : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.techName || r.cveId} graphId={r.nodeId} label="Technology" /></td>
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
