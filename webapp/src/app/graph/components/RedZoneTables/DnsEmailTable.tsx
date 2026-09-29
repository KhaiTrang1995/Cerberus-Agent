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
  Truncated,
  ListCell,
  BoolChip,
  NumCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface DnsEmailRow {
  nodeId: string | null
  domain: string
  spfPresent: boolean
  spfStrict: boolean
  spfRecord: string | null
  dmarcPresent: boolean
  dmarcPolicy: string | null
  dnssec: string | null
  dnssecEnabled: boolean
  zoneTransferOpen: boolean
  mxRecords: string[]
  mxCount: number
  nameServers: string[]
  nameServerCount: number
  nsDistinctProviders: number | null
  whoisEmails: string[]
  registrar: string | null
  organization: string | null
  country: string | null
  expirationDate: string | null
  daysToExpiry: number | null
  registrarStatus: string[]
  vtMaliciousCount: number | null
  vtReputation: number | null
  otxPulseCount: number | null
  vulnTags: string[]
  spfMissing: boolean
  dmarcMissing: boolean
  dnssecMissing: boolean
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 50

function PolicyChip({ policy }: { policy: string | null }) {
  if (!policy) return <span className={rowStyles.nullCell}>-</span>
  let cls = rowStyles.sevHigh
  if (policy === 'reject') cls = rowStyles.sevLow
  else if (policy === 'quarantine') cls = rowStyles.sevMedium
  else if (policy === 'none') cls = rowStyles.sevHigh
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{policy}</span>
}

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'domain', header: 'Domain' },
  { key: 'spfPresent', header: 'SPF Present' },
  { key: 'spfStrict', header: 'SPF Strict' },
  { key: 'spfRecord', header: 'SPF Record' },
  { key: 'dmarcPresent', header: 'DMARC Present' },
  { key: 'dmarcPolicy', header: 'DMARC Policy' },
  { key: 'dnssec', header: 'DNSSEC' },
  { key: 'dnssecEnabled', header: 'DNSSEC Enabled' },
  { key: 'zoneTransferOpen', header: 'Zone Transfer Open' },
  { key: 'mxRecords', header: 'MX Records' },
  { key: 'mxCount', header: 'MX Count' },
  { key: 'nameServers', header: 'Name Servers' },
  { key: 'nameServerCount', header: 'NS Count' },
  { key: 'nsDistinctProviders', header: 'NS Providers' },
  { key: 'whoisEmails', header: 'WHOIS Emails' },
  { key: 'registrar', header: 'Registrar' },
  { key: 'organization', header: 'Organization' },
  { key: 'country', header: 'Country' },
  { key: 'expirationDate', header: 'Expiration' },
  { key: 'daysToExpiry', header: 'Days To Expiry' },
  { key: 'registrarStatus', header: 'Registrar Status' },
  { key: 'vtMaliciousCount', header: 'VT Malicious' },
  { key: 'vtReputation', header: 'VT Reputation' },
  { key: 'otxPulseCount', header: 'OTX Pulses' },
  { key: 'vulnTags', header: 'Vuln Tags' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const DnsEmailTable = memo(function DnsEmailTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<DnsEmailRow>('dnsEmail', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'dnsEmail',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'DNS-Email',
          fileSlug: 'redzone-dns-email',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  return (
    <RedZoneTableShell
      title="DNS & Email Security Posture"
      meta={rows.length ? `${rows.length} domain${rows.length === 1 ? '' : 's'}` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search domain, NS, registrar..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No Domain nodes yet. Run domain_recon + security_checks to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Domain</th>
            <th>SPF</th>
            <th>SPF strict</th>
            <th>DMARC</th>
            <th>DMARC policy</th>
            <th>DNSSEC</th>
            <th>Zone xfer</th>
            <th>MX</th>
            <th>NS</th>
            <th>Expires in</th>
            <th>VT mal.</th>
            <th>OTX</th>
            <th>Registrar</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.domain}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><HostCell host={r.domain} /></td>
              <td><BoolChip value={r.spfPresent} /></td>
              <td><BoolChip value={r.spfStrict} trueLabel="-all" falseLabel="weak" /></td>
              <td><BoolChip value={r.dmarcPresent} /></td>
              <td><PolicyChip policy={r.dmarcPolicy} /></td>
              <td><BoolChip value={r.dnssecEnabled} /></td>
              <td>
                <BoolChip value={r.zoneTransferOpen} trueLabel="OPEN" falseLabel="closed" />
              </td>
              <td><ListCell items={r.mxRecords} max={2} /></td>
              <td><ListCell items={r.nameServers} max={2} /></td>
              <td>
                {r.daysToExpiry != null ? (
                  <span className={r.daysToExpiry < 30 ? rowStyles.sevBadge + ' ' + rowStyles.sevHigh : rowStyles.numCell}>
                    {r.daysToExpiry}d
                  </span>
                ) : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><NumCell value={r.vtMaliciousCount} /></td>
              <td><NumCell value={r.otxPulseCount} /></td>
              <td><Truncated text={r.registrar} max={160} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.domain} graphId={r.nodeId} label="Domain" /></td>
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
