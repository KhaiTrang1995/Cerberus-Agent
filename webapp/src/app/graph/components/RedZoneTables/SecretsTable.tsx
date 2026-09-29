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
  SeverityBadge,
  Mono,
  Truncated,
  UrlCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import { redactSecret } from './redact'
import rowStyles from './RedZoneTableRow.module.css'

interface SecretRow {
  nodeId: string | null
  origin: 'Secret' | 'JsReconFinding' | 'MultiscannerFinding'
    | 'GithubSecret' | 'GithubSensitiveFile' | 'ChainFinding' | string
  id: string
  secretType: string
  valueSample: string | null
  matchedText: string | null
  entropy: number | null
  confidence: string | number | null
  severity: string
  sourceModule: string | null
  sourceUrl: string | null
  secretBaseUrl: string | null
  keyType: string | null
  detectionMethod: string | null
  validationStatus: string | null
  baseUrl: string | null
  subdomain: string | null
  jsFileUrl: string | null
  /** TruffleHog rows only: which of the 14 sources found it, and where. */
  trufflehogSource: string | null
  asset: string | null
  location: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

/** The row node's label. A `JsReconFinding` origin is still a Secret node,
 *  one the route reached through a JS file. */
function secretNodeLabel(origin: string): string {
  return origin === 'JsReconFinding' ? 'Secret' : origin
}

const PAGE_SIZE = 100

const VALIDATION_CLASS: Record<string, string> = {
  validated:        rowStyles.sevCritical,
  format_validated: rowStyles.sevMedium,
  // The verify call itself failed. NOT proof the credential is dead, so it must
  // not share the muted styling of a checked-and-dead one.
  verify_error:     rowStyles.sevMedium,
  unvalidated:      rowStyles.sevInfo,
  // Verification was switched off: nobody looked. Kept distinct from
  // `unvalidated` because collapsing them would overstate the assurance.
  unverified:       rowStyles.sevInfo,
  skipped:          rowStyles.sevInfo,
  invalid:          rowStyles.sevLow,
}

const VALIDATION_LABEL: Record<string, string> = {
  validated: 'LIVE',
  unvalidated: 'not live',
  verify_error: 'verify error',
  unverified: 'not checked',
}

function ValidationChip({ status }: { status: string | null }) {
  if (!status) return <span className={rowStyles.nullCell}>-</span>
  const cls = VALIDATION_CLASS[status] || rowStyles.sevInfo
  const label = VALIDATION_LABEL[status] ?? status.replace('_', ' ')
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{label}</span>
}

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'origin', header: 'Origin' },
  // TruffleHog scans 14 sources in parallel; without a per-source filter the
  // rows from a namespace-wide Docker scan bury everything else.
  { key: 'trufflehogSource', header: 'Source' },
  { key: 'asset', header: 'Asset' },
  { key: 'location', header: 'Location' },
  { key: 'secretType', header: 'Type' },
  { key: 'keyType', header: 'Category' },
  { key: 'valueSample', header: 'Redacted Sample' },
  { key: 'matchedText', header: 'Redacted Match' },
  { key: 'entropy', header: 'Entropy' },
  { key: 'confidence', header: 'Confidence' },
  { key: 'severity', header: 'Severity' },
  { key: 'validationStatus', header: 'Validation' },
  { key: 'detectionMethod', header: 'Detection' },
  { key: 'sourceModule', header: 'Source Module' },
  { key: 'sourceUrl', header: 'Source URL' },
  { key: 'jsFileUrl', header: 'Parent JS File' },
  { key: 'baseUrl', header: 'BaseURL' },
  { key: 'subdomain', header: 'Subdomain' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const SecretsTable = memo(function SecretsTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<SecretRow>('secrets', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'secrets',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows.map(r => ({ ...r, valueSample: redactSecret(r.valueSample), matchedText: redactSecret(r.matchedText) })),
          sheetName: 'Secrets',
          fileSlug: 'redzone-secrets',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  return (
    <RedZoneTableShell
      title="Secrets & Credential Exposure"
      meta={rows.length ? `${rows.length} credential finding${rows.length === 1 ? '' : 's'}` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search secret type, category, URL, subdomain..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No leaked secrets found. Run js_recon, resource_enum, the Secret Multiscanner or a GitHub Secret Hunt to discover credentials."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Type</th>
            <th>Category</th>
            <th>Redacted Sample</th>
            <th>Entropy</th>
            <th>Conf.</th>
            <th>Sev</th>
            <th>Validation</th>
            <th>Origin</th>
            <th>Source</th>
            <th>Asset</th>
            <th>Location</th>
            <th>Source URL</th>
            <th>Subdomain</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={r.id || `${r.sourceUrl}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><Mono>{r.secretType}</Mono></td>
              <td>{r.keyType ? <span className={rowStyles.listChip}>{r.keyType}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><Mono>{redactSecret(r.valueSample || r.matchedText)}</Mono></td>
              <td>{r.entropy != null ? <span className={rowStyles.numCell}>{r.entropy.toFixed(2)}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td>{r.confidence != null ? <span className={rowStyles.numCell}>{String(r.confidence)}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><ValidationChip status={r.validationStatus} /></td>
              <td><span className={rowStyles.listChip}>{r.origin}</span></td>
              <td>{r.trufflehogSource || r.sourceModule
                ? <span className={rowStyles.listChip}>{r.trufflehogSource || r.sourceModule}</span>
                : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><Truncated text={r.asset} max={180} /></td>
              <td><Truncated text={r.location} max={180} /></td>
              <td><UrlCell url={r.sourceUrl} max={260} /></td>
              <td>{r.subdomain ? <HostCell host={r.subdomain} /> : <Truncated text={r.subdomain} max={180} />}</td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.secretType} graphId={r.nodeId} nodeId={r.id} label={secretNodeLabel(r.origin)} /></td>
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
