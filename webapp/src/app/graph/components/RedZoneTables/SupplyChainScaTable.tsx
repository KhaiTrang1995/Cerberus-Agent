'use client'

import { Fragment, memo, useCallback, useEffect, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneFilters } from './useRedZoneFilters'
import { UPDATED_AT_COLUMN, UpdatedAtCell, UpdatedAtTh, useUpdatedAtSort } from './updatedAt'
import { NODE_ID_COLUMN, NodeIdCell, NodeIdTh } from './nodeId'
import { MuteNodeButton, useMuteNodeContext } from '../MuteNode'
import type { RedZoneExportConfig } from './exportCsv'
import {
  SeverityBadge, Mono, Truncated, NumCell, ListCell, LinkedListCell, filterRowsByText,
} from './formatters'
import { normalizeSeverity, SEVERITY_RANK, type Severity } from './types'
import { isHttpUrl } from '@/lib/url-utils'
import rowStyles from './RedZoneTableRow.module.css'

/**
 * Supply-Chain SCA: the Package / MalPackageFinding / Vulnerability model that
 * L1 (SBOM or repo scan) and L2 (live-target recon harvest) both MERGE into,
 * deduped on the purl so all layers converge on the same rows.
 *
 * Not to be confused with the JS Dep Signals table, which reads JsReconFinding
 * nodes (source maps, dev comments, dependency confusion).
 */

type SheetKey = 'verdicts' | 'packages' | 'advisories'

interface VerdictRow {
  nodeId: string | null
  findingId: string
  verdict: string
  severity: string
  sourceTool: string | null
  advisoryId: string | null
  title: string | null
  detail: string | null
  confidence: string | null
  softError: boolean
  aliases: string[]
  firstSeen: string | null
  lastSeen: string | null
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  baseUrls: string[]
  repos: string[]
  sboms: string[]
  // Incident context from the supplychainattack.org catalog (feature B). All
  // null when the intel volume was never synced; the detail row is rendered
  // conditionally so a never-synced deploy shows nothing rather than an empty
  // panel that reads as "no incident is known about this package".
  incidentId: string | null
  incidentUrl: string | null
  incidentSummary: string | null
  incidentBlastRadius: string | null
  incidentRemediation: string[]
  incidentStatus: string | null
  incidentFeedRevised: string | null
  /** Newest of the finding's last_seen / first_seen. */
  updatedAt: string | null
}

interface PackageRow {
  nodeId: string | null
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  firstSeen: string | null
  lastSeen: string | null
  baseUrls: string[]
  repos: string[]
  sboms: string[]
  maliciousCount: number
  suspiciousCount: number
  notAnalysedCount: number
  advisoryCount: number
  advisorySeverities: string[]
  updatedAt: string | null
}

interface AdvisoryRow {
  nodeId: string | null
  advisoryId: string
  severity: string
  cvss: string | null
  title: string | null
  description: string | null
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  firstSeen: string | null
  updatedAt: string | null
  baseUrls: string[]
  repos: string[]
  sboms: string[]
}

interface ScaMeta {
  totalPackages: number
  unversioned: number
  malicious: number
  suspicious: number
  notAnalysed: number
  advisories: number
  byEcosystem?: { ecosystem: string; count: number; unversioned: number }[]
  truncated?: Record<SheetKey, boolean>
}

interface ScaResponse {
  sheets: { verdicts: VerdictRow[]; packages: PackageRow[]; advisories: AdvisoryRow[] }
  meta: ScaMeta
}

const PAGE_SIZE = 100

// --------------------------------------------------------------------------
// Chips
// --------------------------------------------------------------------------

/**
 * A verdict is one of three things, and conflating the third with the second is
 * the failure mode the whole feature is built to avoid: "GuardDog ran and found
 * something" and "GuardDog never ran" must not look alike.
 */
/**
 * What a non-malicious verdict actually means depends on WHICH tool produced it.
 * This used to hardcode GuardDog for every `verdict !== 'malicious'` row, so a
 * finding from any other tool was mislabelled as a behavioural hit.
 */
export function suspiciousVerdictTitle(sourceTool: string | null): string {
  switch ((sourceTool || '').toLowerCase()) {
    case 'guarddog':
      return 'GuardDog behavioural hit, not a terminal verdict'
    case 'typosquat':
      return 'Name is a near-miss of a popular package, not a terminal verdict'
    case 'retirejs':
      return 'retire.js matched a known-vulnerable library version'
    default:
      return 'Non-terminal verdict: flagged, but not confirmed malicious'
  }
}

function VerdictChip({ row }: { row: Pick<VerdictRow, 'verdict' | 'softError' | 'advisoryId' | 'sourceTool'> }) {
  const notAnalysed = row.softError || row.advisoryId === 'guarddog-not-run'
  if (notAnalysed) {
    return <span className={`${rowStyles.sevBadge} ${rowStyles.sevInfo}`} title="The behavioural pass did not produce a verdict for this package. It is UNCHECKED, not clean.">not analysed</span>
  }
  if (row.verdict === 'malicious') {
    return <span className={`${rowStyles.sevBadge} ${rowStyles.sevCritical}`} title="OSV MAL- advisory: the package itself is malware">malicious</span>
  }
  return <span className={`${rowStyles.sevBadge} ${rowStyles.sevMedium}`} title={suspiciousVerdictTitle(row.sourceTool)}>{row.verdict}</span>
}

export function hasIncident(row: Pick<VerdictRow, 'incidentId' | 'incidentSummary'>): boolean {
  return !!(row.incidentId || row.incidentSummary)
}

/**
 * The incident column is EMPTY, not "none", when the catalog was never synced.
 * "None" would assert that no incident is known, which is a claim the product
 * cannot make without the data.
 */
function IncidentToggle({ row, open, onToggle }: {
  row: VerdictRow
  open: boolean
  onToggle: (findingId: string) => void
}) {
  if (!hasIncident(row)) return <span className={rowStyles.nullCell}>-</span>
  return (
    <button
      type="button"
      onClick={() => onToggle(row.findingId)}
      aria-expanded={open}
      style={{
        cursor: 'pointer', background: 'transparent', fontSize: 11,
        border: '1px solid rgba(255,255,255,0.25)', borderRadius: 4,
        padding: '1px 6px', color: 'inherit',
      }}
    >
      {open ? '▾' : '▸'} {row.incidentId || 'incident'}
    </button>
  )
}

function IncidentDetailRow({ row }: { row: VerdictRow }) {
  return (
    <tr>
      <td colSpan={15} style={{ padding: '8px 14px', fontSize: 12, opacity: 0.92 }}>
        {row.incidentSummary && <p style={{ margin: '0 0 6px' }}>{row.incidentSummary}</p>}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginBottom: 6 }}>
          {row.incidentStatus && <span><strong>Status:</strong> {row.incidentStatus}</span>}
          {row.incidentBlastRadius && <span><strong>Blast radius:</strong> {row.incidentBlastRadius}</span>}
          {row.incidentFeedRevised && (
            // The feed revision is what makes a finding interpretable later: a
            // restored Scan Timeline snapshot carries the enrichment it had when
            // it was taken, not today's.
            <span><strong>Feed revision:</strong> {row.incidentFeedRevised}</span>
          )}
        </div>
        {row.incidentRemediation.length > 0 && (
          <>
            <strong>Remediation</strong>
            <ol style={{ margin: '4px 0 6px 18px' }}>
              {row.incidentRemediation.map((step, i) => <li key={i}>{step}</li>)}
            </ol>
          </>
        )}
        {isHttpUrl(row.incidentUrl) && (
          // isHttpUrl, not a truthiness check: this URL comes from a public feed
          // anyone can publish to, and React renders a `javascript:` href
          // happily. The sync gates it too; this covers rows an earlier sync
          // stored before that gate existed.
          <a href={row.incidentUrl!} target="_blank" rel="noopener noreferrer">
            supplychainattack.org incident ↗
          </a>
        )}
        <div style={{ marginTop: 6, opacity: 0.6, fontSize: 11 }}>
          Incident data: supplychainattack.org
        </div>
      </td>
    </tr>
  )
}

type PkgStatus = 'malicious' | 'vulnerable' | 'suspicious' | 'not analysed' | 'unverdictable' | 'clean'

const STATUS_CLASS: Record<PkgStatus, string> = {
  malicious: rowStyles.sevCritical,
  vulnerable: rowStyles.sevHigh,
  suspicious: rowStyles.sevMedium,
  'not analysed': rowStyles.sevInfo,
  unverdictable: rowStyles.sevInfo,
  clean: rowStyles.sevLow,
}

const STATUS_TITLE: Record<PkgStatus, string> = {
  malicious: 'An OSV MAL- advisory matched this package',
  vulnerable: 'One or more CVE/GHSA advisories match this version',
  // Tool-neutral on purpose: the packages sheet rolls up findings from several
  // tools, so naming GuardDog here mislabelled every non-GuardDog finding. The
  // per-tool wording lives on the verdict chip, where the tool is known.
  suspicious: 'Flagged as suspicious, not a terminal verdict (see the Verdicts sheet for which tool)',
  'not analysed': 'The behavioural pass never produced a verdict for this package',
  unverdictable:
    'No version was ever resolved, so osv-scanner could not match a version-specific advisory. This package was never actually checked.',
  clean: 'Verdicted with a version and nothing matched',
}

export function packageStatus(r: Pick<PackageRow, 'maliciousCount' | 'advisoryCount' | 'suspiciousCount' | 'notAnalysedCount' | 'version'>): PkgStatus {
  if (r.maliciousCount > 0) return 'malicious'
  if (r.advisoryCount > 0) return 'vulnerable'
  if (r.suspiciousCount > 0) return 'suspicious'
  if (r.notAnalysedCount > 0) return 'not analysed'
  if (!r.version) return 'unverdictable'
  return 'clean'
}

function StatusChip({ status }: { status: PkgStatus }) {
  return <span className={`${rowStyles.sevBadge} ${STATUS_CLASS[status]}`} title={STATUS_TITLE[status]}>{status}</span>
}

/**
 * Which layer put this package in the graph. Derived rather than stored: the
 * anchor label is the discriminator (L1 repo scans anchor to GithubRepository,
 * L1 uploads to the SbomDocument for the file, L2 to every served BaseURL).
 *
 * harvestSource stays only as a fallback for packages written before uploads
 * were anchored - it is a guess, the anchors are evidence.
 */
export function originOf(r: { repos: string[]; baseUrls: string[]; sboms: string[]; harvestSource: string | null }): string {
  if (r.repos.length > 0) return 'L1 repo'
  if (r.baseUrls.length > 0) return 'L2 live'
  if (r.sboms.length > 0) return 'L1 SBOM'
  if (r.harvestSource === 'osv') return 'L1 SBOM'
  if (r.harvestSource === 'finding') return 'from finding'
  return 'unanchored'
}

function AnchorCell({ row }: { row: { repos: string[]; baseUrls: string[]; sboms: string[] } }) {
  if (row.repos.length > 0) return <ListCell items={row.repos} max={2} />
  if (row.baseUrls.length > 0) return <LinkedListCell items={row.baseUrls} max={2} />
  if (row.sboms.length > 0) return <ListCell items={row.sboms} max={2} />
  return <span className={rowStyles.nullCell}>floating</span>
}

function VersionCell({ version }: { version: string | null }) {
  if (version) return <Mono>{version}</Mono>
  return (
    <span className={`${rowStyles.listChip}`} title="No version resolved, so this package could not be OSV-verdicted">
      no version
    </span>
  )
}

export function worstSeverity(list: string[]): Severity {
  let worst: Severity = 'unknown'
  for (const s of list) {
    const n = normalizeSeverity(s)
    if (SEVERITY_RANK[n] < SEVERITY_RANK[worst]) worst = n
  }
  return worst
}

// --------------------------------------------------------------------------

const EXPORT_COLUMNS: Record<SheetKey, { key: string; header: string }[]> = {
  verdicts: [
    NODE_ID_COLUMN,
    { key: 'verdict', header: 'Verdict' },
    { key: 'severity', header: 'Severity' },
    { key: 'advisoryId', header: 'Advisory / Rule' },
    { key: 'aliases', header: 'Aliases' },
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'sourceTool', header: 'Tool' },
    { key: 'confidence', header: 'Confidence' },
    { key: 'softError', header: 'Not Analysed' },
    { key: 'title', header: 'Title' },
    { key: 'detail', header: 'Detail' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'sboms', header: 'SBOM File' },
    { key: 'firstSeen', header: 'First Seen' },
    { key: 'lastSeen', header: 'Last Seen' },
    // Incident context (B). Declared here so the per-column filter engine and
    // the CSV export both pick them up; without this the columns exist in the
    // UI but cannot be filtered or exported.
    { key: 'incidentId', header: 'Incident' },
    { key: 'incidentStatus', header: 'Incident Status' },
    { key: 'incidentSummary', header: 'Incident Summary' },
    { key: 'incidentBlastRadius', header: 'Blast Radius' },
    { key: 'incidentRemediation', header: 'Remediation' },
    { key: 'incidentUrl', header: 'Incident URL' },
    { key: 'incidentFeedRevised', header: 'Feed Revision' },
    UPDATED_AT_COLUMN,
  ],
  packages: [
    NODE_ID_COLUMN,
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'maliciousCount', header: 'Malicious' },
    { key: 'suspiciousCount', header: 'Suspicious' },
    { key: 'notAnalysedCount', header: 'Not Analysed' },
    { key: 'advisoryCount', header: 'Advisories' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'sboms', header: 'SBOM File' },
    { key: 'firstSeen', header: 'First Seen' },
    { key: 'lastSeen', header: 'Last Seen' },
    UPDATED_AT_COLUMN,
  ],
  advisories: [
    NODE_ID_COLUMN,
    { key: 'advisoryId', header: 'Advisory' },
    { key: 'severity', header: 'Severity' },
    { key: 'cvss', header: 'CVSS' },
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'title', header: 'Title' },
    { key: 'description', header: 'Description' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'sboms', header: 'SBOM File' },
    { key: 'firstSeen', header: 'First Seen' },
    UPDATED_AT_COLUMN,
  ],
}

const SHEET_LABEL: Record<SheetKey, string> = {
  verdicts: 'Verdicts',
  packages: 'Packages',
  advisories: 'Advisories',
}

const SHEET_EMPTY: Record<SheetKey, string> = {
  verdicts:
    'No malicious or suspicious package verdicts. Enable Supply-Chain Recon on a scan, or run a Supply-Chain scan from Other Scans (the offline OSV DB must be synced first).',
  packages:
    'No packages harvested yet. L2 mines them from source maps, imports, detected technologies and retire.js during recon; L1 reads an uploaded SBOM/lockfile or a cloned repo.',
  advisories:
    'No CVE/GHSA advisories matched. Note that packages with no resolved version are never checked at all - see the "unversioned" count above.',
}

interface Props {
  projectId: string | null
  /** Sheet to pre-select, e.g. from `/graph?table=supplyChainSca&sheet=advisories`. */
  initialSheet?: string | null
}

function isSheetKey(v: string | null | undefined): v is SheetKey {
  return v === 'verdicts' || v === 'packages' || v === 'advisories'
}

export const SupplyChainScaTable = memo(function SupplyChainScaTable({ projectId, initialSheet }: Props) {
  const [data, setData] = useState<ScaResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState<SheetKey>(isSheetKey(initialSheet) ? initialSheet : 'verdicts')
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)
  // Per-finding incident detail disclosure (feature B). Keyed by findingId so a
  // re-sort or a filter change does not move the open panel to another row.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const toggleIncident = useCallback((findingId: string) => {
    setExpanded(prev => ({ ...prev, [findingId]: !prev[findingId] }))
  }, [])

  const fetchData = useCallback(async () => {
    if (!projectId) { setData(null); return }
    setIsLoading(true); setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/supplyChainSca?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) {
        const b = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        throw new Error(b.error || `HTTP ${res.status}`)
      }
      setData((await res.json()) as ScaResponse)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally { setIsLoading(false) }
  }, [projectId])

  // Muted rows are filtered server-side, so a mute anywhere means a refetch.
  const { epoch: muteEpoch } = useMuteNodeContext()
  useEffect(() => { fetchData() }, [fetchData, muteEpoch])

  // The three sheets have disjoint row shapes; the shell + text filter work on
  // plain records, and each table body narrows back to its own row type.
  const rows = useMemo(
    () => (data?.sheets?.[active] ?? []) as unknown as Record<string, unknown>[],
    [data, active])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  // The three sheets filter independently: their columns do not overlap, so a
  // verdict filter would be meaningless on the packages sheet.
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: EXPORT_COLUMNS[active], projectId, slug: 'supplyChainSca', sheet: active,
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const selectSheet = useCallback((key: SheetKey) => {
    setActive(key); setSearch(''); setLimit(PAGE_SIZE)
  }, [])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    filtered.length > 0
      ? { rows: sortedRows, sheetName: SHEET_LABEL[active], fileSlug: `supply-chain-sca-${active}`, columns: EXPORT_COLUMNS[active] }
      : undefined,
    [filtered, active])

  const m = data?.meta
  // The unversioned count is deliberately loud: those packages were inventoried
  // but never verdicted, so a short verdict list next to a big unversioned count
  // means "mostly unchecked", not "mostly clean".
  const meta = m
    ? [
        `packages: ${m.totalPackages}`,
        m.unversioned ? `unversioned (unchecked): ${m.unversioned}` : null,
        `malicious: ${m.malicious}`,
        `suspicious: ${m.suspicious}`,
        m.notAnalysed ? `not analysed: ${m.notAnalysed}` : null,
        `advisories: ${m.advisories}`,
        m.byEcosystem?.length ? m.byEcosystem.map(e => `${e.ecosystem} ${e.count}`).join(', ') : null,
        m.truncated?.[active] ? `SHEET CAPPED - showing the first ${rows.length}` : null,
      ].filter(Boolean).join(' · ')
    : undefined

  const counts: Record<SheetKey, number> = {
    verdicts: data?.sheets?.verdicts?.length ?? 0,
    packages: data?.sheets?.packages?.length ?? 0,
    advisories: data?.sheets?.advisories?.length ?? 0,
  }

  return (
    <RedZoneTableShell
      title="Supply-Chain SCA (packages, verdicts, advisories)"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder={`Search ${SHEET_LABEL[active].toLowerCase()}...`}
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={fetchData}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel={SHEET_EMPTY[active]}
      toolbar={(
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '8px 4px' }}>
          {(Object.keys(SHEET_LABEL) as SheetKey[]).map(key => {
            const isActive = key === active
            return (
              <button
                key={key}
                onClick={() => selectSheet(key)}
                style={{
                  fontSize: 12, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                  border: '1px solid ' + (isActive ? '#f59e0b' : 'rgba(255,255,255,0.15)'),
                  background: isActive ? 'rgba(245,158,11,0.15)' : 'transparent',
                  color: isActive ? '#f59e0b' : 'inherit', fontWeight: isActive ? 600 : 400,
                }}
              >
                {SHEET_LABEL[key]} <span style={{ opacity: 0.6 }}>({counts[key]})</span>
              </button>
            )
          })}
        </div>
      )}
    >
      {active === 'verdicts' ? (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <NodeIdTh />
              <th>Verdict</th><th>Sev</th><th>Advisory / Rule</th><th>Package</th>
              <th>Version</th><th>Eco</th><th>Tool</th><th>Origin</th>
              <th>Anchor</th><th>Title</th><th>Detail</th><th>Incident</th>
              <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
              <th />
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as VerdictRow[]).map((r, i) => (
              <Fragment key={r.findingId || `${r.purl}-${i}`}>
                <tr>
                  <td><NodeIdCell value={r.nodeId} /></td>
                  <td><VerdictChip row={r} /></td>
                  <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
                  <td>
                    <Mono>{r.advisoryId || '-'}</Mono>
                    {r.aliases.length > 0 && <ListCell items={r.aliases} max={2} />}
                  </td>
                  <td>{r.name ? <Mono>{r.name}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
                  <td><VersionCell version={r.version} /></td>
                  <td>{r.ecosystem || '-'}</td>
                  <td>{r.sourceTool || '-'}</td>
                  <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                  <td><AnchorCell row={r} /></td>
                  <td><Truncated text={r.title} max={240} /></td>
                  <td><Truncated text={r.detail} max={240} /></td>
                  <td><IncidentToggle row={r} open={!!expanded[r.findingId]} onToggle={toggleIncident} /></td>
                  <td><UpdatedAtCell value={r.updatedAt} /></td>
                  <td><MuteNodeButton name={r.name || r.purl} graphId={r.nodeId} nodeId={r.findingId} label="MalPackageFinding" /></td>
                </tr>
                {expanded[r.findingId] && <IncidentDetailRow row={r} />}
              </Fragment>
            ))}
          </tbody>
        </table>
      ) : active === 'packages' ? (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <NodeIdTh />
              <th>Status</th><th>Package</th><th>Version</th><th>Eco</th>
              <th>Harvest</th><th>Origin</th><th>Anchor</th>
              <th>Mal</th><th>Susp</th><th>Unchecked</th><th>Advisories</th><th>Worst</th>
              <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
              <th />
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as PackageRow[]).map((r, i) => (
              <tr key={r.purl || i}>
                <td><NodeIdCell value={r.nodeId} /></td>
                <td><StatusChip status={packageStatus(r)} /></td>
                <td>{r.name ? <Mono>{r.name}</Mono> : <Truncated text={r.purl} max={200} />}</td>
                <td><VersionCell version={r.version} /></td>
                <td>{r.ecosystem || '-'}</td>
                <td><span className={rowStyles.listChip}>{r.harvestSource || 'unknown'}</span></td>
                <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                <td><AnchorCell row={r} /></td>
                <td><NumCell value={r.maliciousCount} /></td>
                <td><NumCell value={r.suspiciousCount} /></td>
                <td><NumCell value={r.notAnalysedCount} /></td>
                <td><NumCell value={r.advisoryCount} /></td>
                <td>
                  {r.advisorySeverities.length > 0
                    ? <SeverityBadge severity={worstSeverity(r.advisorySeverities)} />
                    : <span className={rowStyles.nullCell}>-</span>}
                </td>
                <td><UpdatedAtCell value={r.updatedAt} /></td>
                <td><MuteNodeButton name={r.name || r.purl} graphId={r.nodeId} label="Package" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <NodeIdTh />
              <th>Advisory</th><th>Sev</th><th>CVSS</th><th>Package</th>
              <th>Version</th><th>Eco</th><th>Origin</th><th>Anchor</th>
              <th>Title</th><th>Description</th>
              <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
              <th />
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as AdvisoryRow[]).map((r, i) => (
              <tr key={`${r.advisoryId}-${r.purl}-${i}`}>
                <td><NodeIdCell value={r.nodeId} /></td>
                <td><Mono>{r.advisoryId}</Mono></td>
                <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
                <td>{r.cvss ? <Truncated text={r.cvss} max={200} /> : <span className={rowStyles.nullCell}>-</span>}</td>
                <td>{r.name ? <Mono>{r.name}</Mono> : <Truncated text={r.purl} max={200} />}</td>
                <td><VersionCell version={r.version} /></td>
                <td>{r.ecosystem || '-'}</td>
                <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                <td><AnchorCell row={r} /></td>
                <td><Truncated text={r.title} max={240} /></td>
                <td><Truncated text={r.description} max={280} /></td>
                <td><UpdatedAtCell value={r.updatedAt} /></td>
                <td><MuteNodeButton name={r.advisoryId} graphId={r.nodeId} nodeId={r.advisoryId} label="Vulnerability" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
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
