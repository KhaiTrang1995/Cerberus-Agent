'use client'

import { memo, useEffect, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneFilters } from './useRedZoneFilters'
import type { RedZoneExportConfig } from './exportCsv'
import {
  Mono, Truncated, UrlCell, NumCell, BoolChip, ListCell, SeverityBadge, filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import {
  UPDATED_AT_HEADER,
  UPDATED_AT_KEY,
  UpdatedAtCell,
  UpdatedAtTh,
  useUpdatedAtSort,
} from './updatedAt'
import { NODE_ID_HEADER, NODE_ID_KEY, NodeIdCell, NodeIdTh } from './nodeId'
import { MuteNodeButton, useMuteNodeContext } from '../MuteNode'
import rowStyles from './RedZoneTableRow.module.css'

type CellKind = 'url' | 'mono' | 'text' | 'bool' | 'num' | 'list' | 'sev' | 'date' | 'nodeId'

/**
 * Appended to every sheet at render time rather than written into each of the
 * eleven `SheetDef`s: the column is not a property of any one sheet, it is the
 * one column every sheet is guaranteed to have.
 */
const UPDATED_AT_CELL: ColumnDef = { key: UPDATED_AT_KEY, header: UPDATED_AT_HEADER, kind: 'date' }

/** Prepended the same way, so it is the leftmost column on every sheet. */
const NODE_ID_CELL: ColumnDef = { key: NODE_ID_KEY, header: NODE_ID_HEADER, kind: 'nodeId' }

interface ColumnDef { key: string; header: string; kind: CellKind; max?: number }
/**
 * The one graph node each of a sheet's rows stands for, for the Mute column.
 * Absent on a sheet whose rows aggregate several nodes: there is no one node to
 * mute there.
 */
interface SheetNode {
  label: string
  /** Row field naming the node in the mute confirm. */
  nameKey: string
  /** Row field carrying the finding's stored id, when the route projects it. */
  idKey?: string
}
interface SheetDef {
  key: string; label: string; columns: ColumnDef[]; empty: string; node?: SheetNode
}

interface MultiSheetProps {
  projectId: string | null
  slug: 'aiSurface' | 'aiRisk'
  title: string
  sheets: SheetDef[]
  /** Sheet key to pre-select (e.g. when deep-linked). Falls back to sheets[0]. */
  initialSheet?: string | null
}

function renderCell(kind: CellKind, value: unknown, max?: number) {
  switch (kind) {
    case 'url': return <UrlCell url={value as string | null} max={max ?? 260} />
    case 'mono': return value ? <Mono>{String(value)}</Mono> : <span>-</span>
    case 'bool': return <BoolChip value={value as boolean | null} />
    case 'num': return <NumCell value={value as number | null} />
    case 'list': return <ListCell items={(value as string[]) || []} max={max ?? 4} />
    case 'sev': return <SeverityBadge severity={normalizeSeverity(value as string)} />
    case 'date': return <UpdatedAtCell value={value} />
    case 'nodeId': return <NodeIdCell value={value} />
    default: return <Truncated text={value == null ? '' : String(value)} max={max ?? 200} />
  }
}

const MultiSheetTable = memo(function MultiSheetTable({ projectId, slug, title, sheets, initialSheet }: MultiSheetProps) {
  const [data, setData] = useState<{ sheets: Record<string, unknown[]> } | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState(
    sheets.some(s => s.key === initialSheet) ? (initialSheet as string) : sheets[0].key,
  )
  const [search, setSearch] = useState('')

  const fetchData = useMemo(() => async () => {
    if (!projectId) { setData(null); return }
    setIsLoading(true); setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/${slug}?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) {
        const b = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        throw new Error(b.error || `HTTP ${res.status}`)
      }
      setData(await res.json())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally { setIsLoading(false) }
  }, [projectId, slug])

  // Muted rows are filtered server-side, so a mute anywhere means a refetch.
  const { epoch: muteEpoch } = useMuteNodeContext()
  useEffect(() => { fetchData() }, [fetchData, muteEpoch])

  const sheet = sheets.find(s => s.key === active) ?? sheets[0]
  const columns = useMemo(() => [NODE_ID_CELL, ...sheet.columns, UPDATED_AT_CELL], [sheet])
  const allRows = useMemo(() => (data?.sheets?.[sheet.key] as Record<string, unknown>[]) ?? [], [data, sheet.key])
  const searched = useMemo(() => filterRowsByText(allRows, search), [allRows, search])
  // Each sheet has its own columns, so it filters - and remembers its filters -
  // independently of its siblings.
  const filterColumns = useMemo(
    () => columns.map(c => ({ key: c.key, header: c.header })),
    [columns],
  )
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: filterColumns, projectId, slug, sheet: sheet.key,
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    filtered.length > 0
      ? { rows: sortedRows, sheetName: sheet.label, fileSlug: `${slug}-${sheet.key}`,
          columns: filterColumns }
      : undefined,
    [filtered.length, sortedRows, sheet, slug, filterColumns])

  const counts = (data?.sheets ?? {}) as Record<string, unknown[]>
  const meta = sheets.map(s => `${s.label}: ${counts[s.key]?.length ?? 0}`).join(' · ')

  return (
    <RedZoneTableShell
      title={title}
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder={`Search ${sheet.label.toLowerCase()}...`}
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={fetchData}
      isLoading={isLoading}
      error={error}
      rowCount={allRows.length}
      filteredRowCount={filtered.length}
      emptyLabel={sheet.empty}
      toolbar={(
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '8px 4px' }}>
          {sheets.map(s => {
            const n = counts[s.key]?.length ?? 0
            const isActive = s.key === active
            return (
              <button
                key={s.key}
                onClick={() => { setActive(s.key); setSearch('') }}
                style={{
                  fontSize: 12, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                  border: '1px solid ' + (isActive ? '#f59e0b' : 'rgba(255,255,255,0.15)'),
                  background: isActive ? 'rgba(245,158,11,0.15)' : 'transparent',
                  color: isActive ? '#f59e0b' : 'inherit', fontWeight: isActive ? 600 : 400,
                }}
              >
                {s.label} <span style={{ opacity: 0.6 }}>({n})</span>
              </button>
            )
          })}
        </div>
      )}
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            {columns.map(c => (
              c.key === UPDATED_AT_KEY
                ? <UpdatedAtTh key={c.key} dir={sortDir} onToggle={toggleSort} />
                : c.key === NODE_ID_KEY
                  ? <NodeIdTh key={c.key} />
                  : <th key={c.key}>{c.header}</th>
            ))}
            <th />
          </tr>
        </thead>
        <tbody>
          {sortedRows.map((r, i) => (
            <tr key={i}>
              {columns.map(c => <td key={c.key}>{renderCell(c.kind, r[c.key], c.max)}</td>)}
              <td>
                {sheet.node && (
                  <MuteNodeButton
                    name={String(r[sheet.node.nameKey] ?? '')}
                    graphId={r[NODE_ID_KEY]}
                    nodeId={sheet.node.idKey ? (r[sheet.node.idKey] as string | null) : null}
                    label={sheet.node.label}
                  />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </RedZoneTableShell>
  )
})

// --------------------------------------------------------------------------- //
const AI_SURFACE_SHEETS: SheetDef[] = [
  { key: 'llmEndpoints', label: 'LLM Endpoints',
    node: { label: 'Endpoint', nameKey: 'path' },
    empty: 'No AI/LLM endpoints detected. Run a scan with AI Surface Recon enabled.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'interfaceType', header: 'Interface', kind: 'text' },
      { key: 'streaming', header: 'Stream', kind: 'bool' },
      { key: 'tools', header: 'Tools', kind: 'bool' },
      { key: 'vision', header: 'Vision', kind: 'bool' },
      { key: 'modelFamily', header: 'Model Family', kind: 'text' },
      { key: 'latencyMs', header: 'Latency (ms)', kind: 'num' },
      { key: 'ragIngest', header: 'RAG', kind: 'bool' },
      { key: 'framework', header: 'Framework', kind: 'text' },
      { key: 'source', header: 'Source', kind: 'text' },
    ] },
  { key: 'mcpServers', label: 'MCP Servers',
    node: { label: 'Endpoint', nameKey: 'path' },
    empty: 'No MCP servers detected.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'serverName', header: 'Server', kind: 'text' },
      { key: 'serverVersion', header: 'Version', kind: 'text' },
      { key: 'protocolVersion', header: 'Protocol', kind: 'text' },
      { key: 'toolCount', header: 'Tools', kind: 'num' },
      { key: 'resourceCount', header: 'Res', kind: 'num' },
      { key: 'promptCount', header: 'Prompts', kind: 'num' },
      { key: 'capabilities', header: 'Capabilities', kind: 'list' },
      { key: 'authRequired', header: 'Auth', kind: 'bool' },
      { key: 'toolsHash', header: 'Tools Hash', kind: 'mono', max: 16 },
    ] },
  { key: 'technologies', label: 'AI Technologies',
    node: { label: 'Technology', nameKey: 'name' },
    empty: 'No AI technologies fingerprinted.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'category', header: 'Category', kind: 'text' },
      { key: 'version', header: 'Version', kind: 'text' },
      { key: 'detectedBy', header: 'Detected By', kind: 'list' },
      { key: 'attachedTo', header: 'Attached', kind: 'num' },
    ] },
  { key: 'vectorDbs', label: 'Vector DBs',
    node: { label: 'Technology', nameKey: 'name' },
    empty: 'No vector databases confirmed.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'host', header: 'Host', kind: 'text' },
      { key: 'port', header: 'Port', kind: 'num' },
      { key: 'detectedBy', header: 'Detected By', kind: 'text' },
    ] },
  { key: 'models', label: 'Model Inventory',
    empty: 'No model IDs discovered.',
    columns: [
      { key: 'modelId', header: 'Model ID', kind: 'mono' },
      { key: 'family', header: 'Family', kind: 'text' },
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'sourceEndpoint', header: 'Source Endpoint', kind: 'mono' },
    ] },
]

const AI_RISK_SHEETS: SheetDef[] = [
  { key: 'findings', label: 'MCP Tool Poisoning',
    node: { label: 'Vulnerability', nameKey: 'name', idKey: 'findingId' },
    empty: 'No MCP tool-poisoning findings. Good - or MCP analysis was disabled.',
    columns: [
      { key: 'severity', header: 'Severity', kind: 'sev' },
      { key: 'type', header: 'Type', kind: 'text' },
      { key: 'name', header: 'Finding', kind: 'text', max: 300 },
      { key: 'owasp', header: 'OWASP-LLM', kind: 'text' },
      { key: 'atlas', header: 'ATLAS', kind: 'text' },
      { key: 'payloadClass', header: 'Class', kind: 'text' },
      { key: 'baseUrl', header: 'MCP Server', kind: 'url' },
      { key: 'endpointPath', header: 'Path', kind: 'mono' },
    ] },
  { key: 'injectableParams', label: 'Injectable Params',
    node: { label: 'Parameter', nameKey: 'name' },
    empty: 'No prompt-injectable parameters flagged.',
    columns: [
      { key: 'name', header: 'Parameter', kind: 'text' },
      { key: 'endpointPath', header: 'Endpoint', kind: 'mono' },
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'toolArgPath', header: 'Tool Arg Path', kind: 'mono' },
      { key: 'position', header: 'Position', kind: 'text' },
    ] },
  { key: 'ragPoints', label: 'RAG Ingestion',
    node: { label: 'Endpoint', nameKey: 'path' },
    empty: 'No RAG ingestion endpoints flagged.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'method', header: 'Method', kind: 'text' },
      { key: 'interfaceType', header: 'Interface', kind: 'text' },
    ] },
  { key: 'exposedRuntimes', label: 'Exposed Runtimes',
    node: { label: 'Technology', nameKey: 'name' },
    empty: 'No exposed AI runtimes or gateways.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'category', header: 'Category', kind: 'text' },
      { key: 'version', header: 'Version', kind: 'text' },
      { key: 'exposedOn', header: 'Exposed On', kind: 'list' },
    ] },
  { key: 'unauthenticatedMcp', label: 'Unauthenticated MCP',
    node: { label: 'Endpoint', nameKey: 'path' },
    empty: 'No unauthenticated MCP servers.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'serverName', header: 'Server', kind: 'text' },
      { key: 'toolCount', header: 'Tools', kind: 'num' },
    ] },
  { key: 'testedVulns', label: 'AI Gauntlet Vulnerabilities',
    empty: 'No AI Gauntlet findings yet. Run a garak / PyRIT / giskard / promptfoo scan.',
    columns: [
      { key: 'severity', header: 'Severity', kind: 'sev' },
      { key: 'owasp', header: 'OWASP-LLM', kind: 'text' },
      { key: 'attack', header: 'Attack', kind: 'text' },
      { key: 'target', header: 'Target', kind: 'url' },
      { key: 'foundBy', header: 'Found By', kind: 'list' },
      { key: 'asr', header: 'ASR', kind: 'text' },
      { key: 'trials', header: 'Trials', kind: 'num' },
      { key: 'evidence', header: 'Evidence', kind: 'text', max: 200 },
    ] },
]

interface Props { projectId: string | null }

export const AiSurfaceTable = memo(function AiSurfaceTable({ projectId }: Props) {
  return <MultiSheetTable projectId={projectId} slug="aiSurface" title="AI / LLM Attack Surface" sheets={AI_SURFACE_SHEETS} />
})

export const AiRiskTable = memo(function AiRiskTable({ projectId, initialSheet }: Props & { initialSheet?: string | null }) {
  return <MultiSheetTable projectId={projectId} slug="aiRisk" title="AI Risk (OWASP-LLM / ATLAS)" sheets={AI_RISK_SHEETS} initialSheet={initialSheet} />
})
