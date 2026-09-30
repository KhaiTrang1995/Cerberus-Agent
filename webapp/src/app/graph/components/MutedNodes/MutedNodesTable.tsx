'use client'

/**
 * Muted Nodes: every finding hidden from the graph, the agent, analytics and
 * reports, whether a person muted it, an external agent did over MCP on a
 * person's token, or a node-filter rule did.
 *
 * An agent's mutes are badged and filterable per token, and a person's Multi
 * mutes per batch, so one token's or one batch's work can be reviewed and
 * unmuted together.
 *
 * This is the ONLY place a muted finding is still visible, so it is also where
 * a mute is undone. Paged on the server, because a filter rule can mute
 * thousands of findings in one apply.
 *
 * Unmuting always records an exemption, so no filter rule mutes that node
 * again; undoing a whole rule is done on the Mute Rules page instead.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronLeft, ChevronRight, Download, Eye, Loader2, RotateCcw } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import { downloadBlob, timestampSlug, toGuardedCsv, CSV_MIME } from '../../utils/exportHelpers'
import {
  EMPTY_FILTERS, EXPORT_COLUMNS, EXPORT_MAX, PAGE_SIZE,
  exportRows, focusFilters, hasFilters, kindLabel, mutedByText, mutedQuery, stateText,
  type MutedFacets, type MutedFilters, type MutedNodesFocus, type MutedRow, type MutedVia,
} from './mutedNodes'
import { NodeIdCell, NodeIdTh } from '../RedZoneTables/nodeId'
import styles from './MutedNodesTable.module.css'

const UNMUTE_TITLE =
  'Rules will not mute it again. To undo a whole rule, disable it and apply to the current graph.'

function fmtWhen(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ')
}

interface MutedNodesTableProps {
  projectId: string | null
  /** Open the Mute Rules page at a rule. */
  onOpenRule?: (kind: string, ruleId: string) => void
  /** Open on these filters (Multi mute's "View muted": one batch). A new
   *  object re-applies them. */
  focus?: MutedNodesFocus | null
}

export function MutedNodesTable({ projectId, onOpenRule, focus }: MutedNodesTableProps) {
  const { userId } = useProject()
  const { alertError } = useAlertModal()
  const toast = useToast()

  const [filters, setFilters] = useState<MutedFilters>(() => focusFilters(focus))
  const [searchDraft, setSearchDraft] = useState('')
  const [offset, setOffset] = useState(0)
  const [rows, setRows] = useState<MutedRow[]>([])
  const [total, setTotal] = useState(0)
  const [facets, setFacets] = useState<MutedFacets | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [exporting, setExporting] = useState(false)
  const requestRef = useRef(0)

  // The page keeps this table mounted across a project switch. Filters and the
  // page belong to the project they were set on (a rule id means nothing in
  // another project), so they reset before the new project's first request.
  const [appliedFocus, setAppliedFocus] = useState(focus)
  if (appliedFocus !== focus) {
    setAppliedFocus(focus)
    if (focus) {
      setFilters(focusFilters(focus))
      setSearchDraft('')
      setOffset(0)
    }
  }
  const [shownProject, setShownProject] = useState(projectId)
  if (shownProject !== projectId) {
    setShownProject(projectId)
    setFilters(EMPTY_FILTERS)
    setSearchDraft('')
    setOffset(0)
    setFacets(null)
    setSelected(new Set())
  }

  // The search box is debounced so typing does not fire a graph query per key.
  // Only a real change resets the page: this also runs on mount, where an
  // unconditional reset bounced a page turned in the first 350 ms back to 1.
  useEffect(() => {
    if (searchDraft === filters.search) return
    const t = setTimeout(() => {
      setFilters(f => ({ ...f, search: searchDraft }))
      setOffset(0)
    }, 350)
    return () => clearTimeout(t)
  }, [searchDraft, filters.search])

  const load = useCallback(async () => {
    if (!projectId) return
    const request = ++requestRef.current
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(mutedQuery(projectId, filters, { offset, limit: PAGE_SIZE }, true))
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || `Muted Nodes: ${res.status}`)
      // An older, slower response must not overwrite a newer filter's result.
      if (request !== requestRef.current) return
      const count = Number(body.total ?? 0)
      if ((body.findings ?? []).length === 0 && offset > 0) {
        // The page emptied (its rows were unmuted): go to the last page that
        // still has rows, rather than an empty table with no pager to leave by.
        setOffset(count > 0 ? Math.floor((count - 1) / PAGE_SIZE) * PAGE_SIZE : 0)
        return
      }
      setRows(body.findings ?? [])
      setTotal(body.total ?? 0)
      if (body.facets) setFacets(body.facets)
      setSelected(new Set())
    } catch (e) {
      if (request === requestRef.current) {
        setError(e instanceof Error ? e.message : 'Could not load the muted nodes')
      }
    } finally {
      if (request === requestRef.current) setLoading(false)
    }
  }, [projectId, filters, offset])

  useEffect(() => { void load() }, [load])

  const setFilter = useCallback(<K extends keyof MutedFilters>(key: K, value: MutedFilters[K]) => {
    setFilters(f => ({ ...f, [key]: value }))
    setOffset(0)
  }, [])

  const clearFilters = useCallback(() => {
    setFilters(EMPTY_FILTERS)
    setSearchDraft('')
    setOffset(0)
  }, [])

  const unmute = useCallback(async (keys: string[]) => {
    if (!projectId || keys.length === 0) return
    setBusy(true)
    try {
      const res = await fetch('/api/triage/unmute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, keys }),
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || 'The findings could not be unmuted.')
      const n = Number(body.unmuted ?? 0)
      if (n === 0) {
        // The node was replaced (a rescan or an activation) since this page loaded.
        toast.warning('Nothing was unmuted: the list was out of date and has been reloaded.')
      } else if (body.exemptionError) {
        toast.warning(String(body.exemptionError))
      } else {
        toast.success(n === 1 ? 'Unmuted. It is visible again everywhere.' : `Unmuted ${n} findings.`)
      }
      await load()
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Unmute failed', 'Unmute')
    } finally {
      setBusy(false)
    }
  }, [projectId, toast, alertError, load])

  const runExport = useCallback(async (format: 'csv' | 'json') => {
    if (!projectId) return
    setExportOpen(false)
    setExporting(true)
    try {
      const res = await fetch(mutedQuery(projectId, filters, { offset: 0, limit: EXPORT_MAX }))
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || `Export: ${res.status}`)
      const all: MutedRow[] = body.findings ?? []
      const out = exportRows(all, userId)
      const name = `muted-nodes-${timestampSlug()}`
      if (format === 'csv') {
        // Finding names and hosts are scanner-controlled, so every cell is
        // guarded against spreadsheet formula injection.
        downloadBlob(toGuardedCsv([...EXPORT_COLUMNS], out), `${name}.csv`, CSV_MIME)
      } else {
        downloadBlob(JSON.stringify(out, null, 2), `${name}.json`, 'application/json')
      }
      if ((body.total ?? all.length) > all.length) {
        toast.warning(`Exported the first ${all.length.toLocaleString()} of ${Number(body.total).toLocaleString()} muted nodes.`)
      }
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Export failed', 'Export')
    } finally {
      setExporting(false)
    }
  }, [projectId, filters, userId, toast, alertError])

  const labelOptions = useMemo(
    () => Object.entries(facets?.labels ?? {}).sort((a, b) => b[1] - a[1]), [facets])
  const ruleOptions = facets?.rules ?? []
  const tokenOptions = facets?.tokens ?? []
  const batchOptions = facets?.batches ?? []
  // A batch opened from Multi mute may be missing from the facets (all of it
  // unmuted since); it stays selectable so the filter still reads right.
  const unlistedToken = filters.token
    && !tokenOptions.some(t => t.token === filters.token)
    && !batchOptions.some(b => b.batch === filters.token)

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const page = Math.floor(offset / PAGE_SIZE) + 1
  const allSelected = rows.length > 0 && rows.every(r => selected.has(r.id))
  const filtered = hasFilters(filters)

  const toggle = (id: string) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })

  if (!projectId) {
    return <div className={styles.empty}>Select a project to see its muted nodes.</div>
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.header}>
        <h3 className={styles.heading}>
          Muted Nodes <span className={styles.count}>· {total.toLocaleString()}</span>
        </h3>
        <p className={styles.note}>
          Hidden from the graph, reports and the AI agent. This is the only place they are still visible.
        </p>
      </div>

      <div className={styles.toolbar}>
        <select
          className={styles.select}
          value={filters.label}
          onChange={e => setFilter('label', e.target.value)}
          aria-label="Kind"
        >
          <option value="">All kinds</option>
          {labelOptions.map(([label, count]) => (
            <option key={label} value={label}>{label} ({count})</option>
          ))}
        </select>
        <select
          className={styles.select}
          value={filters.mutedVia}
          onChange={e => setFilter('mutedVia', e.target.value as MutedVia)}
          aria-label="Muted by"
        >
          <option value="all">Muted by: all</option>
          <option value="person">People</option>
          <option value="multi">Multi mute{facets?.by_multi !== undefined ? ` (${facets.by_multi})` : ''}</option>
          <option value="mcp">Agent (MCP){facets?.by_mcp !== undefined ? ` (${facets.by_mcp})` : ''}</option>
          <option value="rule">Rules</option>
          <option value="deleted_rule">Deleted rules</option>
        </select>
        <select
          className={styles.select}
          value={filters.rule}
          onChange={e => setFilter('rule', e.target.value)}
          aria-label="Rule"
          disabled={ruleOptions.length === 0}
        >
          <option value="">Any rule</option>
          {ruleOptions.map(r => (
            <option key={r.muted_by} value={r.muted_by}>
              {r.rule_deleted ? `(deleted) ${r.reason || r.muted_by}` : r.rule_name ?? r.muted_by} ({r.count})
            </option>
          ))}
        </select>
        <select
          className={styles.select}
          value={filters.token}
          onChange={e => setFilter('token', e.target.value)}
          aria-label="Token"
          disabled={tokenOptions.length === 0 && batchOptions.length === 0 && !filters.token}
          title="The mutes one access token made, or one Multi mute batch"
        >
          <option value="">Any token</option>
          {tokenOptions.length > 0 && (
            <optgroup label="Access tokens">
              {tokenOptions.map(t => (
                <option key={t.token} value={t.token}>{t.token} ({t.count})</option>
              ))}
            </optgroup>
          )}
          {batchOptions.length > 0 && (
            <optgroup label="Multi mute batches">
              {batchOptions.map(b => (
                <option key={b.batch} value={b.batch}>{b.batch} ({b.count})</option>
              ))}
            </optgroup>
          )}
          {unlistedToken && <option value={filters.token}>{filters.token}</option>}
        </select>
        <input
          className={styles.search}
          type="search"
          placeholder="Search name, host, id…"
          value={searchDraft}
          onChange={e => setSearchDraft(e.target.value)}
          aria-label="Search muted nodes"
        />
        <div className={styles.spacer} />
        <div className={styles.exportWrap}>
          <button
            className={styles.button}
            onClick={() => setExportOpen(o => !o)}
            disabled={exporting || total === 0}
            aria-haspopup="menu"
            aria-expanded={exportOpen}
          >
            {exporting ? <Loader2 size={12} className={styles.spin} /> : <Download size={12} />}
            Export
          </button>
          {exportOpen && (
            <div className={styles.exportMenu} role="menu">
              <button className={styles.exportItem} role="menuitem" onClick={() => void runExport('csv')}>CSV</button>
              <button className={styles.exportItem} role="menuitem" onClick={() => void runExport('json')}>JSON</button>
            </div>
          )}
        </div>
        <button
          className={styles.button}
          disabled={busy || selected.size === 0}
          onClick={() => void unmute([...selected])}
          title={UNMUTE_TITLE}
        >
          <Eye size={12} /> Unmute selected{selected.size > 0 ? ` (${selected.size})` : ''}
        </button>
      </div>

      {error ? (
        <div className={styles.error} role="alert">
          <p>{error}</p>
          <button className={styles.button} onClick={() => void load()}>
            <RotateCcw size={12} /> Retry
          </button>
        </div>
      ) : loading && rows.length === 0 ? (
        <div className={styles.tableScroll} aria-busy="true">
          <table className={styles.table}>
            <tbody>
              {Array.from({ length: 6 }, (_, i) => (
                <tr key={i} className={styles.skeletonRow}>
                  {Array.from({ length: 8 }, (__, j) => (
                    <td key={j}><div className={styles.skeletonBar} /></td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : rows.length === 0 ? (
        <div className={styles.empty}>
          {filtered ? (
            <>
              <p>No muted nodes match these filters.</p>
              <button className={styles.button} onClick={clearFilters}>Clear filters</button>
            </>
          ) : (
            <p>Nothing is muted in this project.</p>
          )}
        </div>
      ) : (
        <>
          <div className={styles.tableScroll}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.checkCell}>
                    <input
                      type="checkbox"
                      aria-label="Select all on this page"
                      checked={allSelected}
                      onChange={() => setSelected(allSelected ? new Set() : new Set(rows.map(r => r.id)))}
                    />
                  </th>
                  <NodeIdTh />
                  <th>Kind</th>
                  <th>Name</th>
                  <th>Sev</th>
                  <th>Muted by</th>
                  <th>When</th>
                  <th>State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={`${row.label}:${row.id}`}>
                    <td className={styles.checkCell}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.name || row.id}`}
                        checked={selected.has(row.id)}
                        onChange={() => toggle(row.id)}
                      />
                    </td>
                    <td><NodeIdCell value={row.node_id} /></td>
                    <td className={styles.nowrap}>{kindLabel(row)}</td>
                    <td className={styles.name}>
                      {row.name || row.id}
                      {row.host && <span className={styles.kindSource}>{row.host}</span>}
                    </td>
                    <td>
                      <span className={`${styles.sev} ${styles[(row.severity || '').toLowerCase()] ?? ''}`}>
                        {row.severity || '-'}
                      </span>
                    </td>
                    <td className={styles.mutedBy}>
                      {row.muted_via === 'rule' && !row.rule_deleted && onOpenRule && row.rule_kind && row.rule_id ? (
                        <button
                          className={styles.ruleLink}
                          onClick={() => onOpenRule(row.rule_kind!, row.rule_id!)}
                          title="Open this rule in Mute Rules"
                        >
                          {mutedByText(row, userId)}
                        </button>
                      ) : row.muted_via === 'mcp' ? (
                        <>
                          <span
                            className={styles.agentBadge}
                            title="Muted by an external agent over MCP, on an access token of this project's owner"
                          >
                            {mutedByText(row, userId)}
                          </span>
                          {row.muted_reason && <span className={styles.mutedReason}>{row.muted_reason}</span>}
                        </>
                      ) : row.muted_via === 'multi' ? (
                        <>
                          <span
                            className={styles.multiBadge}
                            title="Muted by a person in bulk, from Multi mute's AI suggestions: not judged one by one"
                          >
                            {mutedByText(row, userId)}
                          </span>
                          {row.muted_reason && <span className={styles.mutedReason}>{row.muted_reason}</span>}
                        </>
                      ) : (
                        <span className={row.rule_deleted ? styles.ruleDeleted : undefined}>
                          {mutedByText(row, userId)}
                        </span>
                      )}
                    </td>
                    <td className={styles.nowrap}>{fmtWhen(row.muted_at)}</td>
                    <td>
                      {row.stale_since ? <span className={styles.resolved}>{stateText(row)}</span> : '-'}
                    </td>
                    <td>
                      <button
                        className={styles.unmuteButton}
                        disabled={busy}
                        onClick={() => void unmute([row.id])}
                        title={UNMUTE_TITLE}
                      >
                        <Eye size={12} /> Unmute
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.pager}>
            {loading && <Loader2 size={12} className={styles.spin} />}
            <span>{PAGE_SIZE} per page · {page} of {pageCount}</span>
            <button
              className={styles.button}
              disabled={offset === 0 || loading}
              onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))}
              aria-label="Previous page"
            >
              <ChevronLeft size={12} />
            </button>
            <button
              className={styles.button}
              disabled={page >= pageCount || loading}
              onClick={() => setOffset(o => o + PAGE_SIZE)}
              aria-label="Next page"
            >
              <ChevronRight size={12} />
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export default MutedNodesTable
