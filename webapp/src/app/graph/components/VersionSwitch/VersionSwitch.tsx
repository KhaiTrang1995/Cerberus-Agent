'use client'

import { useState, useRef, useEffect } from 'react'
import { History, ChevronDown, Check, Loader2, Radio } from 'lucide-react'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'
import styles from './VersionSwitch.module.css'

interface VersionSwitchProps {
  versions: ScanVersionSummary[]
  /** null = the current (active) version is selected. */
  selectedVersionId: string | null
  onSelect: (versionId: string | null) => void
  /** Opens the Version Manager (rename / delete / activate). */
  onManage?: () => void
  /** True while this project's live graph is being swapped. */
  activating?: boolean
  isLoading?: boolean
}

function formatCount(n: number | null): string {
  if (n === null || n === undefined) return '-'
  return n.toLocaleString()
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

/**
 * Scan Timeline version picker (Section 4.2).
 *
 * Selecting a past version only changes what is RENDERED - it never touches the
 * live graph. The version the agent and every analytics panel actually work on is
 * the one marked "Active"; making a different one active is a separate, explicit
 * step in the Version Manager.
 */
export function VersionSwitch({
  versions,
  selectedVersionId,
  onSelect,
  onManage,
  activating = false,
  isLoading = false,
}: VersionSwitchProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    // Escape must dismiss it and hand focus back, or a keyboard user who opens
    // the dropdown is stranded inside it.
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      setOpen(false)
      triggerRef.current?.focus()
    }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const current = versions.find(v => v.isCurrent) ?? null
  const selected = selectedVersionId
    ? versions.find(v => v.id === selectedVersionId) ?? null
    : current
  const viewingPast = !!selectedVersionId && selectedVersionId !== current?.id

  if (!isLoading && versions.length === 0) return null

  return (
    <div className={styles.wrapper} ref={ref}>
      <button
        ref={triggerRef}
        className={`${styles.trigger} ${viewingPast ? styles.triggerPast : ''}`}
        onClick={() => setOpen(o => !o)}
        aria-label={`Scan version: ${activating ? 'activating' : selected ? selected.label : 'none selected'}`}
        title={viewingPast
          ? 'Viewing a past version (read-only). The agent and analytics use the active version.'
          : 'Scan version'}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        {activating ? <Loader2 size={13} className={styles.spinner} /> : <History size={13} />}
        <span className={styles.triggerLabel}>
          {activating ? 'Activating…' : selected ? selected.label : 'Versions'}
        </span>
        {viewingPast && <span className={styles.pastBadge}>read-only</span>}
        <ChevronDown size={13} />
      </button>

      {open && (
        <div className={styles.dropdown} role="listbox">
          <div className={styles.header}>Scan versions</div>
          <div className={styles.list}>
            {versions.map(v => {
              const isSelected = v.id === (selected?.id ?? null)
              return (
                <button
                  key={v.id}
                  role="option"
                  aria-selected={isSelected}
                  className={`${styles.item} ${isSelected ? styles.itemActive : ''}`}
                  onClick={() => { onSelect(v.isCurrent ? null : v.id); setOpen(false) }}
                >
                  <span className={styles.itemCheck}>{isSelected && <Check size={12} />}</span>
                  <span className={styles.itemBody}>
                    <span className={styles.itemLabel}>
                      {v.label}
                      {v.isCurrent && (
                        <span className={styles.activeBadge} title="This version is the live graph the agent works on">
                          <Radio size={9} /> Active
                        </span>
                      )}
                    </span>
                    <span className={styles.itemMeta}>
                      v{v.seq} · {formatDate(v.createdAt)} · {formatCount(v.nodeCount)} nodes
                      {!v.isCurrent && !v.activatable && ' · no snapshot'}
                      {typeof v.degradedSources === 'number' && v.degradedSources > 0
                        && ` · partial — ${v.degradedSources} source${v.degradedSources === 1 ? '' : 's'} skipped`}
                    </span>
                  </span>
                </button>
              )
            })}
          </div>
          {onManage && (
            <button className={styles.manage} onClick={() => { setOpen(false); onManage() }}>
              Manage versions…
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export default VersionSwitch
