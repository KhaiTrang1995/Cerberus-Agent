'use client'

import { useState, useEffect, useCallback } from 'react'
import { X, Trash2, Loader2, FolderOpen } from 'lucide-react'
import { createPortal } from 'react-dom'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './UserPresetDrawer.module.css'
import provenanceStyles from './presetProvenance.module.css'
import {
  PRESET_FILTER_THRESHOLD,
  filterPresetsByName,
  mcpEditedLabel,
  type PresetProvenance,
} from './presetProvenance'

interface PresetListItem extends PresetProvenance {
  id: string
  name: string
  description: string
  createdAt: string
}

interface UserPresetDrawerProps {
  isOpen: boolean
  onClose: () => void
  /** Confirms, applies and (in edit mode) saves. Settles once that is done or declined. */
  onLoad: (preset: { id: string; name: string }) => Promise<void>
  userId: string | null | undefined
}

export function UserPresetDrawer({ isOpen, onClose, onLoad, userId }: UserPresetDrawerProps) {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()
  const [presets, setPresets] = useState<PresetListItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [loadingPresetId, setLoadingPresetId] = useState<string | null>(null)
  const [deletingPresetId, setDeletingPresetId] = useState<string | null>(null)
  const [nameFilter, setNameFilter] = useState('')

  useEffect(() => {
    if (!isOpen || !userId) return

    setIsLoading(true)
    fetch(`/api/presets?userId=${userId}`)
      .then(r => r.ok ? r.json() : [])
      .then(setPresets)
      .catch(() => {
        toast.error('Failed to load presets')
      })
      .finally(() => setIsLoading(false))
  }, [isOpen, userId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Close on Escape, unless a load owns the confirmation dialog: its own Escape
  // cancels it, and closing the drawer too would lose the user's place.
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape' && !loadingPresetId) onClose()
  }, [onClose, loadingPresetId])

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
      document.body.style.overflow = 'hidden'
      return () => {
        document.removeEventListener('keydown', handleKeyDown)
        document.body.style.overflow = ''
      }
    }
  }, [isOpen, handleKeyDown])

  const handleLoad = async (preset: PresetListItem) => {
    setLoadingPresetId(preset.id)
    try {
      await onLoad({ id: preset.id, name: preset.name })
    } finally {
      setLoadingPresetId(null)
    }
  }

  const handleDelete = async (preset: PresetListItem) => {
    const confirmed = await dangerConfirm(`Delete preset "${preset.name}"?`, 'Delete Preset', {
      confirmLabel: 'Delete',
    })
    if (!confirmed) return

    setDeletingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}?userId=${userId}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete preset')

      setPresets(prev => prev.filter(p => p.id !== preset.id))
      toast.success(`Preset "${preset.name}" deleted`, 'Preset Deleted')
    } catch {
      toast.error('Failed to delete preset')
    } finally {
      setDeletingPresetId(null)
    }
  }

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr)
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
  }

  if (!isOpen) return null

  const drawer = (
    <>
      <div className={styles.drawerOverlay} onClick={() => { if (!loadingPresetId) onClose() }} />

      <div className={styles.drawer} onClick={(e) => e.stopPropagation()}>
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>My Presets</h2>
          <button
            type="button"
            className={styles.drawerClose}
            onClick={onClose}
            aria-label="Close drawer"
          >
            <X size={14} />
          </button>
        </div>

        <div className={styles.drawerBody}>
          {isLoading ? (
            <div className={styles.loading}>
              <Loader2 size={20} className={styles.spinner} />
            </div>
          ) : presets.length === 0 ? (
            <div className={styles.emptyState}>
              <FolderOpen size={32} className={styles.emptyIcon} />
              <p>No saved presets yet.</p>
              <p>Use &quot;Save as Preset&quot; to create one.</p>
            </div>
          ) : (
            <>
            {presets.length > PRESET_FILTER_THRESHOLD && (
              <input
                type="search"
                className={`textInput ${provenanceStyles.filter}`}
                placeholder="Filter by name"
                aria-label="Filter presets by name"
                value={nameFilter}
                onChange={e => setNameFilter(e.target.value)}
              />
            )}
            {filterPresetsByName(presets, nameFilter).map(preset => (
              <div key={preset.id} className={styles.card}>
                <h3 className={styles.cardName}>{preset.name}</h3>
                {mcpEditedLabel(preset) && (
                  <span className={provenanceStyles.mcpBadge}>{mcpEditedLabel(preset)}</span>
                )}
                {preset.description && (
                  <p className={styles.cardDescription}>{preset.description}</p>
                )}
                <span className={styles.cardDate}>{formatDate(preset.createdAt)}</span>
                <div className={styles.cardActions}>
                  <button
                    type="button"
                    className={styles.deleteButton}
                    onClick={() => handleDelete(preset)}
                    disabled={deletingPresetId === preset.id}
                    aria-label="Delete preset"
                  >
                    <Trash2 size={12} />
                  </button>
                  <button
                    type="button"
                    className={styles.loadButton}
                    onClick={() => handleLoad(preset)}
                    disabled={loadingPresetId !== null}
                  >
                    {loadingPresetId === preset.id ? (
                      <>
                        <Loader2 size={12} className={styles.spinner} />
                        Loading...
                      </>
                    ) : (
                      'Load'
                    )}
                  </button>
                </div>
              </div>
            ))}
            </>
          )}
        </div>
      </div>
    </>
  )

  if (typeof document !== 'undefined') {
    return createPortal(drawer, document.body)
  }

  return null
}
