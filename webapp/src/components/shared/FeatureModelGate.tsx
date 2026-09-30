'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { ExternalLink, Loader2, RotateCw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { useProject } from '@/providers/ProjectProvider'
import type { ModelOption } from '@/app/graph/components/AIAssistantDrawer/modelUtils'
import {
  GATE_CODES,
  featureModelMessage,
  getLlmFeature,
  modelAllowedForFeature,
  readFeatureModelCode,
  type FeatureId,
} from '@/lib/llmFeatures'
import styles from './FeatureModelGate.module.css'

// ---------------------------------------------------------------------------
// Client calls shared by the gate and the Models by feature section
// ---------------------------------------------------------------------------

export type ModelsByProvider = Record<string, ModelOption[]>

function stringMap(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  return Object.fromEntries(
    Object.entries(raw as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === 'string'),
  )
}

/** The user's selectable models, grouped by provider (the /api/models answer). */
export async function fetchModelOptions(userId: string): Promise<ModelsByProvider> {
  const res = await fetch('/api/models', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId }),
    cache: 'no-store',
  })
  if (!res.ok) throw new Error(`/api/models answered ${res.status}`)
  const data = await res.json()
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.error) {
    throw new Error('/api/models returned no model list')
  }
  return data as ModelsByProvider
}

export async function fetchSavedFeatureModels(userId: string): Promise<Record<string, string>> {
  const res = await fetch(`/api/users/${encodeURIComponent(userId)}/settings`)
  if (!res.ok) throw new Error(`Could not read your settings (${res.status})`)
  const data = await res.json()
  return stringMap(data?.featureModels)
}

/** Save one feature's model ('' clears it). Resolves with the whole saved map. */
export async function saveFeatureModel(
  userId: string,
  featureId: FeatureId,
  model: string,
): Promise<Record<string, string>> {
  const res = await fetch(`/api/users/${encodeURIComponent(userId)}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ featureModels: { [featureId]: model } }),
  })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new Error(typeof body?.error === 'string' ? body.error : `Could not save the model (${res.status})`)
  }
  return stringMap(body?.featureModels)
}

export function countModels(models: ModelsByProvider, keep?: (id: string) => boolean): number {
  let n = 0
  for (const list of Object.values(models)) {
    for (const m of list) if (!keep || keep(m.id)) n++
  }
  return n
}

export const SETTINGS_PROVIDERS_URL = '/settings?tab=providers'

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

export interface FeatureModelGateProps {
  featureId: FeatureId
  userId: string | null
  /** Shown above the picker, e.g. why the saved model could not be used. */
  message?: string
  /** Render the body alone, for embedding in another dialog. */
  inline?: boolean
  confirmLabel?: string
  onSaved: (model: string) => void
  onCancel: () => void
}

type LoadState = 'loading' | 'ready' | 'error'

/**
 * Asks for the model a feature runs on and saves it to the user's settings.
 * Only the models this feature may use are listed, and there is no free-text
 * fallback: a typed id could name a provider the user does not have.
 */
export function FeatureModelGate({
  featureId,
  userId,
  message,
  inline = false,
  confirmLabel = 'Save and continue',
  onSaved,
  onCancel,
}: FeatureModelGateProps) {
  const feature = getLlmFeature(featureId)
  const [models, setModels] = useState<ModelsByProvider>({})
  const [loadState, setLoadState] = useState<LoadState>('loading')
  const [picked, setPicked] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const allowed = useCallback((id: string) => modelAllowedForFeature(featureId, id), [featureId])

  const load = useCallback(async () => {
    if (!userId) {
      setLoadState('error')
      return
    }
    setLoadState('loading')
    try {
      setModels(await fetchModelOptions(userId))
      setLoadState('ready')
    } catch {
      setLoadState('error')
    }
  }, [userId])

  useEffect(() => { void load() }, [load])

  const total = countModels(models)
  const usable = countModels(models, allowed)

  const save = async () => {
    if (!userId || !picked || saving) return
    setSaving(true)
    setSaveError(null)
    try {
      await saveFeatureModel(userId, featureId, picked)
      onSaved(picked)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Could not save the model')
    } finally {
      setSaving(false)
    }
  }

  const providerActions = (
    <div className={styles.inlineActions}>
      <button
        type="button"
        className="secondaryButton"
        onClick={() => window.open(SETTINGS_PROVIDERS_URL, '_blank', 'noopener')}
      >
        <ExternalLink size={12} /> Add provider
      </button>
      <button type="button" className="secondaryButton" onClick={() => void load()}>
        <RotateCw size={12} /> Check again
      </button>
    </div>
  )

  const body = (
    <div className={styles.body}>
      <div>
        {inline && <div className={styles.featureName}>{feature.label}</div>}
        <p className={styles.featureDescription}>{feature.description}</p>
      </div>

      {message && <div className={styles.message} role="alert">{message}</div>}

      {loadState === 'loading' && (
        <div className={styles.status}><Loader2 size={14} className={styles.spin} /> Loading your models...</div>
      )}

      {loadState === 'error' && (
        <div className={styles.emptyBox}>
          <span>Couldn&apos;t load your models.</span>
          <div className={styles.inlineActions}>
            <button type="button" className="secondaryButton" onClick={() => void load()}>
              <RotateCw size={12} /> Check again
            </button>
          </div>
        </div>
      )}

      {loadState === 'ready' && total === 0 && (
        <div className={styles.emptyBox}>
          <span className={styles.emptyTitle}>You have no LLM provider yet</span>
          <span>Add one in Global Settings, then check again.</span>
          {providerActions}
        </div>
      )}

      {loadState === 'ready' && total > 0 && usable === 0 && (
        <div className={styles.emptyBox}>
          <span className={styles.emptyTitle}>None of your models can run {feature.label}</span>
          <span>{feature.hint}</span>
          {providerActions}
        </div>
      )}

      {loadState === 'ready' && usable > 0 && (
        <div className={styles.pickerField}>
          <ModelPicker
            userId={userId}
            value={picked}
            onChange={setPicked}
            models={models}
            hideManualFallback
            filter={allowed}
            disabled={saving}
            emptyLabel="Choose a model"
          />
          <span className={styles.hint}>{feature.hint}</span>
        </div>
      )}

      {saveError && <div className={styles.error} role="alert">{saveError}</div>}

      <p className={styles.note}>
        Saved for your account; also in Global Settings → LLM Providers → Models by feature
      </p>
    </div>
  )

  const buttons = (
    <>
      <button type="button" className="secondaryButton" onClick={onCancel} disabled={saving}>
        Cancel
      </button>
      <button
        type="button"
        className="primaryButton"
        onClick={() => void save()}
        disabled={!picked || saving}
      >
        {saving && <Loader2 size={12} className={styles.spin} />}
        {confirmLabel}
      </button>
    </>
  )

  if (inline) {
    return (
      <div className={styles.inline}>
        {body}
        <div className={styles.inlineFooter}>{buttons}</div>
      </div>
    )
  }

  return (
    <Modal
      isOpen
      onClose={saving ? () => {} : onCancel}
      title={`Choose a model for ${feature.label}`}
      className={styles.dialog}
      footer={buttons}
    >
      {body}
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Provider + hook
// ---------------------------------------------------------------------------

export interface EnsureFeatureModelOptions {
  /** Open the gate even when a model is saved (the saved one failed, or the user asked to change it). */
  force?: boolean
  message?: string
}

export interface FeatureModelGateApi {
  /**
   * The model to run `featureId` on: the saved one, else the one the user
   * picks in the gate. null when the user cancels.
   */
  ensureFeatureModel: (featureId: FeatureId, opts?: EnsureFeatureModelOptions) => Promise<string | null>
  /**
   * Run a request that may answer model_required / model_unavailable. On
   * either, the gate opens and, once a model is picked, the request runs ONE
   * more time. Any other answer, including every agent_* and
   * providers_unreachable code, comes back untouched: another model would not
   * fix those, so the caller shows featureModelMessage(code) instead.
   */
  fetchWithFeatureModel: (featureId: FeatureId, doFetch: () => Promise<Response>) => Promise<Response>
  /** Whose models the gate reads and saves; null outside the provider. */
  userId: string | null
  /** Bumped whenever the gate saves a model, so lines showing one can refetch. */
  savedVersion: number
}

// Without a provider mounted the hook degrades to "no gate": the request runs
// as is and ensureFeatureModel answers null, so a component rendered on its
// own (in a test, say) behaves exactly as it did before the gate existed.
const NO_GATE: FeatureModelGateApi = {
  ensureFeatureModel: async () => null,
  fetchWithFeatureModel: (_featureId, doFetch) => doFetch(),
  userId: null,
  savedVersion: 0,
}

const FeatureModelGateContext = createContext<FeatureModelGateApi>(NO_GATE)

export function useFeatureModelGate(): FeatureModelGateApi {
  return useContext(FeatureModelGateContext)
}

interface PendingGate {
  id: number
  featureId: FeatureId
  message?: string
  resolve: (model: string | null) => void
}

export function FeatureModelGateProvider({ children }: { children: ReactNode }) {
  const { userId } = useProject()
  const [open, setOpen] = useState<PendingGate | null>(null)
  const [savedVersion, setSavedVersion] = useState(0)
  // The promise of the gate on screen. A second request settles the first
  // with null (cancelled) rather than leaving its caller waiting forever.
  const pendingRef = useRef<PendingGate | null>(null)
  const seqRef = useRef(0)

  const openGate = useCallback((featureId: FeatureId, message?: string) => {
    return new Promise<string | null>(resolve => {
      pendingRef.current?.resolve(null)
      const next: PendingGate = { id: ++seqRef.current, featureId, message, resolve }
      pendingRef.current = next
      setOpen(next)
    })
  }, [])

  // Settles the gate `id` only. A gate replaced while it was saving still
  // finishes its save, and its answer belongs to a request already settled
  // with null, never to the gate on screen now (another feature's, maybe).
  const settle = useCallback((id: number, model: string | null) => {
    if (model) setSavedVersion(v => v + 1)
    const pending = pendingRef.current
    if (!pending || pending.id !== id) return
    pendingRef.current = null
    setOpen(null)
    pending.resolve(model)
  }, [])

  const ensureFeatureModel = useCallback(async (featureId: FeatureId, opts: EnsureFeatureModelOptions = {}) => {
    if (!userId) return null
    if (!opts.force) {
      try {
        const saved = (await fetchSavedFeatureModels(userId))[featureId]
        if (saved) return saved
      } catch {
        // Unreadable settings: asking is better than blocking the action.
      }
    }
    return openGate(featureId, opts.message)
  }, [userId, openGate])

  const fetchWithFeatureModel = useCallback(async (featureId: FeatureId, doFetch: () => Promise<Response>) => {
    const res = await doFetch()
    if (res.ok) return res
    const body: unknown = await res.clone().json().catch(() => null)
    const code = readFeatureModelCode(body)
    if (!code || !GATE_CODES.includes(code)) return res
    const failedModel = (body as { model?: unknown }).model
    const model = await ensureFeatureModel(featureId, {
      force: true,
      message: code === 'model_unavailable'
        ? featureModelMessage('model_unavailable', typeof failedModel === 'string' ? failedModel : undefined)
        : undefined,
    })
    return model ? doFetch() : res
  }, [ensureFeatureModel])

  const api = useMemo(
    () => ({ ensureFeatureModel, fetchWithFeatureModel, userId, savedVersion }),
    [ensureFeatureModel, fetchWithFeatureModel, userId, savedVersion],
  )

  return (
    <FeatureModelGateContext.Provider value={api}>
      {children}
      {open && (
        <FeatureModelGate
          key={open.id}
          featureId={open.featureId}
          userId={userId}
          message={open.message}
          onSaved={model => settle(open.id, model)}
          onCancel={() => settle(open.id, null)}
        />
      )}
    </FeatureModelGateContext.Provider>
  )
}

// ---------------------------------------------------------------------------
// "Model: X · Change", shown next to the button that runs a feature
// ---------------------------------------------------------------------------

type LineState = { kind: 'loading' } | { kind: 'error' } | { kind: 'ready'; model: string }

/**
 * The saved model of a feature, with a link that reopens the gate to change
 * it. Renders nothing outside the provider, so a component tested on its own
 * makes no settings request.
 */
export function FeatureModelLine({
  featureId,
  label = 'Model',
  className,
}: {
  featureId: FeatureId
  label?: string
  className?: string
}) {
  const { userId, savedVersion, ensureFeatureModel } = useFeatureModelGate()
  const [state, setState] = useState<LineState>({ kind: 'loading' })

  useEffect(() => {
    if (!userId) return
    let live = true
    fetchSavedFeatureModels(userId)
      .then(map => { if (live) setState({ kind: 'ready', model: map[featureId] ?? '' }) })
      .catch(() => { if (live) setState({ kind: 'error' }) })
    return () => { live = false }
  }, [userId, featureId, savedVersion])

  if (!userId) return null

  const model = state.kind === 'ready' ? state.model : ''
  const shown = state.kind === 'loading' ? '...' : state.kind === 'error' ? 'unknown' : model || 'not set'

  return (
    <span className={`${styles.line} ${className ?? ''}`} data-feature-model={featureId}>
      <span>{label}:</span>
      <span className={styles.lineValue} title={model || undefined}>{shown}</span>
      <span aria-hidden="true">·</span>
      <button
        type="button"
        className={styles.lineChange}
        onClick={() => void ensureFeatureModel(featureId, { force: true })}
        aria-label={`Change the ${getLlmFeature(featureId).label} model`}
      >
        {model ? 'Change' : 'Choose'}
      </button>
    </span>
  )
}
