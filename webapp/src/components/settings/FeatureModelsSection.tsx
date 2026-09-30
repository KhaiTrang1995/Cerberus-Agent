'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { RotateCw, X } from 'lucide-react'
import { useToast } from '@/components/ui'
import { ModelPicker } from '@/components/shared/ModelPicker'
import {
  fetchModelOptions,
  fetchSavedFeatureModels,
  saveFeatureModel,
  type ModelsByProvider,
} from '@/components/shared/FeatureModelGate'
import { getDisplayName } from '@/app/graph/components/AIAssistantDrawer/modelUtils'
import { LLM_FEATURES, modelAllowedForFeature, type FeatureId, type LlmFeature } from '@/lib/llmFeatures'
import styles from './FeatureModelsSection.module.css'

interface FeatureModelsSectionProps {
  userId: string | null
  providersCount: number
  providersLoading: boolean
}

type LoadState = 'loading' | 'ready' | 'error'
type TileStatus = 'set' | 'unset' | 'removed'

const STATUS_LABEL: Record<TileStatus, string> = {
  set: 'Set',
  unset: 'Not set',
  removed: 'Provider removed',
}

/**
 * Global Settings → LLM Providers → "Models by feature": one tile per AI
 * feature, each saving that feature's model for the user. The whole grid
 * shares ONE /api/models call, handed to every picker.
 */
export function FeatureModelsSection({ userId, providersCount, providersLoading }: FeatureModelsSectionProps) {
  const toast = useToast()
  const [saved, setSaved] = useState<Record<string, string>>({})
  const [savedState, setSavedState] = useState<LoadState>('loading')
  const [models, setModels] = useState<ModelsByProvider>({})
  const [modelsState, setModelsState] = useState<LoadState>('loading')
  const [savingId, setSavingId] = useState<FeatureId | null>(null)
  const noProviders = !providersLoading && providersCount === 0

  useEffect(() => {
    if (!userId) return
    let live = true
    fetchSavedFeatureModels(userId)
      .then(map => { if (live) { setSaved(map); setSavedState('ready') } })
      .catch(() => { if (live) setSavedState('error') })
    return () => { live = false }
  }, [userId])

  const loadModels = useCallback(async () => {
    if (!userId) return
    setModelsState('loading')
    try {
      setModels(await fetchModelOptions(userId))
      setModelsState('ready')
    } catch {
      setModelsState('error')
    }
  }, [userId])

  // Refetched when the provider count changes: a new provider brings new models.
  useEffect(() => {
    if (providersLoading || providersCount === 0) return
    void loadModels()
  }, [loadModels, providersLoading, providersCount])

  const modelIds = useMemo(
    () => new Set(Object.values(models).flatMap(list => list.map(m => m.id))),
    [models],
  )

  const statusOf = (model: string): TileStatus => {
    if (!model) return 'unset'
    if (modelsState === 'ready' && !modelIds.has(model)) return 'removed'
    return 'set'
  }

  const save = async (feature: LlmFeature, model: string) => {
    if (!userId || savingId) return
    if (model === (saved[feature.id] ?? '')) return
    setSavingId(feature.id)
    try {
      const merged = await saveFeatureModel(userId, feature.id, model)
      setSaved(merged)
      toast.success(model
        ? `${feature.label} now uses ${getDisplayName(model, models)}`
        : `${feature.label} has no model now`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Could not save the ${feature.label} model`)
    } finally {
      setSavingId(null)
    }
  }

  const loading = !noProviders && (providersLoading || savedState === 'loading' || modelsState === 'loading')

  return (
    <section className={styles.section} aria-labelledby="feature-models-title">
      <h3 id="feature-models-title" className={styles.title}>Models by feature</h3>
      <p className={styles.intro}>
        Each feature below uses its own model, in all your projects. A feature with no model asks
        for one the first time you use it.
      </p>

      {noProviders ? (
        <div className={styles.empty}>Add an LLM provider above to choose models for these features</div>
      ) : loading ? (
        <div className={styles.grid} aria-busy="true" aria-label="Loading models by feature">
          {LLM_FEATURES.map(f => (
            <div key={f.id} className={`${styles.tile} ${styles.tileSkeleton}`} data-testid="feature-model-skeleton">
              <span className={`${styles.skel} ${styles.skelTitle}`} />
              <span className={`${styles.skel} ${styles.skelLine}`} />
              <span className={`${styles.skel} ${styles.skelPicker}`} />
              <span className={`${styles.skel} ${styles.skelLine}`} />
            </div>
          ))}
        </div>
      ) : (
        <>
          {savedState === 'error' && (
            <div className={styles.notice} role="alert">Couldn&apos;t read your saved models. Reload the page to try again.</div>
          )}
          <div className={styles.grid}>
            {LLM_FEATURES.map(feature => {
              const model = saved[feature.id] ?? ''
              const status = statusOf(model)
              // Every tile waits while one saves: `save` takes one at a time,
              // and a pick made meanwhile would snap back, unsaved and unsaid.
              const busy = savingId !== null
              return (
                <div key={feature.id} className={styles.tile} data-feature={feature.id}>
                  <div className={styles.tileHead}>
                    <span className={styles.tileLabel}>{feature.label}</span>
                    <span className={`${styles.chip} ${styles[`chip_${status}`]}`}>{STATUS_LABEL[status]}</span>
                  </div>
                  <p className={styles.tileDesc}>{feature.description}</p>

                  {modelsState === 'error' ? (
                    <div className={styles.readOnly}>
                      <span className={styles.readOnlyValue} title={model || undefined}>{model || 'Not set'}</span>
                      <button type="button" className="textButton" onClick={() => void loadModels()}>
                        <RotateCw size={11} /> Retry
                      </button>
                    </div>
                  ) : (
                    <div className={styles.pickerRow}>
                      <div className={styles.picker}>
                        <ModelPicker
                          userId={userId}
                          value={model}
                          onChange={id => void save(feature, id)}
                          models={models}
                          hideManualFallback
                          filter={id => modelAllowedForFeature(feature.id, id)}
                          disabled={busy || savedState !== 'ready'}
                          emptyLabel="Choose a model"
                        />
                      </div>
                      {model && (
                        <button
                          type="button"
                          className={`iconButton ${styles.clear}`}
                          onClick={() => void save(feature, '')}
                          disabled={busy}
                          title={`Clear the ${feature.label} model`}
                          aria-label={`Clear the ${feature.label} model`}
                        >
                          <X size={12} />
                        </button>
                      )}
                    </div>
                  )}

                  <p className={styles.tileHint}>{feature.hint}</p>
                  {feature.alsoEditedIn.length > 0 && (
                    <p className={styles.tileAlso}>Also in: {feature.alsoEditedIn.join(', ')}</p>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}
    </section>
  )
}
