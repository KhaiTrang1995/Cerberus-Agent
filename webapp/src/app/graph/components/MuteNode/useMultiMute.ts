'use client'

/**
 * Multi mute's state machine: read the saved model (or ask for one), ask the
 * agent for findings like the seed, then mute what the person picks.
 *
 *   gate ⇄ loading → results | error
 *
 * The AI never mutes. Suggest is read-only and returns a batch id; every write
 * names that batch and the agent accepts only its keys, re-checking each one
 * under its lock. So a row can come back "skipped" here even though it was
 * offered a minute ago: the finding changed in between.
 *
 * Undo lives in the modal's activity bar, not on the toast: the global Toast
 * holds one action and closes on click, and its one action is "View muted".
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAlertModal } from '@/components/ui'
import { fetchSavedFeatureModels } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, GATE_CODES, readFeatureModelCode } from '@/lib/llmFeatures'
import {
  APPLY_CHUNK, chunk, groupKeys, isHighOrCritical,
  type ApplyConcept, type ApplyItem, type MultiMuteGroup, type MultiMuteMember,
  type MultiMuteSeed, type MuteOutcome, type SuggestResult,
} from './multiMuteModel'
import { muteConfirmText } from './useMuteNode'

export type MultiMutePhase =
  | { kind: 'gate'; message?: string; /** Cancel returns to the results it came from. */ back: boolean }
  | { kind: 'loading'; model: string | null }
  | { kind: 'results' }
  | { kind: 'error'; message: string; retry: boolean }

export interface ActivityEntry {
  id: number
  batchId: string
  /** What this action muted (outcome `muted`): exactly what its Undo may unmute. */
  mutedKeys: string[]
  undoneKeys: string[]
  /** Set when the seed is among `mutedKeys`. */
  seedKey: string | null
  skipped: number
  workItemsAffected: number
  triageRunLive: boolean
  undo: 'idle' | 'running' | 'done'
  error: string | null
}

export interface ActionError {
  message: string
  /** The suggestion is gone server-side; only a new run can mute anything. */
  rerun: boolean
}

export interface CloseSummary {
  muted: string[]
  seedMuted: boolean
  workItems: number
  triageRunLive: boolean
  batches: string[]
}

const SUGGEST_URL = '/api/triage/multi-mute/suggest'
const APPLY_URL = '/api/triage/multi-mute/apply'
const UNMUTE_URL = '/api/triage/unmute'

const SUGGEST_MESSAGES: Record<string, string> = {
  activation_busy: 'A version is being activated; try again when it finishes.',
  busy: 'Too many Multi mute searches right now; try again in a moment.',
  seed_changed: 'This finding changed or was muted since the page loaded. The page has been reloaded.',
  superseded: 'A newer Multi mute search replaced this one.',
}

const APPLY_MESSAGES: Record<string, string> = {
  activation_busy: 'A version is being activated; try again when it finishes.',
  batch_expired: 'This suggestion expired; run Multi mute again.',
  batch_mismatch: 'These findings are not part of this suggestion; run Multi mute again.',
  retry: 'The graph was busy and nothing more was muted; try again.',
}

function codeOf(body: unknown): string | null {
  const code = body && typeof body === 'object' ? (body as { code?: unknown }).code : null
  return typeof code === 'string' ? code : null
}

function errorText(body: unknown, fallback: string): string {
  const error = body && typeof body === 'object' ? (body as { error?: unknown }).error : null
  return typeof error === 'string' && error ? error : fallback
}

function isSuggestPayload(body: unknown): body is SuggestResult {
  const b = body as Partial<SuggestResult> | null
  return !!b && typeof b === 'object' && typeof b.batch_id === 'string' && !!b.seed && Array.isArray(b.groups)
}

function initialSelection(result: SuggestResult): Set<string> {
  const keys = new Set<string>()
  for (const group of result.groups) {
    for (const member of [...group.members, ...group.probably_not]) if (member.checked) keys.add(member.key)
  }
  return keys
}

interface UseMultiMuteArgs {
  projectId: string
  userId: string | null
  seed: MultiMuteSeed
  /** The seed changed under the page: refresh the graph and every table. */
  onStale: () => void
}

export function useMultiMute({ projectId, userId, seed, onStale }: UseMultiMuteArgs) {
  const { dangerConfirm } = useAlertModal()
  const [phase, setPhase] = useState<MultiMutePhase>({ kind: 'loading', model: null })
  const [result, setResult] = useState<SuggestResult | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [includeSeed, setIncludeSeed] = useState(true)
  const [outcomes, setOutcomes] = useState<Map<string, MuteOutcome>>(new Map())
  const [entries, setEntries] = useState<ActivityEntry[]>([])
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<ActionError | null>(null)
  const seqRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const entryIdRef = useRef(0)
  // The inline gate can finish saving after the modal closed, and its onSaved
  // runs `run`: a closed modal must not spend a model call nor, the agent
  // keeping one search per user, supersede the one a reopened modal started.
  const aliveRef = useRef(true)
  // The seed muted here and not undone. A new search from it is refused as
  // `seed_changed`, which is expected, not a stale page.
  const seedMutedHereRef = useRef(false)
  useEffect(() => {
    seedMutedHereRef.current = !!result && outcomes.get(result.seed.key) === 'muted'
  }, [result, outcomes])

  /**
   * Ask for suggestions. Each call supersedes the previous one: its fetch is
   * aborted, and a late answer to it is dropped by the sequence check (the
   * agent also cancels the older task, per user).
   */
  const run = useCallback(async (opts: { model?: string } = {}) => {
    if (!aliveRef.current) return
    const seq = ++seqRef.current
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setActionError(null)

    let model: string | null = opts.model ?? null
    if (!model && userId) {
      setPhase({ kind: 'loading', model: null })
      try {
        model = (await fetchSavedFeatureModels(userId)).multi_mute || null
        if (seq !== seqRef.current) return
        if (!model) {
          setPhase({ kind: 'gate', back: false })
          return
        }
      } catch {
        // The server reads the model itself and answers model_required if
        // there is none, so an unreadable settings row only costs the name.
        if (seq !== seqRef.current) return
      }
    }
    setPhase({ kind: 'loading', model })

    let res: Response
    try {
      res = await fetch(SUGGEST_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(seed.nodeId
          ? { projectId, nodeId: seed.nodeId }
          : { projectId, graphId: seed.graphId }),
        signal: controller.signal,
      })
    } catch {
      if (seq !== seqRef.current || controller.signal.aborted) return
      setPhase({ kind: 'error', message: 'Could not reach the server; try again.', retry: true })
      return
    }
    const body: unknown = await res.json().catch(() => null)
    if (seq !== seqRef.current) return

    const usable = res.ok || (res.status === 502 && (body as { status?: unknown } | null)?.status === 'model_unreadable')
    if (usable && isSuggestPayload(body)) {
      setResult(body)
      setSelected(initialSelection(body))
      setOutcomes(new Map())
      setIncludeSeed(true)
      setPhase({ kind: 'results' })
      return
    }

    const featureCode = readFeatureModelCode(body)
    if (featureCode && GATE_CODES.includes(featureCode)) {
      const failed = (body as { model?: unknown }).model
      setPhase({
        kind: 'gate',
        back: false,
        message: featureCode === 'model_unavailable'
          ? featureModelMessage('model_unavailable', typeof failed === 'string' ? failed : undefined)
          : undefined,
      })
      return
    }
    if (featureCode) {
      setPhase({ kind: 'error', message: featureModelMessage(featureCode), retry: true })
      return
    }
    const code = codeOf(body)
    if (code === 'seed_changed' && seedMutedHereRef.current) {
      // Back to the results: their activity bar holds the Undo for that mute.
      setPhase({ kind: 'results' })
      setActionError({
        message: 'This finding is muted now, so it cannot start a new search. Undo its mute to search from it again.',
        rerun: false,
      })
      return
    }
    if (code === 'seed_changed') onStale()
    setPhase({
      kind: 'error',
      message: (code && SUGGEST_MESSAGES[code]) || errorText(body, `Multi mute failed (${res.status}).`),
      retry: code !== 'seed_changed' && code !== 'seed_not_muteable',
    })
  }, [projectId, userId, seed, onStale])

  // One suggestion per mount: the provider remounts the modal for each open.
  const runRef = useRef(run)
  useEffect(() => { runRef.current = run })
  useEffect(() => {
    aliveRef.current = true
    void runRef.current()
    return () => {
      aliveRef.current = false
      seqRef.current++
      abortRef.current?.abort()
    }
  }, [])

  const cancelLoading = useCallback(() => {
    seqRef.current++
    abortRef.current?.abort()
  }, [])

  const changeModel = useCallback(() => setPhase({ kind: 'gate', back: true }), [])
  const backToResults = useCallback(() => setPhase({ kind: 'results' }), [])

  const toggle = useCallback((key: string) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  }), [])

  /** Each key's member row, the first seen, for the confirm's severity and AI-only counts. */
  const memberByKey = useMemo(() => {
    const map = new Map<string, MultiMuteMember>()
    for (const group of result?.groups ?? []) {
      for (const m of [...group.members, ...group.probably_not]) if (!map.has(m.key)) map.set(m.key, m)
    }
    return map
  }, [result])

  const pendingSelected = useCallback((keys: string[]) => {
    const out: string[] = []
    const seen = new Set<string>()
    for (const k of keys) {
      if (seen.has(k) || !selected.has(k) || outcomes.has(k)) continue
      seen.add(k)
      out.push(k)
    }
    return out
  }, [selected, outcomes])

  const groupSelection = useCallback((group: MultiMuteGroup) => pendingSelected(groupKeys(group)), [pendingSelected])

  const allSelection = useMemo(
    () => pendingSelected((result?.groups ?? []).flatMap(groupKeys)),
    [result, pendingSelected],
  )

  const groupsWithSelection = useMemo(
    () => (result?.groups ?? []).filter(g => groupSelection(g).length > 0).length,
    [result, groupSelection],
  )

  const seedKey = result?.seed.key ?? ''
  const seedPending = !!seedKey && !outcomes.has(seedKey)

  const apply = useCallback(async (keys: string[], concept: ApplyConcept, withSeed: boolean) => {
    if (!result || busy) return
    const others = keys.filter(k => k !== seedKey && !outcomes.has(k))
    const sendSeed = withSeed && seedPending
    const all = sendSeed ? [seedKey, ...others] : others
    if (all.length === 0) return

    setBusy(true)
    setActionError(null)
    const items: ApplyItem[] = []
    const notFound: string[] = []
    let workItemsAffected = 0
    let triageRunLive = false
    let failure: ActionError | null = null
    for (const part of chunk(all, APPLY_CHUNK)) {
      try {
        const res = await fetch(APPLY_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            projectId,
            batchId: result.batch_id,
            keys: part,
            includeSeed: sendSeed && part.includes(seedKey),
            concept,
          }),
        })
        const body = await res.json().catch(() => ({}))
        if (!res.ok) {
          const code = codeOf(body)
          const featureCode = readFeatureModelCode(body)
          failure = {
            message: (code && APPLY_MESSAGES[code])
              || (featureCode ? featureModelMessage(featureCode) : errorText(body, `The mute failed (${res.status}).`)),
            rerun: code === 'batch_expired' || code === 'batch_mismatch',
          }
          break
        }
        if (Array.isArray(body.items)) items.push(...body.items)
        if (Array.isArray(body.notFound)) notFound.push(...body.notFound)
        workItemsAffected += Number(body.workItemsAffected) || 0
        triageRunLive = triageRunLive || body.triageRunLive === true
      } catch {
        failure = { message: 'Could not reach the server; nothing more was muted.', rerun: false }
        break
      }
    }

    if (items.length > 0 || notFound.length > 0) {
      setOutcomes(prev => {
        const next = new Map(prev)
        for (const item of items) next.set(item.key, item.outcome)
        for (const key of notFound) next.set(key, 'not_found')
        return next
      })
      const mutedKeys = items.filter(i => i.outcome === 'muted').map(i => i.key)
      setEntries(prev => [...prev, {
        id: ++entryIdRef.current,
        batchId: result.batch_id,
        mutedKeys,
        undoneKeys: [],
        seedKey: mutedKeys.includes(seedKey) ? seedKey : null,
        skipped: items.length + notFound.length - mutedKeys.length,
        workItemsAffected,
        triageRunLive,
        undo: mutedKeys.length > 0 ? 'idle' : 'done',
        error: null,
      }])
    }
    if (failure) setActionError(failure)
    setBusy(false)
  }, [result, busy, seedKey, seedPending, outcomes, projectId])

  /** One `dangerConfirm`, naming what makes this selection worth a second look. */
  const confirmMute = useCallback(async (keys: string[], withSeed: boolean) => {
    const members = keys.map(k => memberByKey.get(k)).filter((m): m is MultiMuteMember => !!m)
    const risky = members.filter(m => isHighOrCritical(m.severity)).length
    const aiOnly = members.filter(m => m.ai_only).length
    const count = keys.length + (withSeed ? 1 : 0)
    const notes: string[] = []
    if (risky) notes.push(`${risky} of them ${risky === 1 ? 'is' : 'are'} high or critical.`)
    if (aiOnly) notes.push(`${aiOnly} ${aiOnly === 1 ? 'was' : 'were'} suggested by the AI alone, not by an exact match.`)
    return dangerConfirm(
      [muteConfirmText({ count }), ...notes].join('\n\n'),
      'Multi mute',
      { confirmLabel: `Mute ${count}` },
    )
  }, [memberByKey, dangerConfirm])

  const muteRow = useCallback((member: MultiMuteMember, group: MultiMuteGroup) => {
    void apply([member.key], group.concepts[0] ?? 'selected', false)
  }, [apply])

  const muteSeed = useCallback(() => { void apply([], 'seed', true) }, [apply])

  const muteGroup = useCallback(async (group: MultiMuteGroup) => {
    const keys = groupSelection(group)
    if (keys.length === 0) return
    const needsConfirm = keys.some(k => {
      const m = memberByKey.get(k)
      return !!m && (isHighOrCritical(m.severity) || m.ai_only)
    })
    if (needsConfirm && !(await confirmMute(keys, false))) return
    await apply(keys, group.concepts[0] ?? 'selected', false)
  }, [groupSelection, memberByKey, confirmMute, apply])

  const muteAll = useCallback(async () => {
    const withSeed = includeSeed && seedPending
    if (allSelection.length === 0 && !withSeed) return
    if (!(await confirmMute(allSelection, withSeed))) return
    await apply(allSelection, allSelection.length === 0 ? 'seed' : 'selected', withSeed)
  }, [includeSeed, seedPending, allSelection, confirmMute, apply])

  const undo = useCallback(async (entryId: number) => {
    const entry = entries.find(e => e.id === entryId)
    if (!entry || busy || entry.undo !== 'idle') return
    const keys = entry.mutedKeys.filter(k => !entry.undoneKeys.includes(k))
    if (keys.length === 0) return
    const patch = (p: Partial<ActivityEntry>) =>
      setEntries(prev => prev.map(e => e.id === entryId ? { ...e, ...p } : e))

    setBusy(true)
    patch({ undo: 'running', error: null })
    const unmuted: string[] = []
    let error: string | null = null
    for (const part of chunk(keys, APPLY_CHUNK)) {
      try {
        const res = await fetch(UNMUTE_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectId, keys: part, undoBatch: entry.batchId }),
        })
        const body = await res.json().catch(() => ({}))
        if (!res.ok) {
          const featureCode = readFeatureModelCode(body)
          error = featureCode ? featureModelMessage(featureCode) : errorText(body, `Undo failed (${res.status}).`)
          break
        }
        for (const item of Array.isArray(body.items) ? body.items : []) {
          if (item && typeof item.key === 'string') unmuted.push(item.key)
        }
      } catch {
        error = 'Could not reach the server; nothing more was undone.'
        break
      }
    }

    const undoneKeys = [...entry.undoneKeys, ...unmuted]
    // A key the server did not unmute changed since (a newer mute took it
    // over); retrying cannot bring it back, so only a failed call keeps Undo.
    patch({ undoneKeys, undo: error ? 'idle' : 'done', error })
    if (unmuted.length > 0) {
      setOutcomes(prev => {
        const next = new Map(prev)
        for (const key of unmuted) next.delete(key)
        return next
      })
      setSelected(prev => {
        const next = new Set(prev)
        for (const key of unmuted) next.delete(key)
        return next
      })
    }
    setBusy(false)
  }, [entries, busy, projectId])

  const closeSummary = useCallback((): CloseSummary => {
    const muted: string[] = []
    const batches = new Set<string>()
    let workItems = 0
    let triageRunLive = false
    let seedMuted = false
    for (const e of entries) {
      const still = e.mutedKeys.filter(k => !e.undoneKeys.includes(k))
      if (still.length === 0) continue
      muted.push(...still)
      batches.add(e.batchId)
      workItems += e.workItemsAffected
      triageRunLive = triageRunLive || e.triageRunLive
      if (e.seedKey && still.includes(e.seedKey)) seedMuted = true
    }
    return { muted, seedMuted, workItems, triageRunLive, batches: [...batches] }
  }, [entries])

  return {
    phase, result, selected, includeSeed, outcomes, entries, busy, actionError,
    allSelection, groupsWithSelection, seedPending,
    run, cancelLoading, changeModel, backToResults,
    toggle, setIncludeSeed, groupSelection,
    muteRow, muteSeed, muteGroup, muteAll, undo,
    dismissActionError: () => setActionError(null),
    closeSummary,
  }
}

export type MultiMuteState = ReturnType<typeof useMultiMute>
