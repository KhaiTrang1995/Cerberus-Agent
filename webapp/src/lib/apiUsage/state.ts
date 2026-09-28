/**
 * In-process state of the usage checks: which users have a run in flight, and
 * when each user's last run finished (for the cooldown, including runs whose
 * save failed and so left no row to read a date from).
 *
 * A module-level map is enough because the standalone Next server is one Node
 * process. It lives on globalThis so a dev hot reload or a duplicated bundle
 * cannot split it in two. A restart drops it: the in-flight run is lost, the
 * saved report is untouched, and nothing stays locked.
 */

/**
 * The air-gap switch. Default ON, and read like the other egress switches
 * (OSV_DB_AUTO_REFRESH, SCA_INTEL_AUTO_REFRESH): false, 0, no or off, in any
 * case, turn the check off. An operator who writes `FALSE` on an air-gapped
 * host must not keep the egress on. Read per request from the server env,
 * never by the browser.
 */
const OFF_VALUES = new Set(['false', '0', 'no', 'off'])

export function checksEnabled(): boolean {
  return !OFF_VALUES.has((process.env.API_USAGE_CHECK_ENABLED ?? '').trim().toLowerCase())
}

export const MAX_CONCURRENT_RUNS = 3
export const COOLDOWN_MS = 60_000

export interface RunInfo {
  startedAt: string
  keys: number
}

interface RunState {
  running: Map<string, RunInfo>
  lastFinishedAt: Map<string, number>
}

const globalForRuns = globalThis as unknown as { __apiUsageRuns?: RunState }
const state: RunState = (globalForRuns.__apiUsageRuns ??= { running: new Map(), lastFinishedAt: new Map() })

export type AcquireResult =
  | { ok: true }
  | { ok: false; reason: 'run_in_progress'; startedAt: string }
  | { ok: false; reason: 'busy' }

/**
 * Check and take the user's lock in one synchronous step. There is no await
 * between the check and the set, so two POSTs arriving together cannot both
 * pass. The caller MUST release() on every exit path.
 */
export function tryAcquire(userId: string, startedAt: string): AcquireResult {
  const current = state.running.get(userId)
  if (current) return { ok: false, reason: 'run_in_progress', startedAt: current.startedAt }
  // Bounds outbound sockets and memory in the 1 GB webapp container.
  if (state.running.size >= MAX_CONCURRENT_RUNS) return { ok: false, reason: 'busy' }
  state.running.set(userId, { startedAt, keys: 0 })
  return { ok: true }
}

export function setRunKeys(userId: string, keys: number): void {
  const current = state.running.get(userId)
  if (current) current.keys = keys
}

/** Release the lock; `finishedAtMs` is passed only when a run actually happened. */
export function release(userId: string, finishedAtMs?: number): void {
  state.running.delete(userId)
  if (finishedAtMs != null) state.lastFinishedAt.set(userId, finishedAtMs)
}

export function runningFor(userId: string): RunInfo | null {
  const r = state.running.get(userId)
  return r ? { ...r } : null
}

export function lastFinishedAt(userId: string): number | undefined {
  return state.lastFinishedAt.get(userId)
}

/** Test hook: forget every run. */
export function resetRunState(): void {
  state.running.clear()
  state.lastFinishedAt.clear()
}
