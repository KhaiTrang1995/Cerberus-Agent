/**
 * Runs the check jobs and assembles the report. It never throws: a probe that
 * throws, times out or answers nonsense becomes an error ROW, and the other
 * probes carry on.
 *
 * Scheduling: at most CONCURRENCY calls in flight; the keys of one service run
 * one after another, `minIntervalMs` apart, because several providers limit per
 * account or per second (Shodan 1 req/s, FOFA code 45012). Services marked
 * `limitScope: 'ip'` (Onyphe, Qianxin Hunter) limit per SOURCE IP, so their gap
 * is kept in one process-wide gate: two users checking at the same moment must
 * not trip it for each other.
 *
 * Every string a provider could have put in a result is scrubbed of every secret
 * of the run before it leaves here, email addresses in it become "[email]", and
 * an email-shaped account label is dropped.
 */
import { computeHealth } from './health'
import { probeFetch, ProbeTransportError, scrub } from './http'
import { errorResult, notCheckedResult } from './results'
import type { JobPlan, ProbeJob } from './credentials'
import { WHITESPACE_WARNING } from './credentials'
import type {
  ApiUsageReportV1, KeyResult, ProbeContext, ProbeRequest, ProbeResponse, ProbeResult, ReportCounts,
} from './types'
import { REPORT_SCHEMA_VERSION } from './types'

export const CONCURRENCY = 8
export const RUN_BUDGET_MS = 90_000
export const DEFAULT_MIN_INTERVAL_MS = 250

const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/
const EMAILS = new RegExp(EMAIL.source, 'g')
// A provider's own masked echo of the key ("sk-proj-****…abcd", "xa***gA"):
// the full key is scrubbed, but this still carries its first and last characters.
const MASKED_ECHO = /[A-Za-z0-9_-]{2,16}\*{3,}[A-Za-z0-9_-]{0,8}/g
const MAX_PLAN = 80
const MAX_CODE = 60
const MAX_NOTE = 300
const MAX_NOTES = 10
const MAX_METERS = 60

const globalForGates = globalThis as unknown as { __apiUsageIpGates?: Map<string, number> }
const IP_GATES = (globalForGates.__apiUsageIpGates ??= new Map<string, number>())

export interface RunnerDeps {
  http?: (req: ProbeRequest) => Promise<ProbeResponse>
  /** Milliseconds clock. */
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  concurrency?: number
  budgetMs?: number
  ipGates?: Map<string, number>
  log?: (line: string) => void
}

function semaphore(limit: number) {
  let active = 0
  const waiting: (() => void)[] = []
  return {
    async acquire() {
      if (active < limit) {
        active++
        return
      }
      await new Promise<void>(resolve => waiting.push(resolve))
      active++
    },
    release() {
      active--
      waiting.shift()?.()
    },
  }
}

function clip(s: string | undefined, max: number): string | undefined {
  if (s == null) return undefined
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

/** A plan or account label, or nothing when it is an email address (checked before the cut hides one). */
function safeLabel(s: string | undefined, secrets: string[]): string | undefined {
  if (!s) return undefined
  const cleaned = scrub(s, secrets)
  return cleaned && !EMAIL.test(cleaned) ? clip(cleaned, MAX_PLAN) : undefined
}

/** The row: the probe's findings + the job's identity, with every provider string scrubbed. */
export function toKeyResult(
  job: ProbeJob, result: ProbeResult, latencyMs: number | null, checkedAt: string, secrets: string[],
): KeyResult {
  const s = (v: string) => scrub(v, secrets).replace(MASKED_ECHO, '[masked key]').replace(EMAILS, '[email]')
  const meters = result.meters.slice(0, MAX_METERS).map(m => ({
    ...m,
    label: clip(s(m.label), MAX_PLAN)!,
    ...(m.note ? { note: clip(s(m.note), MAX_NOTE) } : {}),
  }))
  const account = result.account
    ? Object.fromEntries(Object.entries({
        plan: safeLabel(result.account.plan, secrets),
        label: safeLabel(result.account.label, secrets),
        expiresAt: result.account.expiresAt,
      }).filter(([, v]) => v))
    : undefined
  const notes = [...job.notes, ...(result.notes ?? [])].map(n => clip(s(n), MAX_NOTE)!).slice(0, MAX_NOTES)
  const warnings = [...job.warnings]
  const health = result.outcome === 'usage' ? result.healthOverride ?? computeHealth(meters) : undefined
  return {
    serviceId: job.probe.id,
    serviceLabel: job.probe.label,
    group: job.probe.group,
    field: job.field,
    keyRole: job.keyRole,
    keyIndex: job.keyIndex,
    keyHint: job.keyHint,
    ...(job.sourceName ? { sourceName: job.sourceName } : {}),
    outcome: result.outcome,
    ...(health ? { health } : {}),
    ...(account && Object.keys(account).length ? { account } : {}),
    meters,
    ...(result.error ? {
      error: {
        ...result.error,
        message: clip(s(result.error.message), MAX_NOTE)!,
        ...(result.error.providerCode ? { providerCode: clip(s(result.error.providerCode), MAX_CODE) } : {}),
      },
    } : {}),
    ...(result.notCheckedReason ? { notCheckedReason: result.notCheckedReason } : {}),
    ...(notes.length ? { notes } : {}),
    ...(warnings.length ? { warnings } : {}),
    costNote: job.probe.costNote,
    dashboardUrl: job.probe.dashboardUrl,
    docsUrl: job.probe.docsUrl,
    endpoint: job.probe.endpoint,
    ...(job.probe.experimental ? { experimental: true } : {}),
    checkedAt,
    latencyMs,
  }
}

async function executeJob(job: ProbeJob, http: RunnerDeps['http'] & object, now: () => number, secrets: string[]): Promise<{ result: ProbeResult; latencyMs: number; checkedAt: string }> {
  const started = now()
  const checkedAt = new Date(started).toISOString()
  const ctx: ProbeContext = { key: job.key, companions: job.companions, now: new Date(started), http }
  let result: ProbeResult
  try {
    if (!job.probe.run) {
      result = notCheckedResult(job.probe.notCheckedReason ?? 'pending', job.probe.notCheckedMessage)
    } else {
      result = await job.probe.run(ctx)
    }
  } catch (e) {
    if (e instanceof ProbeTransportError) {
      result = errorResult(e.kind, e.message)
      if (e.keyFormat && !job.warnings.includes(WHITESPACE_WARNING)) job.warnings.push(WHITESPACE_WARNING)
    } else {
      const msg = e instanceof Error ? e.message : String(e)
      result = errorResult('unexpected_response', `the check failed: ${scrub(msg, secrets).slice(0, 160)}`)
    }
  }
  return { result, latencyMs: now() - started, checkedAt }
}

function countResults(results: KeyResult[]): ReportCounts {
  return {
    services: new Set(results.map(r => r.serviceId)).size,
    keys: results.length,
    usage: results.filter(r => r.outcome === 'usage').length,
    validNoUsage: results.filter(r => r.outcome === 'valid_no_usage').length,
    notChecked: results.filter(r => r.outcome === 'not_checked').length,
    errors: results.filter(r => r.outcome === 'error').length,
    low: results.filter(r => r.health === 'low').length,
    exhausted: results.filter(r => r.health === 'exhausted').length,
  }
}

export async function runJobs(plan: JobPlan, deps: RunnerDeps = {}): Promise<ApiUsageReportV1> {
  const now = deps.now ?? Date.now
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>(r => setTimeout(r, ms)))
  const http = deps.http ?? ((req: ProbeRequest) => probeFetch(req))
  const log = deps.log ?? ((line: string) => console.info(line))
  const gates = deps.ipGates ?? IP_GATES
  const budget = deps.budgetMs ?? RUN_BUDGET_MS
  const sem = semaphore(deps.concurrency ?? CONCURRENCY)
  const secrets = plan.secrets

  const startedAt = now()
  const deadline = startedAt + budget
  const rows = new Map<ProbeJob, KeyResult>()
  const ordered = [...plan.jobs].sort((a, b) => a.order - b.order)

  const record = (job: ProbeJob, result: ProbeResult, latencyMs: number | null, checkedAt: string) => {
    const row = toKeyResult(job, result, latencyMs, checkedAt, secrets)
    rows.set(job, row)
    const status = row.error ? row.error.kind : row.health ?? row.notCheckedReason ?? 'ok'
    log(`[api-usage] ${row.serviceId} ${row.outcome} ${status}`)
    if (row.error?.kind === 'unexpected_response') log(`[api-usage] drift ${row.serviceId} status=${row.error.httpStatus ?? '-'}`)
  }
  const overBudget = (job: ProbeJob) =>
    record(job, errorResult('timeout', `not run: the ${Math.round(budget / 1000)} s time budget was used up by other checks`), null, new Date(now()).toISOString())

  const byService = new Map<string, ProbeJob[]>()
  for (const job of ordered) {
    if (job.immediate) {
      record(job, job.immediate, null, new Date(now()).toISOString())
      continue
    }
    const list = byService.get(job.probe.service) ?? []
    list.push(job)
    byService.set(job.probe.service, list)
  }

  await Promise.all([...byService.entries()].map(async ([service, jobs]) => {
    let lastStart = Number.NEGATIVE_INFINITY
    for (const job of jobs) {
      try {
        const interval = job.probe.minIntervalMs ?? DEFAULT_MIN_INTERVAL_MS
        const chainSlot = Math.max(now(), lastStart + interval)
        if (chainSlot > deadline) {
          overBudget(job)
          continue
        }
        if (chainSlot > now()) await sleep(chainSlot - now())
        await sem.acquire()
        try {
          if (job.probe.limitScope === 'ip') {
            // Reserve the slot synchronously so a concurrent run queues behind it.
            const slot = Math.max(now(), gates.get(service) ?? Number.NEGATIVE_INFINITY)
            gates.set(service, slot + interval)
            if (slot > deadline) {
              overBudget(job)
              continue
            }
            if (slot > now()) await sleep(slot - now())
          }
          if (now() > deadline) {
            overBudget(job)
            continue
          }
          lastStart = now()
          const { result, latencyMs, checkedAt } = await executeJob(job, http, now, secrets)
          record(job, result, latencyMs, checkedAt)
        } finally {
          sem.release()
        }
      } catch (e) {
        // Scheduling itself failing is a bug, but it still must not sink the run.
        const msg = e instanceof Error ? e.message : String(e)
        record(job, errorResult('unexpected_response', `the check failed: ${scrub(msg, secrets).slice(0, 160)}`), null, new Date(now()).toISOString())
      }
    }
  }))

  const finishedAt = now()
  const results = ordered.map(j => rows.get(j)!).filter(Boolean)
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    startedAt: new Date(startedAt).toISOString(),
    finishedAt: new Date(finishedAt).toISOString(),
    durationMs: finishedAt - startedAt,
    counts: countResults(results),
    skippedEmpty: plan.skippedEmpty,
    inventory: plan.inventory,
    results,
  }
}
