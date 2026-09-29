/**
 * Test helpers for the usage probes. Not a test file and never imported by the
 * app: provider tests build synthetic responses with `res()` and drive a probe
 * end to end with `runProbe()`, which records every request it makes, and
 * `reportRow()` shows the row the runner saves from those answers.
 */
import { buildJobs } from './credentials'
import { runJobs } from './runner'
import type { KeyResult, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from './types'

/** A fixed clock for the tests: Sat 26 Sep 2026, 14:32:05 UTC. */
export const NOW = new Date('2026-09-26T14:32:05.000Z')

export function res(
  status: number,
  payload?: unknown,
  opts: { headers?: Record<string, string>; contentType?: string; text?: string } = {},
): ProbeResponse {
  const text = opts.text ?? (payload === undefined ? '' : typeof payload === 'string' ? payload : JSON.stringify(payload))
  const isJson = payload !== undefined && typeof payload !== 'string'
  const lowered = Object.fromEntries(Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
  return {
    status,
    headers: lowered,
    json: isJson ? payload : undefined,
    text: text.slice(0, 2048),
    contentType: (opts.contentType ?? (isJson ? 'application/json' : 'text/plain')).toLowerCase(),
    latencyMs: 1,
    truncated: false,
  }
}

export function html(status: number, page = '<!DOCTYPE html><html><head><title>Blocked</title></head><body></body></html>'): ProbeResponse {
  return res(status, page, { contentType: 'text/html; charset=utf-8' })
}

export interface ProbeRun {
  result: ProbeResult
  requests: ProbeRequest[]
}

/**
 * Run a probe against queued responses. A response may be an Error to throw
 * (a transport failure). Running out of responses fails the test loudly.
 */
export async function runProbe(
  probe: ProbeDef,
  key: string,
  responses: (ProbeResponse | Error)[],
  companions: Record<string, string> = {},
): Promise<ProbeRun> {
  const queue = [...responses]
  const requests: ProbeRequest[] = []
  const ctx: ProbeContext = {
    key,
    companions,
    now: NOW,
    http: async (req: ProbeRequest) => {
      requests.push(req)
      const next = queue.shift()
      if (!next) throw new Error(`unexpected extra request: ${req.method} ${req.url}`)
      if (next instanceof Error) throw next
      return next
    },
  }
  if (!probe.run) throw new Error(`${probe.id} has no run()`)
  const result = await probe.run(ctx)
  return { result, requests }
}

/**
 * The saved report row one probe's answers become: the real job building and
 * runner, so health, scrubbing and notes are what the user would see.
 */
export async function reportRow(
  probe: ProbeDef,
  settings: Record<string, string>,
  responses: ProbeResponse[],
): Promise<KeyResult> {
  const queue = [...responses]
  const plan = buildJobs({ settings, rotationRows: [], probes: [probe] })
  const report = await runJobs(plan, {
    http: async req => {
      const next = queue.shift()
      if (!next) throw new Error(`unexpected extra request: ${req.method} ${req.url}`)
      return next
    },
    now: () => NOW.getTime(),
    sleep: async () => {},
    log: () => {},
    ipGates: new Map(),
  })
  return report.results[0]
}

/** Every string anywhere in the value, for "the secret never appears" assertions. */
export function allStrings(value: unknown): string[] {
  const out: string[] = []
  const walk = (v: unknown) => {
    if (typeof v === 'string') out.push(v)
    else if (Array.isArray(v)) v.forEach(walk)
    else if (v && typeof v === 'object') Object.values(v).forEach(walk)
  }
  walk(value)
  return out
}
