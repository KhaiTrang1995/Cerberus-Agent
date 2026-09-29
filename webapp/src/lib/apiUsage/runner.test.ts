/**
 * The runner's scheduling, isolation and scrubbing, on a virtual clock: sleeps
 * resolve only when the driver advances time, so pacing and the budget are
 * asserted to the millisecond without real waiting.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { runJobs, type RunnerDeps } from './runner'
import { buildJobs } from './credentials'
import { ProbeTransportError } from './http'
import { errorResult, meter, usageResult } from './results'
import type { ProbeDef, ProbeRequest, ProbeResponse } from './types'
import { res } from './testUtils'

function virtualClock() {
  let t = 1_000_000
  const timers: { at: number; resolve: () => void }[] = []
  const flush = () => new Promise<void>(r => setImmediate(r))
  return {
    now: () => t,
    sleep: (ms: number) => new Promise<void>(resolve => timers.push({ at: t + ms, resolve })),
    async drive<T>(p: Promise<T>): Promise<T> {
      let done = false
      let value!: T
      let error: unknown
      p.then(v => { done = true; value = v }, e => { done = true; error = e })
      for (let i = 0; i < 10_000 && !done; i++) {
        await flush()
        if (done || timers.length === 0) continue
        timers.sort((a, b) => a.at - b.at)
        const next = timers.shift()!
        t = Math.max(t, next.at)
        next.resolve()
      }
      if (error) throw error
      return value
    },
  }
}

type Call = { url: string; t: number }

function setup(opts: { slowMs?: number } = {}) {
  const clock = virtualClock()
  const calls: Call[] = []
  const http = async (req: ProbeRequest): Promise<ProbeResponse> => {
    calls.push({ url: req.url, t: clock.now() })
    if (opts.slowMs) await clock.sleep(opts.slowMs)
    return res(200, { ok: true })
  }
  const logs: string[] = []
  const deps: RunnerDeps = { now: clock.now, sleep: clock.sleep, http, log: l => logs.push(l), ipGates: new Map() }
  return { clock, calls, deps, logs }
}

const probe = (id: string, over: Partial<ProbeDef> = {}): ProbeDef => ({
  id, service: id, label: id.toUpperCase(), group: 'keys', field: `${id}Key`, rotationTool: id, kind: 'usage',
  costNote: 'free', docsUrl: 'https://docs.example.test', dashboardUrl: 'https://dash.example.test', verifiedOn: null,
  endpoint: `GET ${id}.example.test/usage`,
  run: async ctx => {
    await ctx.http({ method: 'GET', url: `https://${id}.example.test/usage?k=${ctx.key}` })
    return usageResult([meter({ id: 'm', label: 'Credits', unit: 'credits', window: 'month', limit: 100, remaining: 50, primary: true })])
  },
  ...over,
})

describe('scheduling', () => {
  test('keys of one service run one after another, minIntervalMs apart', async () => {
    const { clock, calls, deps } = setup()
    const p = probe('shodan', { minIntervalMs: 1100 })
    const plan = buildJobs({
      settings: { shodanKey: 'K1' }, rotationRows: [{ toolName: 'shodan', extraKeys: 'K2\nK3' }], probes: [p],
    })
    const report = await clock.drive(runJobs(plan, deps))
    expect(calls.map(c => c.t - calls[0].t)).toEqual([0, 1100, 2200])
    expect(report.results.map(r => r.keyIndex)).toEqual([0, 1, 2])
  })

  test('different services run in parallel', async () => {
    const { clock, calls, deps } = setup()
    const plan = buildJobs({ settings: { aKey: 'A', bKey: 'B' }, rotationRows: [], probes: [probe('a'), probe('b')] })
    await clock.drive(runJobs(plan, deps))
    expect(calls[0].t).toBe(calls[1].t)
  })

  test('never more than `concurrency` calls in flight', async () => {
    const { clock, calls, deps } = setup({ slowMs: 1000 })
    const probes = Array.from({ length: 10 }, (_, i) => probe(`s${i}`))
    const settings = Object.fromEntries(probes.map(p => [p.field, `KEY-${p.id}`]))
    const plan = buildJobs({ settings, rotationRows: [], probes })
    await clock.drive(runJobs(plan, { ...deps, concurrency: 8 }))
    const t0 = calls[0].t
    expect(calls.filter(c => c.t === t0)).toHaveLength(8)
    expect(calls.filter(c => c.t === t0 + 1000)).toHaveLength(2)
  })

  test('jobs that cannot start inside the budget become "not run" timeout rows', async () => {
    const { clock, calls, deps } = setup()
    const p = probe('slowsvc', { minIntervalMs: 1100 })
    const plan = buildJobs({ settings: { slowsvcKey: 'K1' }, rotationRows: [{ toolName: 'slowsvc', extraKeys: 'K2\nK3\nK4\nK5' }], probes: [p] })
    const report = await clock.drive(runJobs(plan, { ...deps, budgetMs: 3000 }))
    expect(calls).toHaveLength(3)
    const notRun = report.results.filter(r => r.error?.kind === 'timeout')
    expect(notRun).toHaveLength(2)
    expect(notRun[0].error?.message).toMatch(/not run: the 3 s time budget/)
    expect(report.counts.errors).toBe(2)
  })

  test("limitScope 'ip' spaces calls across two concurrent runs (a process-wide gate)", async () => {
    const clock = virtualClock()
    const calls: Call[] = []
    const gates = new Map<string, number>()
    const http = async (req: ProbeRequest) => { calls.push({ url: req.url, t: clock.now() }); return res(200, {}) }
    const deps: RunnerDeps = { now: clock.now, sleep: clock.sleep, http, log: () => {}, ipGates: gates }
    const p = probe('onyphe', { minIntervalMs: 1100, limitScope: 'ip' })
    const planA = buildJobs({ settings: { onypheKey: 'USER-A' }, rotationRows: [], probes: [p] })
    const planB = buildJobs({ settings: { onypheKey: 'USER-B' }, rotationRows: [], probes: [p] })
    await clock.drive(Promise.all([runJobs(planA, deps), runJobs(planB, deps)]))
    expect(calls).toHaveLength(2)
    expect(Math.abs(calls[1].t - calls[0].t)).toBeGreaterThanOrEqual(1100)
  })

  test('a key-scoped service does NOT wait for another run', async () => {
    const clock = virtualClock()
    const calls: Call[] = []
    const http = async (req: ProbeRequest) => { calls.push({ url: req.url, t: clock.now() }); return res(200, {}) }
    const deps: RunnerDeps = { now: clock.now, sleep: clock.sleep, http, log: () => {}, ipGates: new Map() }
    const p = probe('shodan', { minIntervalMs: 1100 })
    const planA = buildJobs({ settings: { shodanKey: 'USER-A' }, rotationRows: [], probes: [p] })
    const planB = buildJobs({ settings: { shodanKey: 'USER-B' }, rotationRows: [], probes: [p] })
    await clock.drive(Promise.all([runJobs(planA, deps), runJobs(planB, deps)]))
    expect(calls[0].t).toBe(calls[1].t)
  })
})

describe('isolation', () => {
  test('a probe that throws becomes one error row; the others are unaffected', async () => {
    const { clock, deps } = setup()
    const boom = probe('boom', { run: async () => { throw new Error('parser exploded on KEY-BOOM-1') } })
    const plan = buildJobs({ settings: { boomKey: 'KEY-BOOM-1', okKey: 'KEY-OK' }, rotationRows: [], probes: [boom, probe('ok')] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results[0].error?.kind).toBe('unexpected_response')
    expect(report.results[0].error?.message).not.toContain('KEY-BOOM-1')
    expect(report.results[0].error?.message).toContain('***')
    expect(report.results[1].outcome).toBe('usage')
  })

  test('transport errors keep their kind; a key-format error adds the whitespace warning', async () => {
    const { clock, deps } = setup()
    const t = probe('t', { run: async () => { throw new ProbeTransportError('timeout', 'timed out after 10 s') } })
    const k = probe('k', { run: async () => { throw new ProbeTransportError('invalid_key', 'line break in key', true) } })
    const plan = buildJobs({ settings: { tKey: 'T', kKey: 'K\r' }, rotationRows: [], probes: [t, k] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results[0].error).toMatchObject({ kind: 'timeout', message: 'timed out after 10 s' })
    expect(report.results[1].error?.kind).toBe('invalid_key')
    expect(report.results[1].warnings).toHaveLength(1)
  })

  test('immediate (not checked) jobs make no call', async () => {
    const { clock, calls, deps } = setup()
    const none = probe('none', { kind: 'none', notCheckedReason: 'no_api', notCheckedMessage: 'nothing to ask', run: undefined, rotationTool: undefined })
    const plan = buildJobs({ settings: { noneKey: 'N' }, rotationRows: [], probes: [none] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(calls).toHaveLength(0)
    expect(report.results[0]).toMatchObject({ outcome: 'not_checked', notCheckedReason: 'no_api', notes: ['nothing to ask'], latencyMs: null })
  })
})

describe('the report', () => {
  test('provider strings are scrubbed of every secret; an email-shaped label is dropped', async () => {
    const { clock, deps } = setup()
    const leaky = probe('leaky', {
      run: async ctx => ({
        ...usageResult(
          [meter({ id: 'm', label: `Credits for ${ctx.key}`, unit: 'credits', window: 'month', remaining: 1, primary: true, note: `note ${ctx.key}` })],
          { account: { plan: `Plan ${ctx.key}`, label: 'owner@example.test' }, notes: [`echo ${ctx.key}`] },
        ),
      }),
    })
    const plan = buildJobs({ settings: { leakyKey: 'LEAKY-SECRET-KEY' }, rotationRows: [], probes: [leaky] })
    const report = await clock.drive(runJobs(plan, deps))
    const json = JSON.stringify(report)
    expect(json).not.toContain('LEAKY-SECRET-KEY')
    expect(json).not.toContain('owner@example.test')
    expect(report.results[0].account?.plan).toBe('Plan ***')
    expect(report.results[0].keyHint).toBe('••••••••-KEY')
  })

  test("a provider's masked echo of the key is redacted too (OpenAI, xAI style)", async () => {
    const { clock, deps } = setup()
    const p = probe('echo', {
      run: async () => errorResult('invalid_key', 'Incorrect API key provided: sk-TESTK***********************0000. See the docs; xa***gA'),
    })
    const plan = buildJobs({ settings: { echoKey: 'sk-TESTKEY-0000-not-real-0000' }, rotationRows: [], probes: [p] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results[0].error?.message).toBe('Incorrect API key provided: [masked key]. See the docs; [masked key]')
  })

  test('an error message quoting a companion secret is scrubbed too', async () => {
    const { clock, deps } = setup()
    const p = probe('pair', {
      companions: [{ field: 'pairSecret', required: true }],
      run: async ctx => errorResult('invalid_key', `bad pair ${ctx.companions.pairSecret}`),
    })
    const plan = buildJobs({ settings: { pairKey: 'ID-0001', pairSecret: 'COMPANION-SECRET' }, rotationRows: [], probes: [p] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results[0].error?.message).toBe('bad pair ***')
  })

  // A top-up can carry an account whose plan meter is used up (SerpAPI extra
  // credits, Tavily pay-as-you-go). The probe says so with healthOverride, which
  // the runner used to apply only when it made the health WORSE.
  test('REGRESSION topup-balance-reads-exhausted: the probe verdict replaces what the primary meters say', async () => {
    const { clock, deps } = setup()
    const carried = probe('carried', {
      run: async () => usageResult(
        [meter({ id: 'plan', label: 'Plan', unit: 'searches', window: 'month', limit: 100, remaining: 0, primary: true })],
        { healthOverride: 'low' },
      ),
    })
    const stopped = probe('stopped', {
      run: async () => usageResult(
        [meter({ id: 'bal', label: 'Balance', unit: 'usd', window: 'balance', remaining: 12, primary: true })],
        { healthOverride: 'exhausted' },
      ),
    })
    const plan = buildJobs({ settings: { carriedKey: 'C', stoppedKey: 'S' }, rotationRows: [], probes: [carried, stopped] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results.map(r => r.health)).toEqual(['low', 'exhausted'])
    expect(report.counts).toMatchObject({ low: 1, exhausted: 1 })
  })

  test('REGRESSION provider-code-unscrubbed: the provider code is scrubbed and clipped like the message', async () => {
    const { clock, deps } = setup()
    const p = probe('code', {
      run: async ctx => errorResult('forbidden', 'denied', { httpStatus: 403, providerCode: `denied_for_${ctx.key}_${'x'.repeat(200)}` }),
    })
    const plan = buildJobs({ settings: { codeKey: 'CODE-SECRET-KEY-0001' }, rotationRows: [], probes: [p] })
    const report = await clock.drive(runJobs(plan, deps))
    // Scrubbed to "denied_for_***_xx…", which then reads as a masked echo too.
    expect(report.results[0].error?.providerCode).toBe(`[masked key]${'x'.repeat(47)}…`)
  })

  test('REGRESSION label-email-check-after-clip: an address cut by the length limit still drops the label', async () => {
    const { clock, deps } = setup()
    // The address straddles character 80: cut first, it no longer looks like one.
    const label = `${'Token for the platform team, rotated every quarter, owner'.padEnd(60, '.')} alice.smith@acme-corporation.example`
    const p = probe('named', {
      run: async () => usageResult(
        [meter({ id: 'm', label: 'M', unit: 'credits', window: 'month', remaining: 1, primary: true })],
        { account: { plan: 'Pro', label } },
      ),
    })
    const plan = buildJobs({ settings: { namedKey: 'N' }, rotationRows: [], probes: [p] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results[0].account).toEqual({ plan: 'Pro' })
    expect(JSON.stringify(report)).not.toContain('alice.smith@')
  })

  test('REGRESSION email-in-notes-and-messages: an address in a note, a meter or a message is redacted', async () => {
    const { clock, deps } = setup()
    const noted = probe('noted', {
      run: async () => usageResult(
        [meter({ id: 'm', label: 'Seats of ops@example.test', unit: 'count', window: 'month', remaining: 1, primary: true, note: 'billed to billing@example.test' })],
        { notes: ['Token: alice@example.test (read)'] },
      ),
    })
    const refused = probe('refused', { run: async () => errorResult('forbidden', 'account bob@example.test is suspended') })
    const plan = buildJobs({ settings: { notedKey: 'N', refusedKey: 'R' }, rotationRows: [], probes: [noted, refused] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(JSON.stringify(report)).not.toContain('@example.test')
    expect(report.results[0].notes).toEqual(['Token: [email] (read)'])
    expect(report.results[0].meters[0]).toMatchObject({ label: 'Seats of [email]', note: 'billed to [email]' })
    expect(report.results[1].error?.message).toBe('account [email] is suspended')
  })

  test('counts, health and a stable order', async () => {
    const { clock, deps } = setup()
    const low = probe('low', {
      run: async () => usageResult([meter({ id: 'm', label: 'M', unit: 'credits', window: 'month', limit: 100, remaining: 3, primary: true })]),
    })
    const bad = probe('bad', { run: async () => errorResult('invalid_key', 'nope', { httpStatus: 401 }) })
    const plan = buildJobs({ settings: { lowKey: 'L', badKey: 'B' }, rotationRows: [], probes: [low, bad] })
    const report = await clock.drive(runJobs(plan, deps))
    expect(report.results.map(r => r.serviceId)).toEqual(['low', 'bad'])
    expect(report.results[0].health).toBe('low')
    expect(report.results[1].health).toBeUndefined()
    expect(report.counts).toEqual({ services: 2, keys: 2, usage: 1, validNoUsage: 0, notChecked: 0, errors: 1, low: 1, exhausted: 0 })
    expect(report.schemaVersion).toBe(1)
    expect(report.inventory).toEqual(plan.inventory)
  })

  test('logs carry service, outcome and status only; unexpected answers log a drift line', async () => {
    const { clock, deps, logs } = setup()
    const drift = probe('drift', { run: async () => errorResult('unexpected_response', 'shape changed', { httpStatus: 200 }) })
    const plan = buildJobs({ settings: { driftKey: 'DRIFT-KEY-SECRET' }, rotationRows: [], probes: [drift] })
    await clock.drive(runJobs(plan, deps))
    expect(logs).toEqual(['[api-usage] drift error unexpected_response', '[api-usage] drift drift status=200'])
    expect(logs.join('\n')).not.toContain('DRIFT-KEY-SECRET')
  })
})
