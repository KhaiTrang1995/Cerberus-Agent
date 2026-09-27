/**
 * The "Check API usage" click flow: save-first, the overwrite confirm naming the
 * saved date, the running-scans warning, every server answer, and picking up a
 * run that started elsewhere.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, render, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'

const confirm = vi.fn()
const alertError = vi.fn()
const alertFn = vi.fn()
const toast = { info: vi.fn(), warning: vi.fn(), success: vi.fn(), error: vi.fn() }

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ confirm, alertError, alert: alertFn }),
  useToast: () => toast,
}))

import { useApiUsageReport, type ApiUsageMeta, type UseApiUsageReportArgs } from './useApiUsageReport'
import type { ApiUsageReportV1 } from '@/lib/apiUsage/types'

const TRACKED = [{ field: 'shodanApiKey', probeId: 'shodan', label: 'Shodan', role: 'key' as const, rotationTool: 'shodan' }]

function report(finishedAt = '2026-09-25T10:00:00.000Z'): ApiUsageReportV1 {
  return {
    schemaVersion: 1, startedAt: finishedAt, finishedAt, durationMs: 1000,
    counts: { services: 1, keys: 1, usage: 1, validNoUsage: 0, notChecked: 0, errors: 0, low: 0, exhausted: 0 },
    skippedEmpty: [], inventory: { shodanApiKey: { hint: '••••••••1234', extraKeys: 0 } },
    results: [],
  }
}

function meta(over: Partial<ApiUsageMeta> = {}): ApiUsageMeta {
  return { enabled: true, report: null, running: null, runBy: null, activity: { runningScans: [], agentRuns: [] }, tracked: TRACKED, ...over }
}

type Answer = { status: number; body: unknown }
let getAnswers: Answer[]
let postAnswers: (Answer | Error)[]
let fetchMock: ReturnType<typeof vi.fn>

function respond(a: Answer) {
  return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.body }
}

beforeEach(() => {
  vi.clearAllMocks()
  getAnswers = []
  postAnswers = []
  fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
    if ((init?.method ?? 'GET') === 'GET') {
      const next = getAnswers.length > 1 ? getAnswers.shift()! : getAnswers[0]
      return respond(next ?? { status: 200, body: meta() })
    }
    const next = postAnswers.shift()
    if (!next) throw new Error('unexpected POST')
    if (next instanceof Error) throw next
    return respond(next)
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function setup(over: Partial<UseApiUsageReportArgs> = {}) {
  const args: UseApiUsageReportArgs = {
    userId: 'u1', active: true, settingsDirty: false, saveSettings: vi.fn(async () => true),
    values: { shodanApiKey: '••••••••1234' }, extraKeyCounts: { shodan: 1 }, llmRows: [], llmLabel: t => t,
    ...over,
  }
  const hook = renderHook((p: UseApiUsageReportArgs) => useApiUsageReport(p), { initialProps: args })
  return { ...hook, args }
}

const posts = () => fetchMock.mock.calls.filter(c => c[1]?.method === 'POST').map(c => JSON.parse(String(c[1].body)))

function confirmText(callIndex = 0): string {
  const { container } = render(<>{confirm.mock.calls[callIndex][0] as ReactNode}</>)
  return container.textContent ?? ''
}

describe('loading', () => {
  test('fetches the metadata when the tab is active; counts keys from the masked state', async () => {
    getAnswers = [{ status: 200, body: meta() }]
    const { result } = setup()
    await waitFor(() => expect(result.current.meta).not.toBeNull())
    expect(fetchMock.mock.calls[0][0]).toBe('/api/users/u1/settings/api-usage')
    expect(result.current.summary).toEqual({ keys: 2, services: [{ id: 'shodan', label: 'Shodan' }] })
  })

  test('no fetch while the tab is not active', async () => {
    setup({ active: false })
    await new Promise(r => setTimeout(r, 20))
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('startCheck', () => {
  test('no report, nothing running: posts straight away and shows the report', async () => {
    getAnswers = [{ status: 200, body: meta() }]
    postAnswers = [{ status: 200, body: { report: report('2026-09-26T14:32:05.000Z'), saved: true } }]
    const { result } = setup()
    await waitFor(() => expect(result.current.meta).not.toBeNull())
    await act(() => result.current.startCheck())
    expect(confirm).not.toHaveBeenCalled()
    expect(posts()).toEqual([{ overwrite: false, ignoreRunningScans: false }])
    expect(result.current.view).toBe('report')
    expect(result.current.shown?.report.finishedAt).toBe('2026-09-26T14:32:05.000Z')
  })

  test('unsaved edits: "Save first?", and nothing runs when the save fails', async () => {
    confirm.mockResolvedValue(true)
    const saveSettings = vi.fn(async () => false)
    const { result } = setup({ settingsDirty: true, saveSettings })
    await act(() => result.current.startCheck())
    expect(confirm.mock.calls[0][1]).toBe('Save first?')
    expect(confirm.mock.calls[0][2]).toMatchObject({ confirmLabel: 'Save and check' })
    expect(saveSettings).toHaveBeenCalled()
    expect(posts()).toEqual([])
  })

  test('unsaved edits declined: nothing is saved or run', async () => {
    confirm.mockResolvedValue(false)
    const saveSettings = vi.fn(async () => true)
    const { result } = setup({ settingsDirty: true, saveSettings })
    await act(() => result.current.startCheck())
    expect(saveSettings).not.toHaveBeenCalled()
    expect(posts()).toEqual([])
  })

  test('an existing report: the confirm names its date; cancel keeps it', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    confirm.mockResolvedValue(false)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(confirm.mock.calls[0][1]).toBe('Replace the saved report?')
    expect(confirm.mock.calls[0][2]).toMatchObject({ confirmLabel: 'Run new check', cancelLabel: 'Keep current report' })
    const text = confirmText()
    expect(text).toMatch(/will be replaced/)
    expect(text).toMatch(/2025|2026/)
    expect(text).toMatch(/1 service \(2 keys\)/)
    expect(posts()).toEqual([])
    expect(result.current.meta?.report?.finishedAt).toBe(report().finishedAt)
  })

  test('confirmed: posts with overwrite', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    postAnswers = [{ status: 200, body: { report: report('2026-09-26T14:32:05.000Z'), saved: true } }]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(posts()).toEqual([{ overwrite: true, ignoreRunningScans: false }])
  })

  test('409 report_exists (another tab saved meanwhile): re-confirms with the new date, then overwrites', async () => {
    getAnswers = [{ status: 200, body: meta() }]
    postAnswers = [
      { status: 409, body: { error: 'report_exists', finishedAt: '2026-09-26T14:00:00.000Z' } },
      { status: 200, body: { report: report('2026-09-26T14:32:05.000Z'), saved: true } },
    ]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(confirm.mock.calls[0][1]).toBe('Replace the saved report?')
    expect(posts()).toEqual([{ overwrite: false, ignoreRunningScans: false }, { overwrite: true, ignoreRunningScans: false }])
    expect(result.current.view).toBe('report')
  })

  test('running scans: the confirm names them and the POST carries ignoreRunningScans', async () => {
    getAnswers = [{ status: 200, body: meta({ activity: {
      runningScans: [{ projectId: 'p1', projectName: 'acme', kind: 'full_recon', startedAt: null }, { projectId: 'p2', projectName: 'beta', kind: 'gvm', startedAt: null }],
      agentRuns: [{ projectId: 'p1', projectName: 'acme' }],
    } }) }]
    postAnswers = [{ status: 200, body: { report: report(), saved: true } }]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    const text = confirmText()
    expect(text).toMatch(/2 scans are running/)
    expect(text).toMatch(/Recon on acme, GVM on beta/)
    expect(text).toMatch(/the agent is working on acme/)
    expect(posts()).toEqual([{ overwrite: false, ignoreRunningScans: true }])
  })

  test('409 scans_running (a scan started meanwhile): asks again with the new list', async () => {
    getAnswers = [{ status: 200, body: meta() }]
    postAnswers = [
      { status: 409, body: { error: 'scans_running', scans: [{ projectId: 'p1', projectName: 'acme', kind: 'trufflehog', startedAt: null }], agentRuns: [] } },
      { status: 200, body: { report: report(), saved: true } },
    ]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(confirmText()).toMatch(/Secret Multiscanner on acme/)
    expect(posts()[1]).toEqual({ overwrite: false, ignoreRunningScans: true })
  })

  test.each([
    ['cooldown', { error: 'cooldown', retryAfterSec: 42 }, 429, () => expect(toast.info).toHaveBeenCalledWith(expect.stringMatching(/42 s/))],
    ['no_keys', { error: 'no_keys' }, 400, () => expect(toast.info).toHaveBeenCalledWith('No saved keys to check.')],
    ['busy', { error: 'busy', retryAfterSec: 30 }, 429, () => expect(toast.info).toHaveBeenCalledWith(expect.stringMatching(/Another check is running/))],
    ['activity_unknown', { error: 'activity_unknown' }, 503, () => expect(alertError).toHaveBeenCalledWith(expect.stringMatching(/Could not tell whether scans are running/))],
    ['disabled', { error: 'disabled' }, 409, () => expect(toast.warning).toHaveBeenCalledWith(expect.stringMatching(/API_USAGE_CHECK_ENABLED=false/))],
  ])('%s answer', async (_name, body, status, check) => {
    getAnswers = [{ status: 200, body: meta() }]
    postAnswers = [{ status, body }]
    const { result } = setup()
    await act(() => result.current.startCheck())
    check()
    expect(result.current.view).toBe('closed')
  })

  test('401 (session expired): tells the user the check may still be saved', async () => {
    getAnswers = [{ status: 200, body: meta() }]
    postAnswers = [{ status: 401, body: { error: 'Unauthorized' } }]
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(alertFn.mock.calls[0][0]).toMatch(/session expired.*log in and open Last report/i)
  })

  test('a network failure: alert, and the saved report is untouched', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    postAnswers = [new TypeError('fetch failed')]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(alertError).toHaveBeenCalledWith(expect.stringMatching(/saved report is unchanged/))
    expect(result.current.meta?.report?.finishedAt).toBe(report().finishedAt)
    expect(result.current.view).toBe('closed')
  })

  test('saved: false -> the fresh report is shown flagged as unsaved, with the previous date', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    postAnswers = [{ status: 200, body: { report: report('2026-09-26T14:32:05.000Z'), saved: false, saveError: 'the database refused the save' } }]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(result.current.shown).toMatchObject({ saved: false, saveError: 'the database refused the save', previousFinishedAt: report().finishedAt })
  })

  test('checks disabled on the host: no confirm, no POST', async () => {
    getAnswers = [{ status: 200, body: meta({ enabled: false }) }]
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(toast.warning).toHaveBeenCalled()
    expect(posts()).toEqual([])
  })
})

describe('a refused run from an open report', () => {
  test('cooldown keeps the report open instead of closing it', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    postAnswers = [{ status: 429, body: { error: 'cooldown', retryAfterSec: 30 } }]
    confirm.mockResolvedValue(true)
    const { result } = setup()
    await waitFor(() => expect(result.current.meta?.report).toBeTruthy())
    act(() => result.current.openReport())
    expect(result.current.view).toBe('report')
    await act(() => result.current.startCheck())
    expect(toast.info).toHaveBeenCalled()
    expect(result.current.view).toBe('report')
    expect(result.current.shown?.report.finishedAt).toBe(report().finishedAt)
  })
})

describe('a run started elsewhere', () => {
  test('GET running -> "running", polled until it lands, then the report opens in place', async () => {
    getAnswers = [
      { status: 200, body: meta({ running: { startedAt: '2026-09-26T14:32:00.000Z', keys: 3 } }) },
      { status: 200, body: meta({ running: { startedAt: '2026-09-26T14:32:00.000Z', keys: 3 } }) },
      { status: 200, body: meta({ report: report('2026-09-26T14:32:40.000Z') }) },
    ]
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const { result } = setup()
    await vi.waitFor(() => expect(result.current.running).toBe(true))
    act(() => result.current.openReport())
    expect(result.current.view).toBe('running')
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    await vi.waitFor(() => expect(result.current.running).toBe(false))
    expect(result.current.view).toBe('report')
    expect(result.current.shown?.report.finishedAt).toBe('2026-09-26T14:32:40.000Z')
  })

  test('409 run_in_progress on POST switches to the running view', async () => {
    // Mount, then startCheck's refresh (nothing running yet), then the refresh after the 409.
    getAnswers = [{ status: 200, body: meta() }, { status: 200, body: meta() }, { status: 200, body: meta({ running: { startedAt: '2026-09-26T14:32:00.000Z', keys: 2 } }) }]
    postAnswers = [{ status: 409, body: { error: 'run_in_progress', startedAt: '2026-09-26T14:32:00.000Z' } }]
    const { result } = setup()
    await act(() => result.current.startCheck())
    expect(result.current.view).toBe('running')
    expect(result.current.runStartedAt).toBe('2026-09-26T14:32:00.000Z')
  })
})

describe('stale', () => {
  test('a changed key hint or rotation count after the report -> stale; unsaved edits never count', async () => {
    getAnswers = [{ status: 200, body: meta({ report: report() }) }]
    const { result, rerender, args } = setup({ extraKeyCounts: {} })
    // toBeTruthy, not .not.toBeNull(): `meta?.report` is undefined while meta is still null.
    await waitFor(() => expect(result.current.meta?.report).toBeTruthy())
    act(() => result.current.openReport())
    expect(result.current.stale).toBe(false)
    rerender({ ...args, extraKeyCounts: {}, values: { shodanApiKey: '••••••••9999' } })
    expect(result.current.stale).toBe(true)
    rerender({ ...args, extraKeyCounts: {}, values: { shodanApiKey: '••••••••9999' }, settingsDirty: true })
    expect(result.current.stale).toBe(false)
  })
})
