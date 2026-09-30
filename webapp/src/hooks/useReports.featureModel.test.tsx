/**
 * Report generation and the user's "Report narratives" model.
 *
 * The gate runs inside the mutation. A cancelled first prompt resolves null
 * (nothing was sent, so there is no error to show); model_required from the
 * route opens the gate again and retries once; every other code becomes the
 * mutation's error, worded by featureModelMessage.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import type { ReactNode } from 'react'
import { renderHook, screen, cleanup, fireEvent, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { useAllReports, useReports, type ReportMeta } from './useReports'

const REPORTS_URL = '/api/projects/p1/reports'
const REPORT = { id: 'r1', projectId: 'p1', title: 'Pentest Report', hasNarratives: true } as ReportMeta

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <FeatureModelGateProvider>{children}</FeatureModelGateProvider>
    </QueryClientProvider>
  )
}

function reportsRoute(post: () => Response) {
  return (url: string, init: RequestInit | undefined) => {
    if (url === REPORTS_URL && init?.method === 'POST') return post()
    return jsonResponse(200, [])
  }
}

describe('useAllReports().generate', () => {
  test('no saved model: the gate opens first, then the report is generated once', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    await pickInGate('Claude Opus 4.6')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.saved).toEqual({ report_narratives: 'claude-opus-4-6' })
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(1)
  })

  test('cancelling the first prompt resolves null and sends nothing', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await expect(generated).resolves.toBeNull()
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(0)
    await waitFor(() => expect(result.current.generateError).toBeNull())
  })

  test('model_required from the route opens the gate and retries exactly once', async () => {
    let n = 0
    const stub = stubGateFetch({ report_narratives: 'claude-haiku-4-5' }, reportsRoute(() => (++n === 1
      ? jsonResponse(409, { error: 'x', code: 'model_required', featureId: 'report_narratives' })
      : jsonResponse(200, REPORT))))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    await pickInGate('Claude Opus 4.6')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(2)
  })

  test('a non-gate code is the mutation error, in its fixed wording, and never opens the gate', async () => {
    stubGateFetch({ report_narratives: 'claude-haiku-4-5' },
      reportsRoute(() => jsonResponse(502, { error: 'x', code: 'agent_outdated', featureId: 'report_narratives' })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1')).rejects.toThrow('The agent is older than the webapp: rebuild it')
    })
    await waitFor(() => expect(result.current.generateError?.message).toBe('The agent is older than the webapp: rebuild it'))
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('useReports(projectId).generate', () => {
  test('runs through the same gate', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useReports('p1'), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate() })
    await pickInGate('Claude Haiku 4.5')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.saved).toEqual({ report_narratives: 'claude-haiku-4-5' })
  })
})
