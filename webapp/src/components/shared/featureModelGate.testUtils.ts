/**
 * Test helpers for components that run a feature through the real
 * FeatureModelGateProvider: a fetch stub that serves the user's saved models,
 * /api/models and the settings PUT, plus a way to pick a model in the gate.
 * Every other URL goes to `route`.
 */
import { vi } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'

export const GATE_USER = 'user-1'

export const GATE_MODELS = {
  Anthropic: [
    { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', context_length: 200000, description: '' },
    { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', context_length: 200000, description: '' },
  ],
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

export interface GateFetchStub {
  fetch: ReturnType<typeof vi.fn>
  saved: Record<string, string>
  /** Calls to a URL (and method, GET when omitted). */
  calls: (url: string, method?: string) => Array<[string, RequestInit | undefined]>
}

export function stubGateFetch(
  saved: Record<string, string>,
  route: (url: string, init: RequestInit | undefined) => Response | Promise<Response>,
): GateFetchStub {
  const settingsUrl = `/api/users/${GATE_USER}/settings`
  const stub: GateFetchStub = {
    saved: { ...saved },
    fetch: vi.fn(),
    calls: (url, method = 'GET') => stub.fetch.mock.calls.filter(([u, init]) =>
      u === url && ((init as RequestInit | undefined)?.method ?? 'GET') === method) as Array<[string, RequestInit | undefined]>,
  }
  stub.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/models') return jsonResponse(200, GATE_MODELS)
    if (url === settingsUrl && method === 'GET') return jsonResponse(200, { featureModels: { ...stub.saved } })
    if (url === settingsUrl && method === 'PUT') {
      const patch = JSON.parse(init!.body as string).featureModels as Record<string, string>
      for (const [k, v] of Object.entries(patch)) {
        if (v) stub.saved[k] = v
        else delete stub.saved[k]
      }
      return jsonResponse(200, { featureModels: { ...stub.saved } })
    }
    return route(url, init)
  })
  vi.stubGlobal('fetch', stub.fetch)
  return stub
}

/** Pick `name` in the open gate and confirm it. */
export async function pickInGate(name: string, confirmLabel = 'Save and continue') {
  fireEvent.click(await screen.findByText('Choose a model'))
  fireEvent.click(await screen.findByText(name))
  fireEvent.click(screen.getByRole('button', { name: confirmLabel }))
}
