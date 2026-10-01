/**
 * useHasJevProvider: whether the acting user has a TypeSafe Jev token.
 *
 * The load-bearing behaviour is that a lookup which FAILED is never reported as
 * "no token". ShodanSection's equivalent hook reads a failed fetch as "no key";
 * here that would tell a user who already has a token to go add one, and would
 * disable the Jev choice on a working setup. The form treats `error` and `no`
 * differently, so they must not collapse.
 *
 * Run: npx vitest run src/hooks/useHasJevProvider.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'

const project = vi.hoisted(() => ({ userId: 'user-1' as string | null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: project.userId }) }))

import { useHasJevProvider } from './useHasJevProvider'

let fetchMock: ReturnType<typeof vi.fn>

const rows = (...types: string[]) => ({
  ok: true, status: 200, json: async () => types.map((providerType, i) => ({ id: `p${i}`, providerType })),
})

beforeEach(() => {
  project.userId = 'user-1'
  fetchMock = vi.fn().mockResolvedValue(rows('anthropic'))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useHasJevProvider', () => {
  test('is loading until the lookup answers, and asks for this user\'s providers', async () => {
    const { result } = renderHook(() => useHasJevProvider())
    expect(result.current).toBe('loading')
    await waitFor(() => expect(result.current).not.toBe('loading'))
    expect(fetchMock).toHaveBeenCalledWith('/api/users/user-1/llm-providers')
  })

  test('yes when one of the rows is a Jev token', async () => {
    fetchMock.mockResolvedValue(rows('anthropic', 'jev'))
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('yes'))
  })

  test('no when the lookup worked and there is no Jev row', async () => {
    fetchMock.mockResolvedValue(rows('anthropic', 'openai_compatible'))
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('no'))
  })

  test('no for an account with no providers at all', async () => {
    fetchMock.mockResolvedValue(rows())
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('no'))
  })

  test.each([401, 403, 500, 503])('a %i answer is error, never "no token"', async status => {
    fetchMock.mockResolvedValue({ ok: false, status, json: async () => ({ error: 'x' }) })
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('error'))
  })

  test('a fetch that throws is error, never "no token"', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'))
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('error'))
  })

  test('a body that is not valid JSON is error, never "no token"', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token <') } })
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('error'))
  })

  test('a 200 whose body is not a list is error, never "no token" (malformed answer)', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ error: 'Failed to fetch LLM providers' }) })
    const { result } = renderHook(() => useHasJevProvider())
    await waitFor(() => expect(result.current).toBe('error'))
  })

  test('stays loading and asks nothing while the user is not known yet', async () => {
    project.userId = null
    const { result } = renderHook(() => useHasJevProvider())
    await Promise.resolve()
    expect(result.current).toBe('loading')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
