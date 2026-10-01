/**
 * Import and the Jev engine flags.
 *
 * Import KEEPS a bundle's engine choices and warns, instead of refusing: a
 * bundle exported from an account with a Jev token must still import on an
 * account without one. The warning names each hook that will use its static
 * fallback until the importer adds a token. The warning lookup never fails an
 * import that already succeeded.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), tokenCount: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
    userLlmProvider: { count: (...a: unknown[]) => h.tokenCount(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

async function bundle(project: Record<string, unknown>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.createProject.mockResolvedValue({ id: 'new', name: 'imported' })
  h.tokenCount.mockResolvedValue(0)
})

describe('importing a bundle whose hooks run on Jev', () => {
  test('the engine choice is kept and each hook is named in a warning when the importer has no token', async () => {
    const res = await POST(await bundle({ ffufAiUseJev: true, takeoverAiUseJev: true }))
    expect(res.status).toBe(200)
    const created = h.createProject.mock.calls[0][0].data
    expect(created.ffufAiUseJev).toBe(true)
    expect(created.takeoverAiUseJev).toBe(true)
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(2)
    expect(warnings[0]).toContain('ffufAiUseJev')
    expect(warnings[1]).toContain('takeoverAiUseJev')
    expect(warnings.join(' ')).toContain('static fallback')
    expect(h.tokenCount).toHaveBeenCalledWith({ where: { userId: 'importer', providerType: 'jev' } })
  })

  test('with a token there is nothing to warn about', async () => {
    h.tokenCount.mockResolvedValue(1)
    const res = await POST(await bundle({ wafAiUseJev: true }))
    expect(res.status).toBe(200)
    expect((await res.json()).warnings).toEqual([])
  })

  test('a failed token lookup does not fail the import: it becomes one warning', async () => {
    h.tokenCount.mockRejectedValue(new Error('db down'))
    const res = await POST(await bundle({ nucleiTagsAiUseJev: true }))
    expect(res.status).toBe(200)
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(1)
    expect(h.createProject).toHaveBeenCalled()
  })

  test('a bundle with no Jev hook has an empty warnings list and no lookup', async () => {
    const res = await POST(await bundle({ ffufAiUseJev: false }))
    expect((await res.json()).warnings).toEqual([])
    expect(h.tokenCount).not.toHaveBeenCalled()
  })
})
