/**
 * validateApplication and the Jev engine flags.
 *
 * A saved preset can name an engine flag (a user preset is a snapshot of a
 * project's settings). Applying one that switches a hook onto Jev needs a Jev
 * token on the project OWNER's account. The owner is looked up here, not taken
 * from the applied row, because that row is limited to MCP-readable fields.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockProjectFind = vi.fn()
const mockTokenCount = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userProjectPreset: { findFirst: vi.fn() },
    userSettings: { findUnique: vi.fn() },
    project: { findUnique: (...a: unknown[]) => mockProjectFind(...a) },
    userLlmProvider: { count: (...a: unknown[]) => mockTokenCount(...a) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { extractPresetSettings } from '@/lib/project-preset-utils'
import { validateApplication } from './server'

const row = (): Record<string, unknown> => ({
  ...extractPresetSettings({}),
  mcpKaliExecEnabled: false,
  updateGraphDb: true,
  targetDomain: 'lab.example.com',
})

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectFind.mockResolvedValue({ userId: 'owner' })
  mockTokenCount.mockResolvedValue(0)
})

describe('validateApplication: a preset that switches a hook onto Jev', () => {
  const switchOn = () => {
    const current = row()
    return { current, application: { data: { ...current, ffufAiUseJev: true }, changed: ['ffufAiUseJev'] } }
  }

  test('with a token on the owner\'s account it is accepted', async () => {
    mockTokenCount.mockResolvedValue(1)
    const { current, application } = switchOn()
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
    expect(mockProjectFind).toHaveBeenCalledWith({ where: { id: 'p1' }, select: { userId: true } })
    expect(mockTokenCount).toHaveBeenCalledWith({ where: { userId: 'owner', providerType: 'jev' } })
  })

  test('without a token it is refused, keyless, so the caller does not say "re-save the preset"', async () => {
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem).not.toBeNull()
    expect(problem!.key).toBe('')
    expect(problem!.error).toContain('ffufAiUseJev')
    expect(problem!.error).toContain('Settings')
    expect(problem!.error.endsWith('.')).toBe(false)
  })

  test('it fails closed when the project owner cannot be read', async () => {
    mockProjectFind.mockRejectedValue(new Error('db down'))
    const { current, application } = switchOn()
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem?.error).toContain("Couldn't verify your Jev token")
  })

  test('it fails closed when the project has no owner', async () => {
    mockProjectFind.mockResolvedValue(null)
    const { current, application } = switchOn()
    expect(await validateApplication(application, current, 'p1', 'actor')).not.toBeNull()
    expect(mockTokenCount).not.toHaveBeenCalled()
  })
})

describe('validateApplication: no switch-on, no lookup', () => {
  test('an apply that leaves every engine as it was never touches the owner or token tables', async () => {
    const current = row()
    expect(await validateApplication({ data: { ...current }, changed: [] }, current, 'p1', 'actor')).toBeNull()
    expect(mockProjectFind).not.toHaveBeenCalled()
    expect(mockTokenCount).not.toHaveBeenCalled()
  })

  test('a stored true that the preset leaves alone does not need a token', async () => {
    const current = { ...row(), wafAiUseJev: true }
    expect(await validateApplication({ data: { ...current }, changed: [] }, current, 'p1', 'actor')).toBeNull()
    expect(mockTokenCount).not.toHaveBeenCalled()
  })

  test('switching a hook back to the LLM needs no token', async () => {
    const current = { ...row(), wafAiUseJev: true }
    const application = { data: { ...current, wafAiUseJev: false }, changed: ['wafAiUseJev'] }
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
    expect(mockTokenCount).not.toHaveBeenCalled()
  })
})

describe('validateApplication: a preset that turns on a Jev-only hook', () => {
  test('without a token it is refused, naming the field', async () => {
    const current = row()
    const application = { data: { ...current, httpxJevPageType: true }, changed: ['httpxJevPageType'] }
    const problem = await validateApplication(application, current, 'p1', 'actor')
    expect(problem).not.toBeNull()
    expect(problem!.error).toContain('httpxJevPageType')
  })

  test('with a token it is accepted', async () => {
    mockTokenCount.mockResolvedValue(1)
    const current = row()
    const application = { data: { ...current, hakrawlerJevSeedOrder: true }, changed: ['hakrawlerJevSeedOrder'] }
    expect(await validateApplication(application, current, 'p1', 'actor')).toBeNull()
  })
})
