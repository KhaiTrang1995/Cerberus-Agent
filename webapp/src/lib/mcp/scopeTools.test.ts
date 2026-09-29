/**
 * update_project_scope: the one tool that changes an existing project's
 * targets.
 *
 * Every test here is a way the platform could be re-pointed without the
 * controls that make re-pointing acceptable: a field outside the eight target
 * lists, a root on the permanent blocklist, a third-party widening with no
 * record of who authorized it, or a grouping the caller supplied instead of
 * the one derived from the host list.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  projectFind: vi.fn(),
  projectUpdateMany: vi.fn(),
  authCreate: vi.fn(),
  jobs: vi.fn(),
  schedules: vi.fn(),
  userSettings: vi.fn(),
  live: vi.fn(),
  seed: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      findUnique: (...a: unknown[]) => h.projectFind(...a),
      updateMany: (...a: unknown[]) => h.projectUpdateMany(...a),
    },
    engagementAuthorization: { create: (...a: unknown[]) => h.authCreate(...a) },
    jobQueue: { findMany: (...a: unknown[]) => h.jobs(...a) },
    scanSchedule: { findMany: (...a: unknown[]) => h.schedules(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.userSettings(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: (...a: unknown[]) => h.live(...a) }))
vi.mock('@/lib/graphSeedDomains', () => ({ seedProjectDomains: (...a: unknown[]) => h.seed(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { McpScopeError, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { validateDomainBatch } from '@/lib/domainBatch'
import { createOnlyFields } from '@/lib/reconSettings/registry'
import { updateProjectScope } from './scopeTools'
import type { McpContext } from './tools'

const EVERY: McpScope[] = [
  'recon:read', 'recon:scan', 'recon:overwrite', 'recon:settings', 'triage:read', 'recon:queue',
  'triage:write', 'graph:cypher', 'project:create', 'engagement:authorize',
  'preset:write', 'preset:apply', 'project:rescope', 'kali:exec',
]
const ctx = (scopes: McpScope[] = ['project:rescope']): McpContext => ({
  token: { tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'agent', scopes },
})

const AT = new Date('2026-09-29T08:00:00.000Z')
const AUTH = {
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  issuedAt: '2026-01-01T00:00:00.000Z',
}

const batchRow = (hosts: string[], over: Record<string, unknown> = {}) => ({
  domainBatchMode: true,
  domainBatchHosts: hosts,
  domainBatchGroups: validateDomainBatch(hosts).groups,
  engagementKind: 'internal',
  githubTargetOrg: '', githubTargetRepos: '', gvmScanTargets: 'both',
  supplyChainOrgName: '', supplyChainRepoUrl: '', supplyChainRepoRef: '', supplyChainRepoScope: '',
  userId: 'owner',
  updatedAt: AT,
  ...over,
})

let row: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  row = batchRow(['a.example.com', 'b.example.com'])
  h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
    Object.keys(args.select ?? {}).length === 2 ? { id: 'p1', userId: 'owner' } : row)
  h.projectUpdateMany.mockResolvedValue({ count: 1 })
  h.authCreate.mockResolvedValue({ id: 'auth1' })
  h.jobs.mockResolvedValue([])
  h.schedules.mockResolvedValue([])
  h.userSettings.mockResolvedValue(null)
  h.live.mockResolvedValue(null)
  h.seed.mockResolvedValue(true)
  h.audit.mockResolvedValue(undefined)
})

const call = (changes: Record<string, unknown>, extra: Record<string, unknown> = {}, scopes?: McpScope[]) =>
  updateProjectScope(ctx(scopes), { projectId: 'p1', changes, ...extra } as never)

describe('only the eight target lists move', () => {
  test('every other create-only field is refused, whatever the token holds', async () => {
    const fixed = createOnlyFields().filter(f => !f.rescope).map(f => f.key)
    expect(fixed).toHaveLength(11)
    for (const key of fixed) {
      __resetRateLimiter()
      await expect(call({ [key]: 'x' }, {}, EVERY), key).rejects.toMatchObject({ code: 'setting_rejected' })
    }
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('an ordinary setting is pointed at update_recon_settings', async () => {
    await expect(call({ katanaDepth: 3 })).rejects.toThrow(/update_recon_settings/)
  })

  test('the batch grouping is derived here; a caller\'s copy is refused', async () => {
    await expect(call({ domainBatchGroups: [{ rootDomain: 'attacker.example', prefixes: ['*'] }] }))
      .rejects.toMatchObject({ code: 'setting_rejected' })
    await call({ domainBatchHosts: ['a.example.com', 'c.example.org'] })
    const data = h.projectUpdateMany.mock.calls[0][0].data
    expect(data.domainBatchGroups).toEqual(validateDomainBatch(['a.example.com', 'c.example.org']).groups)
    expect(data.updatedById).toBe('owner')
  })
})

describe('values are validated as the form validates them', () => {
  test('the GVM strategy is a closed set', async () => {
    await expect(call({ gvmScanTargets: 'everything' })).rejects.toThrow(/must be one of both, ips_only, hostnames_only/)
    await expect(call({ gvmScanTargets: 'ips_only' })).resolves.toBeTruthy()
  })

  test('GitHub names follow GitHub\'s grammar', async () => {
    await expect(call({ githubTargetOrg: 'bad org!' })).rejects.toMatchObject({ code: 'setting_rejected' })
    await expect(call({ githubTargetRepos: 'owner/repo' })).rejects.toThrow(/no owner\/ prefix/)
    await expect(call({ githubTargetOrg: 'acme-labs', githubTargetRepos: 'api, web.site' })).resolves.toBeTruthy()
  })

  test('a supply-chain repository on a host nobody registered is refused', async () => {
    await expect(call({ supplyChainRepoUrl: 'https://git.example.com/acme/app' }))
      .rejects.toThrow(/Repository must be a repo on github\.com/)
  })

  test('a batch host list on a project that is not a batch is refused', async () => {
    row = batchRow(['a.example.com'], { domainBatchMode: false })
    await expect(call({ domainBatchHosts: ['a.example.com'] })).rejects.toThrow(/not one/)
  })

  test('the permanent guardrail refuses a blocked root', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'portal.example.gov'] }))
      .rejects.toThrow(/permanently blocked/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })
})

describe('widening a third-party engagement needs an authorization', () => {
  beforeEach(() => {
    row = batchRow(['a.example.com', 'b.example.com'], { engagementKind: 'third_party' })
  })

  test('a new root without one is refused, and nothing is written', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] }))
      .rejects.toMatchObject({ code: 'authorization_required' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a wildcard on an existing root is a widening too', async () => {
    await expect(call({ domainBatchHosts: ['*.example.com'] }))
      .rejects.toMatchObject({ code: 'authorization_required' })
  })

  test('passing an authorization needs engagement:authorize: a scope denial', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'c.example.org'] }, { authorization: AUTH }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('with both, the authorization is written in the same transaction', async () => {
    const r = await call(
      { domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] },
      { authorization: AUTH },
      ['project:rescope', 'engagement:authorize'],
    )
    expect(r.authorizationId).toBe('auth1')
    expect(r.addedRoots).toEqual(['example.org'])
    expect(h.authCreate.mock.calls[0][0].data).toMatchObject({
      projectId: 'p1', documentSha256: 'a'.repeat(64), recordedVia: 'mcp', recordedByTokenId: 't1',
    })
  })

  test('a narrowing needs neither', async () => {
    const r = await call({ domainBatchHosts: ['a.example.com'] })
    expect(r.removedRoots).toEqual([])
    expect(h.authCreate).not.toHaveBeenCalled()
    expect(h.projectUpdateMany).toHaveBeenCalled()
  })

  test('a new GitHub organisation is a widening; emptying the repo list is too', async () => {
    await expect(call({ githubTargetOrg: 'other-org' })).rejects.toMatchObject({ code: 'authorization_required' })
    row = { ...row, githubTargetRepos: 'api' }
    await expect(call({ githubTargetRepos: '' })).rejects.toMatchObject({ code: 'authorization_required' })
    await expect(call({ gvmScanTargets: 'ips_only' })).resolves.toBeTruthy()
  })
})

describe('the write itself', () => {
  test('a compare-and-swap, and a lost one is a conflict', async () => {
    await call({ gvmScanTargets: 'ips_only' })
    expect(h.projectUpdateMany.mock.calls[0][0].where).toEqual({ id: 'p1', updatedAt: AT })
    h.projectUpdateMany.mockResolvedValue({ count: 0 })
    await expect(call({ gvmScanTargets: 'hostnames_only' })).rejects.toMatchObject({ code: 'conflict' })
  })

  test('refused while anything reads or writes the graph', async () => {
    h.live.mockResolvedValue('an agent session is running')
    await expect(call({ gvmScanTargets: 'ips_only' })).rejects.toMatchObject({ code: 'busy' })
  })

  test('a failed Domain seed is reported, and the update stands', async () => {
    h.seed.mockResolvedValue(false)
    const r = await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] })
    expect(r.graphSeeded).toBe(false)
    expect(h.projectUpdateMany).toHaveBeenCalled()
    expect(h.seed.mock.calls[0]).toEqual([['example.org'], 'owner', 'p1'])
    expect(h.audit.mock.calls[0][0].after.graphSeeded).toBe(false)
  })

  test('it reports the queued scans the change parked, by id', async () => {
    h.jobs.mockResolvedValue([{ id: 'j9', kind: 'gvm', projectId: 'p1', payload: {}, settingsHash: 'old' }])
    const r = await call({ gvmScanTargets: 'ips_only' })
    expect(r.queuedJobsNeedingReview).toEqual({ count: 1, jobIds: ['j9'] })
  })

  test('a call that changes nothing is refused', async () => {
    await expect(call({ gvmScanTargets: 'both' })).rejects.toMatchObject({ code: 'bad_args' })
  })
})
