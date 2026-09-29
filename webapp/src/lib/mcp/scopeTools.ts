/**
 * update_project_scope: change an EXISTING project's target lists.
 *
 * Scope was create-only on this surface for every token. This reopens exactly
 * the target lists the project form already lets a person edit after creation -
 * a batch project's host list and the standalone scanners' targets - and
 * nothing else. The target domain, the address list, the targeting mode,
 * ownership verification and the target guardrail stay refused whatever the
 * token holds (the registry's `rescope` attribute is the list).
 *
 * The controls, in the order they run:
 *  - its own permission, never auto-ticked by any profile;
 *  - refused while anything reads or writes the graph: the in-app agent reads
 *    the batch groups every turn, and the scanners read their targets at spawn;
 *  - every value validated, every new batch root through the permanent
 *    guardrail, the batch grouping re-derived here and never taken from a caller;
 *  - on a third-party engagement a WIDENING must arrive with an authorization
 *    record, written in the same transaction, and passing one needs
 *    engagement:authorize as well;
 *  - a compare-and-swap on `updatedAt`, and an audit row with every before/after;
 *  - a batch that gains hosts pauses the project's scan schedules in the same
 *    transaction, so no unattended run reaches the new hosts before a person
 *    has looked at them.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { validateDomainBatch, type DomainGroup } from '@/lib/domainBatch'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { seedProjectDomains } from '@/lib/graphSeedDomains'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { assertReadableSelect } from '@/lib/mcpReadableFields'
import { auditableKey, filterReconSettings } from '@/lib/reconSettings/filter'
import { rescopableFields } from '@/lib/reconSettings/registry'
import { validateCrossFieldRules } from '@/lib/reconSettings/crossField'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import { normaliseAuthorization, refuseHardBlocked, type AuthorizationArgs } from '@/lib/mcp/engagementTools'
import { busyHint, casVersion, countQueuedJobsNeedingReview, describeAffectedSchedules } from '@/lib/mcp/writeTools'

export interface UpdateProjectScopeArgs {
  projectId: string
  changes: Record<string, unknown>
  authorization?: AuthorizationArgs
  expectedUpdatedAt?: string
}

type Row = Record<string, unknown> & {
  updatedAt: Date
  engagementKind: string
  domainBatchMode: boolean
  domainBatchGroups: unknown
}

/** `root|prefix` for every group: the shape a widening shows up in. */
function batchSignature(groups: unknown): Set<string> {
  const out = new Set<string>()
  for (const g of Array.isArray(groups) ? groups as Partial<DomainGroup>[] : []) {
    for (const p of g?.prefixes ?? []) out.add(`${String(g?.rootDomain ?? '')}|${p}`)
  }
  return out
}

/** How many host or wildcard entries this change adds to the batch. */
function batchEntriesAdded(row: Row, data: Record<string, unknown>): number {
  if (!('domainBatchGroups' in data)) return 0
  const before = batchSignature(row.domainBatchGroups)
  return [...batchSignature(data.domainBatchGroups)].filter(s => !before.has(s)).length
}

const rootsOf = (groups: unknown) => new Set(
  (Array.isArray(groups) ? groups as Partial<DomainGroup>[] : []).map(g => String(g?.rootDomain ?? '')).filter(Boolean)
)

const repoSet = (v: unknown) => new Set(
  String(v ?? '').split(',').map(r => r.trim().toLowerCase()).filter(Boolean)
)

const text = (v: unknown) => String(v ?? '').trim().toLowerCase()

/**
 * What this change adds to what the engagement can reach, in words, or an
 * empty list. Removals, a narrower GitHub repository list and the GVM strategy
 * are not widenings.
 */
function wideningsOf(row: Row, data: Record<string, unknown>): string[] {
  const out: string[] = []
  const added = batchEntriesAdded(row, data)
  if (added > 0) out.push(`the batch gains ${added} host or wildcard entr${added === 1 ? 'y' : 'ies'}`)
  if ('githubTargetOrg' in data && text(data.githubTargetOrg) && text(data.githubTargetOrg) !== text(row.githubTargetOrg)) {
    out.push('the GitHub hunt points at a different organisation')
  }
  if ('githubTargetRepos' in data) {
    const before = repoSet(row.githubTargetRepos)
    const after = repoSet(data.githubTargetRepos)
    // An empty list means EVERY repository, so emptying it is the widest move.
    if ((after.size === 0 && before.size > 0) || [...after].some(r => before.size > 0 && !before.has(r))) {
      out.push('the GitHub hunt covers more repositories')
    }
  }
  if ('supplyChainOrgName' in data && text(data.supplyChainOrgName) && text(data.supplyChainOrgName) !== text(row.supplyChainOrgName)) {
    out.push('the supply-chain scan points at a different organisation')
  }
  if ('supplyChainRepoUrl' in data && text(data.supplyChainRepoUrl) && text(data.supplyChainRepoUrl) !== text(row.supplyChainRepoUrl)) {
    out.push('the supply-chain scan points at a different repository')
  }
  return out
}

export async function updateProjectScope(ctx: McpContext, args: UpdateProjectScopeArgs) {
  requireScope(ctx.token, 'project:rescope')
  // Recording what authorized a widening is its own durable claim.
  if (args.authorization !== undefined) requireScope(ctx.token, 'engagement:authorize')
  await assertMcpProjectAccess(ctx.token.userId, args.projectId)
  enforceRate(ctx, 'write')

  const busy = await describeLiveGraphWriters(args.projectId)
  if (busy) {
    throw new McpToolError(
      `Cannot change this project's targets while ${busy}: the work in progress read its targets ` +
      'when it started and would report on a scope that no longer exists. ' +
      busyHint(busy),
      'busy'
    )
  }

  const filtered = filterReconSettings(args.changes, { mode: 'rescope', projectId: args.projectId })
  if (!filtered.ok) {
    throw new McpToolError(filtered.error, 'setting_rejected', { rejectedKey: auditableKey(filtered.key) })
  }

  const select = {
    ...Object.fromEntries(rescopableFields().map(f => [f.key, true])),
    engagementKind: true, domainBatchMode: true, domainBatchGroups: true, updatedAt: true,
  }
  assertReadableSelect(select, 'update_project_scope')
  const row = await prisma.project.findUnique({ where: { id: args.projectId }, select }) as Row | null
  if (!row) throw new McpToolError('Project not found', 'not_found')

  const data: Record<string, unknown> = { ...filtered.data }
  let addedRoots: string[] = []
  let removedRoots: string[] = []
  if ('domainBatchHosts' in data) {
    if (row.domainBatchMode !== true) {
      throw new McpToolError(
        'domainBatchHosts is the host list of a domain-batch project, and this project is not one. ' +
        'Its targeting mode is fixed at creation.',
        'setting_rejected', { rejectedKey: 'domainBatchHosts' }
      )
    }
    const batch = validateDomainBatch(data.domainBatchHosts as string[])
    if (!batch.ok) throw new McpToolError(batch.errors.join(' '), 'setting_rejected', { rejectedKey: 'domainBatchHosts' })
    const before = rootsOf(row.domainBatchGroups)
    const after = rootsOf(batch.groups)
    addedRoots = [...after].filter(r => !before.has(r)).sort()
    removedRoots = [...before].filter(r => !after.has(r)).sort()
    // Every root this project would scan, not only the new ones: a root that
    // joined the permanent blocklist since it was added must not ride along.
    refuseHardBlocked([...after])
    // The grouping is the scope every reader uses, so it is derived here from
    // the host list and never accepted from a caller.
    data.domainBatchHosts = batch.groups.flatMap(g => g.hosts)
    data.domainBatchGroups = batch.groups
  }

  const crossField = await validateCrossFieldRules({ ...row, ...data }, Object.keys(data), ctx.token.userId)
  if (crossField) throw new McpToolError(crossField, 'setting_rejected')

  const widenings = wideningsOf(row, data)
  if (widenings.length > 0 && row.engagementKind === 'third_party' && args.authorization === undefined) {
    throw new McpToolError(
      `This widens a third-party engagement (${widenings.join('; ')}), which needs a record of what ` +
      'authorized the wider scope. Pass `authorization` with the new scope document\'s digest; that ' +
      'also needs the engagement:authorize permission. Nothing was written.',
      'authorization_required'
    )
  }
  const authorization = args.authorization !== undefined ? normaliseAuthorization(args.authorization) : null

  const changed = Object.keys(data)
  if (changed.every(k => JSON.stringify(row[k] ?? null) === JSON.stringify(data[k] ?? null)) && !authorization) {
    throw new McpToolError('Nothing to change: the project already holds these values.', 'bad_args')
  }

  const version = casVersion(row.updatedAt, args.expectedUpdatedAt)
  const batchGained = batchEntriesAdded(row, data) > 0
  const { authorizationId, paused } = await prisma.$transaction(async tx => {
    const { count } = await tx.project.updateMany({
      where: { id: args.projectId, updatedAt: version },
      data: { ...data, updatedById: ctx.token.userId } as never,
    })
    if (count === 0) {
      throw new McpToolError(
        'The project changed since this call read it. Nothing was written; read it again and retry.',
        'conflict'
      )
    }
    // A scheduled run is a full recon of the whole batch that nobody watches
    // start. Only the batch pauses them: the GitHub and supply-chain targets
    // are never read by a scheduled run, and a narrowing takes nothing new.
    const paused = batchGained
      ? await tx.scanSchedule.findMany({
          where: { projectId: args.projectId, enabled: true },
          select: { id: true, label: true },
        })
      : []
    if (paused.length > 0) {
      await tx.scanSchedule.updateMany({
        where: { id: { in: paused.map(s => s.id) }, enabled: true },
        data: { enabled: false },
      })
    }
    if (!authorization) return { authorizationId: null, paused }
    const created = await tx.engagementAuthorization.create({
      data: {
        projectId: args.projectId,
        ...authorization,
        recordedVia: 'mcp',
        recordedByTokenId: ctx.token.tokenId,
        recordedByUserId: ctx.token.userId,
      },
      select: { id: true },
    })
    return { authorizationId: created.id, paused }
  })
  const pausedSchedules = { count: paused.length, names: paused.map(s => s.label || s.id) }

  // After the commit, and best-effort: the partial-recon picker lists Domain
  // nodes, so a new root without one could not be scanned on its own.
  // The owner is the token's user: assertMcpProjectAccess proved it, and the
  // row's own userId is not an MCP-readable column.
  const graphSeeded = await seedProjectDomains(addedRoots, ctx.token.userId, args.projectId)

  const shown = changed.filter(k => k !== 'domainBatchGroups')
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.update_project_scope',
    targetType: 'project',
    targetId: args.projectId,
    before: Object.fromEntries(changed.map(k => [k, row[k] ?? null])),
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      changes: Object.fromEntries(changed.map(k => [k, data[k] ?? null])),
      widenings,
      authorizationId,
      authorizationDigest: authorization?.documentSha256 ?? null,
      graphSeeded,
      pausedScheduleIds: paused.map(s => s.id),
    },
    source: 'mcp',
  })

  const [queuedJobsNeedingReview, affectedSchedules] = await Promise.all([
    countQueuedJobsNeedingReview(args.projectId),
    describeAffectedSchedules(args.projectId),
  ])

  return {
    projectId: args.projectId,
    changes: shown.map(k => ({ key: k, before: row[k] ?? null, after: data[k] ?? null })),
    addedRoots,
    removedRoots,
    widenings,
    authorizationId,
    queuedJobsNeedingReview,
    pausedSchedules,
    affectedSchedules,
    graphSeeded,
    note:
      (graphSeeded ? '' : 'The new roots could not be added to the graph yet; the next full recon adds them. ') +
      (pausedSchedules.count > 0
        ? `The batch gained hosts, so ${pausedSchedules.count} scheduled scan(s) were paused; a person ` +
          're-enables them in the Scans tab once they have reviewed the new scope. '
        : '') +
      'The change applies to the NEXT scan. Call preflight_scope_check and report what it says.',
  }
}
