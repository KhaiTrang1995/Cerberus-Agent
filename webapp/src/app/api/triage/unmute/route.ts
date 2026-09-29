import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { requireProjectOwner, graphTriage, realActorUserId } from '@/lib/triageClient'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { activationBusy, activationBusyResponse } from '@/lib/activationLock'
import { auditUnmute, ensureExemptions } from '@/lib/unmuteExemptions'
import { invalidateCache } from '@/app/api/graph/cache'

/**
 * POST /api/triage/unmute - restore suppressed findings.
 *
 * Body: { projectId, keys: string[] }, or the single-finding form { projectId, nodeId }.
 *
 * Lossless: each finding keeps every relationship and property it had. The triage
 * VERDICT is deliberately left in place -- unmuting means "show me this again",
 * not "forget the analysis".
 *
 * Every unmuted finding also gets a NodeFilterExemption, whether a person or a
 * rule had muted it, so an operator's unmute sticks: no filter rule mutes that
 * node again until the exemption is cleared from the Mute Rules page. The
 * exemption is a Postgres row rather than a graph property because the prune,
 * the recon asset clear, version activation and import would each delete a
 * property.
 *
 * The order is graph first, exemptions second: a person watching the table can
 * see a failed exemption and act on it (`exemptionError`). MCP `unmute_findings`
 * uses the same helpers in the opposite order, for an unattended caller.
 */
const MAX_KEYS = 500

export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, keys } = parsed.body as {
    projectId?: string; nodeId?: unknown; keys?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller

  const wanted = Array.isArray(keys)
    ? keys.filter((k): k is string => typeof k === 'string' && k.length > 0 && k.length <= 300)
    : typeof nodeId === 'string' && nodeId ? [nodeId] : []
  if (wanted.length === 0) {
    return NextResponse.json({ error: 'keys (or nodeId) is required' }, { status: 400 })
  }
  if (wanted.length > MAX_KEYS) {
    return NextResponse.json({ error: `at most ${MAX_KEYS} keys per request` }, { status: 400 })
  }

  if (await activationBusy(caller.projectId)) return activationBusyResponse()

  // A running apply read the exemptions when it started, so a finding unmuted
  // now would be muted again when its page comes up. Refused until it ends.
  const applying = await describeNodeFilterWriter(caller.projectId)
  if (applying) {
    return NextResponse.json(
      { error: `Cannot unmute while ${applying}. Try again when it finishes.` },
      { status: 409 },
    )
  }

  const result = await graphTriage('unmute_many', caller, { keys: [...new Set(wanted)] })
  if (result.status !== 200) return NextResponse.json(result.body, { status: result.status })
  invalidateCache(caller.projectId)

  const items = (Array.isArray(result.body.items) ? result.body.items : []) as {
    key: string; label: string; muted_by: string
  }[]
  const realActor = await realActorUserId()

  let exempted = 0
  let exemptionError: string | null = null
  try {
    const result = await ensureExemptions(
      caller.projectId,
      items.map(i => ({ label: i?.label, key: i?.key })),
      { createdBy: caller.userId, realActorUserId: realActor },
    )
    exempted = result.total
  } catch (e) {
    // The graph unmute already happened and is not rolled back: the finding is
    // visible, which is what the operator asked for. What is lost is only the
    // guarantee that a rule will not mute it again, so the caller is told.
    console.error('[unmute] could not record node-filter exemptions:', e)
    exemptionError = 'Unmuted, but the exemption was not saved: a mute rule may mute it again.'
  }

  if (items.length > 0) {
    await auditUnmute({
      actorId: caller.userId,
      projectId: caller.projectId,
      source: 'ui',
      realActorUserId: realActor,
      exempted,
      items: items.map(i => ({ key: i.key, label: i.label, mutedBy: i.muted_by })),
    })
  }

  return NextResponse.json({
    unmuted: items.length,
    items,
    exempted,
    ...(exemptionError ? { exemptionError } : {}),
  })
}
