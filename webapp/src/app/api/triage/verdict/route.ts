import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, realActorUserId } from '@/lib/triageClient'
import { readJsonBody } from '@/lib/jsonBody'
import { writeAudit } from '@/lib/audit'
import { recordVerdict, VERDICT_STATUSES, type VerdictStatus } from '@/lib/triage/actions'
import { actionErrorResponse, parseFindingRef } from '@/lib/triage/http'

/**
 * POST /api/triage/verdict - a person's decision on a finding.
 *
 * Body: { projectId, nodeId, status, reason?, label? }
 *
 * `confirmed` (Real) sets the finding's `real` factor to 100%; `likely_noise`
 * (False positive) moves it to the false-positive section; `unreviewed` is a
 * RESET that removes the decision, so the finding is ranked from its rules and
 * review again and is no longer protected from prune or Mute Rules. The agent
 * rescores the finding in the same transaction, and the answer carries the new
 * row, so the board replaces it in place without a reload.
 */
export async function POST(request: NextRequest) {
  // A plain HTML form cannot send JSON, so a cross-site page cannot drive this.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, status, reason, label } = parsed.body as {
    projectId?: string; nodeId?: unknown; status?: string; reason?: unknown; label?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  const ref = parseFindingRef(nodeId, label)
  if (ref instanceof NextResponse) {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }
  if (typeof status !== 'string' || !(VERDICT_STATUSES as readonly string[]).includes(status)) {
    return NextResponse.json(
      { error: `status must be one of ${VERDICT_STATUSES.join(', ')}` },
      { status: 400 },
    )
  }

  try {
    const result = await recordVerdict(caller, {
      findingId: ref.findingId,
      label: ref.label,
      status: status as VerdictStatus,
      reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
      channel: 'app',
    })
    void writeAudit({
      actorId: caller.userId,
      action: 'triage.verdict',
      targetType: 'finding',
      targetId: ref.findingId,
      after: {
        projectId: caller.projectId,
        findingId: ref.findingId,
        status,
        label: result.label,
        before: result.before,
        after: result.after,
        realActorUserId: await realActorUserId(),
      },
      source: 'ui',
    })
    return NextResponse.json({ updated: true, ...result })
  } catch (err) {
    return actionErrorResponse(err)
  }
}
