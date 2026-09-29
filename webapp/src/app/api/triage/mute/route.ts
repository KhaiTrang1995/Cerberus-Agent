import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'
import { readJsonBody } from '@/lib/jsonBody'
import { invalidateCache } from '@/app/api/graph/cache'
import { activationBusy, activationBusyResponse } from '@/lib/activationLock'

/**
 * POST /api/triage/mute - suppress one finding as noise.
 *
 * Body: { projectId, nodeId, reason? }
 *
 * NOT cascaded to Remediation, deliberately. A Remediation is synthesised by the
 * CypherFix LLM from CORRELATED findings -- one work item can cover several, and
 * the model carries no link back to the finding nodes it came from (only
 * `affectedAssets`, `cveIds` and prose). There is therefore no key to cascade on,
 * and matching by title or asset would dismiss the wrong work item.
 *
 * What covers the gap instead: the classify phase drops `likely_noise` before
 * remediations are generated, and both the dashboard and the client report
 * exclude `status = 'dismissed'`. Linking the two properly needs a
 * `findingIds String[]` on Remediation plus attribution from the generator,
 * which is a schema change and is written up as a follow-up.
 *
 * Never overwrites: an already-muted finding is left exactly as it was (a
 * rule's or an agent's mute keeps its attribution) and the answer carries
 * `already: true`. Refused with 409 while a version activation holds the graph,
 * which would otherwise swallow the mute after reporting success.
 */
export async function POST(request: NextRequest) {
  // A plain HTML form cannot send JSON, so a cross-site page cannot drive this.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, reason } = parsed.body as {
    projectId?: string; nodeId?: unknown; reason?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }
  if (await activationBusy(caller.projectId)) return activationBusyResponse()

  const res = await callGraphTriage('mute', caller, {
    node_id: nodeId,
    reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
    muted_by: caller.userId,
  })
  // The Graph Map serves a cached copy for up to 10 s; a muted finding must
  // leave it now, not then.
  if (res.ok) invalidateCache(caller.projectId)
  return res
}
