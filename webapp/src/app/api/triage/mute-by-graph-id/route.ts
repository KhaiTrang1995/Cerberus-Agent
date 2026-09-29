import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'
import { readJsonBody } from '@/lib/jsonBody'
import { invalidateCache } from '@/app/api/graph/cache'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { muteableLabel, muteKey } from '@/lib/muteTarget'

/**
 * POST /api/triage/mute-by-graph-id - `/api/triage/mute` for a node known only
 * by its graph id.
 *
 * Body: { projectId, graphId }
 *
 * The graph tables carry Neo4j's internal id per row (the Node ID column), but
 * a mute is keyed on the finding's stored id, which survives the DETACH DELETE
 * and recreate of an import or a version activation. This resolves the one to
 * the other inside the caller's tenant, then issues exactly the mute the
 * Priority Board does.
 *
 * An internal id is reused after its node is deleted, so a row loaded before an
 * activation can point at a different node now. What still holds: the lookup
 * is tenant-scoped, only finding labels resolve, and the result is one
 * reversible mute. A node that is gone answers 409, the same "changed while the
 * page was open" the Priority Board handles.
 */
export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, graphId } = parsed.body as { projectId?: string; graphId?: unknown }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (typeof graphId !== 'string' || !/^\d{1,18}$/.test(graphId)) {
    return NextResponse.json({ error: 'graphId must be a graph node id' }, { status: 400 })
  }

  const session = getGraphSession()
  let labels: string[]
  let props: { id?: unknown; finding_id?: unknown }
  try {
    const result = await session.run(
      `MATCH (n)
       WHERE id(n) = toInteger($graphId)
         AND n.user_id = $userId AND n.project_id = $projectId
       RETURN labels(n) AS labels, n.id AS id, n.finding_id AS findingId`,
      { graphId, userId: caller.userId, projectId: caller.projectId },
    )
    const record = result.records[0]
    if (!record) {
      return NextResponse.json(
        { error: 'This node is no longer in the graph.' }, { status: 409 })
    }
    labels = record.get('labels') as string[]
    props = { id: record.get('id'), finding_id: record.get('findingId') }
  } finally {
    await session.close()
  }

  const label = muteableLabel(labels)
  if (!label) {
    const kind = labels.find(l => l !== 'Muted') ?? 'This'
    return NextResponse.json({
      error: `${kind} nodes cannot be muted. Only findings can: an asset is ` +
        'context, and muting it would orphan the findings attached to it.',
    }, { status: 422 })
  }
  const nodeId = muteKey(label, props)
  if (!nodeId) {
    return NextResponse.json(
      { error: 'This finding has no stored id to mute it by.' }, { status: 422 })
  }

  const res = await callGraphTriage('mute', caller, {
    node_id: nodeId,
    reason: '',
    muted_by: caller.userId,
  })
  // The Graph Map serves a cached copy for up to 10 s; a muted finding must
  // leave it now, not then.
  if (res.ok) invalidateCache(caller.projectId)
  return res
}
