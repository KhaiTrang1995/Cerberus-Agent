/**
 * Resolve a finding's stored key from its graph id (the tables' Node ID).
 *
 * A mute is keyed on the finding's stored id, which survives the DETACH DELETE
 * and recreate of an import or a version activation; the tables carry Neo4j's
 * internal id. This resolves the one to the other inside the caller's tenant.
 * An internal id is reused after its node is deleted, so a row loaded before an
 * activation can point at a different node now: the lookup is tenant-scoped
 * and only finding labels resolve, so the worst case is the caller's own
 * finding.
 *
 * Shared by `/api/triage/mute-by-graph-id` and Multi mute's suggest route.
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { muteableLabel, muteKey } from '@/lib/muteTarget'
import type { TriageCaller } from '@/lib/triageClient'

export type ResolvedFinding =
  | { ok: true; label: string; key: string }
  | { ok: false; response: NextResponse }

export const GRAPH_ID_PATTERN = /^\d{1,18}$/

export async function resolveFindingByGraphId(
  caller: TriageCaller,
  graphId: unknown,
): Promise<ResolvedFinding> {
  if (typeof graphId !== 'string' || !GRAPH_ID_PATTERN.test(graphId)) {
    return { ok: false, response: NextResponse.json({ error: 'graphId must be a graph node id' }, { status: 400 }) }
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
      return { ok: false, response: NextResponse.json(
        { error: 'This node is no longer in the graph.' }, { status: 409 }) }
    }
    labels = record.get('labels') as string[]
    props = { id: record.get('id'), finding_id: record.get('findingId') }
  } finally {
    await session.close()
  }

  const label = muteableLabel(labels)
  if (!label) {
    const kind = labels.find(l => l !== 'Muted') ?? 'This'
    return { ok: false, response: NextResponse.json({
      error: `${kind} nodes cannot be muted. Only findings can: an asset is ` +
        'context, and muting it would orphan the findings attached to it.',
    }, { status: 422 }) }
  }
  const key = muteKey(label, props)
  if (!key) {
    return { ok: false, response: NextResponse.json(
      { error: 'This finding has no stored id to mute it by.' }, { status: 422 }) }
  }
  return { ok: true, label, key }
}
