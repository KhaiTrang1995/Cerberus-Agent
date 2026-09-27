/**
 * Scan Timeline - version list for a project.
 *
 * GET  /api/projects/[id]/versions   list versions (newest first)
 * POST /api/projects/[id]/versions   freeze the live graph as a new past version
 *                                    ("Save current as a version", Section 5)
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { writeAudit } from '@/lib/audit'
import {
  captureGraphSnapshot,
  storeSnapshot,
  ensureCurrentVersion,
} from '@/lib/scanSnapshot'
import { rotateToNextVersion } from '@/lib/scanTimeline'
import { isActivationInProgress } from '@/lib/activationLock'
import { describeScanWriters, describeSecondaryScanWriters } from '@/lib/graphWriters'
import { applyRetentionSafe } from '@/lib/scanRetention'
import { sanitizeVersionLabel } from '@/lib/scanVersionLabel'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  try {
    // A project that predates the Scan Timeline gets its v1 (= the live graph)
    // on first read, so the switch is never empty for an existing project.
    await ensureCurrentVersion(id)

    const rows = await prisma.$queryRaw<Array<{
      id: string
      seq: number
      label: string
      is_current: boolean
      pinned: boolean
      node_count: number | null
      link_count: number | null
      created_at: Date
      snapshot_bytes: number | null
      degraded_sources: number | null
    }>>`
      SELECT sv.id, sv.seq, sv.label, sv.is_current, sv.pinned, sv.node_count,
             sv.link_count, sv.created_at,
             octet_length(sv.snapshot) AS snapshot_bytes,
             (SELECT sj.degraded_sources
                FROM scan_jobs sj
               WHERE sj.version_id = sv.id AND sj.kind = 'full_recon'
               ORDER BY sj.created_at DESC
               LIMIT 1) AS degraded_sources
      FROM scan_versions sv
      WHERE sv.project_id = ${id}
      ORDER BY sv.seq DESC
    `

    return NextResponse.json({
      versions: rows.map(r => ({
        id: r.id,
        seq: r.seq,
        label: r.label,
        isCurrent: r.is_current,
        pinned: r.pinned,
        nodeCount: r.node_count,
        linkCount: r.link_count,
        createdAt: r.created_at,
        snapshotBytes: r.snapshot_bytes ?? 0,
        // Finding sources the run behind this version could not fully re-check
        // (circuit breakers). null = unknown/complete, N>0 = partial.
        degradedSources: r.degraded_sources,
        // A version with no bytes cannot be restored into Neo4j (4A.6). The
        // current version is the live graph, so it is never "activatable".
        activatable: !r.is_current && (r.snapshot_bytes ?? 0) > 0,
      })),
      activating: await isActivationInProgress(id),
    }, { headers: { 'Cache-Control': 'private, no-cache' } })
  } catch (error) {
    console.error('[scanTimeline] version list failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list versions' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  // Freezing reads the whole live graph, so it must not run while anything is
  // rewriting it: an activation swap, or a scan/partial recon mid-write (Risk 1 -
  // a snapshot of a half-built graph is worse than no snapshot).
  if (await isActivationInProgress(id)) {
    return NextResponse.json(
      { error: 'A version activation is in progress for this project. Try again once it finishes.' },
      { status: 409 }
    )
  }
  // Both guards: describeScanWriters covers full/partial recon, and the
  // secondary one covers the scans that also stream findings into the live graph
  // (13.2). Saving a version while a TruffleHog source is mid-write captures a
  // partial subgraph — a bug that predates the multi-source work and worsens
  // with parallel runs.
  const busy = (await describeScanWriters(id)) ?? (await describeSecondaryScanWriters(id))
  if (busy) {
    return NextResponse.json(
      {
        error: `Cannot save a version while ${busy} for this project - the snapshot would capture a ` +
          'half-written graph. Wait for it to finish.',
        busy,
      },
      { status: 409 }
    )
  }

  const body = await request.json().catch(() => ({}))
  const label = sanitizeVersionLabel((body as { label?: unknown })?.label)
  if (label instanceof Error) {
    return NextResponse.json({ error: label.message }, { status: 400 })
  }

  try {
    const captured = await captureGraphSnapshot(id)
    if (captured.nodeCount === 0) {
      return NextResponse.json(
        { error: 'The graph is empty - there is nothing to save as a version.' },
        { status: 400 }
      )
    }

    // "Save current as a version" freezes NOW as a past version and immediately
    // opens the next version for the live graph, so the live graph keeps being
    // the current version (the model's single invariant).
    const current = await ensureCurrentVersion(id)
    await storeSnapshot(current.id, captured)
    if (label) {
      await prisma.scanVersion.update({ where: { id: current.id }, data: { label } })
    }

    // Same collision-tolerant rotation the scan path uses.
    const created = await rotateToNextVersion(id, current.id)

    await applyRetentionSafe(id)

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-version.save-current',
      targetType: 'scanVersion',
      targetId: current.id,
      after: { seq: current.seq, nodeCount: captured.nodeCount, linkCount: captured.linkCount },
    })

    return NextResponse.json({
      savedVersion: { id: current.id, seq: current.seq, nodeCount: captured.nodeCount },
      currentVersion: created,
    })
  } catch (error) {
    console.error('[scanTimeline] save-current failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to save the current graph as a version' },
      { status: 500 }
    )
  }
}
