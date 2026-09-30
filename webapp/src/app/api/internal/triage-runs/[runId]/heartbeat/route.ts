/**
 * POST /api/internal/triage-runs/[runId]/heartbeat — "still here", and "should I stop?".
 *
 * The agent calls this every 30 seconds with `{phase, progress}`. The reply
 * carries `abort`, which is how the run learns that something outside it
 * changed: the project was deleted or a version activation started. The agent
 * treats two consecutive failures as an abort, so a webapp it cannot reach
 * stops the run rather than letting it publish blind.
 *
 * A run that is PUBLISHING is alive too (B12, B16). A publish can outlast the
 * ten-minute heartbeat window on a big project; refusing its heartbeat used to
 * let the run be marked lost mid-write, free the graph for an activation, and
 * have `finish` overwrite the verdict afterwards.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { isActivationInProgress } from '@/lib/activationLock'
import { LIVE_TRIAGE_STATUSES } from '@/lib/triageRun'

interface RouteParams {
  params: Promise<{ runId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const { runId } = await params
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>
  const phase = typeof body.phase === 'string' ? body.phase.slice(0, 40) : undefined
  const progress =
    typeof body.progress === 'number' && Number.isFinite(body.progress)
      ? Math.max(0, Math.min(100, Math.round(body.progress)))
      : undefined

  const run = await prisma.triageRun.findUnique({
    where: { id: runId },
    select: { id: true, projectId: true, status: true },
  })

  // A missing run means the project was deleted (the relation cascades), which
  // is exactly the case the agent must stop for.
  if (!run) {
    return NextResponse.json(
      { status: 'gone', abort: true, reason: 'the run no longer exists' },
      { status: 404 }
    )
  }

  // Finished (or marked lost) already: there is nothing left for it to do.
  if (!(LIVE_TRIAGE_STATUSES as readonly string[]).includes(run.status)) {
    return NextResponse.json({
      status: run.status,
      abort: true,
      reason: `the run is ${run.status}`,
    })
  }

  if (await isActivationInProgress(run.projectId)) {
    return NextResponse.json({
      status: run.status,
      abort: true,
      reason: 'a version activation started',
    })
  }

  // Conditional, so a heartbeat racing `finish` cannot resurrect a row.
  await prisma.triageRun.updateMany({
    where: { id: runId, status: { in: [...LIVE_TRIAGE_STATUSES] } },
    data: {
      heartbeatAt: new Date(),
      ...(phase !== undefined ? { phase } : {}),
      ...(progress !== undefined ? { progress } : {}),
    },
  })

  return NextResponse.json({ status: run.status, abort: false })
}
