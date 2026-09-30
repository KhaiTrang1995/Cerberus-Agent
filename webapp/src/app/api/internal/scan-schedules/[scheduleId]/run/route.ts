/**
 * Scan Timeline - execute a due schedule (Section 7.2). Internal-key only.
 *
 * Runs the scan through the SAME path a manual scan uses (lib/startFullScan.ts),
 * so a scheduled run inherits, unchanged:
 *   - the project activation lock (F3),
 *   - the freeze-before-start of the outgoing graph (Section 3.2 option 1),
 *   - the orchestrator's RoE time-window / excluded-host / hard-guardrail checks
 *     and the admission ledger (Section 7.3 "ROE at execution"),
 *   - the ScanJob history row, tagged trigger='scheduled'.
 *
 * `nextRunAt` is advanced whatever the outcome, so a scan that cannot start does
 * not pin the schedule to a due state and hot-loop the worker.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { startFullScan } from '@/lib/startFullScan'
import { computeNextRun } from '@/lib/scanSchedule'
import { parseScanMode, createScanJob } from '@/lib/scanTimeline'
import { classifyStartFailure } from '@/lib/scanStartOutcome'
import { enqueueJob } from '@/lib/enqueueJob'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ scheduleId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { scheduleId } = await params

  try {
    const schedule = await prisma.scanSchedule.findUnique({ where: { id: scheduleId } })
    if (!schedule) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    if (!schedule.enabled) {
      return NextResponse.json({ ok: false, skipped: 'disabled' }, { status: 409 })
    }

    const mode = parseScanMode(schedule.scanMode) ?? 'new'
    const now = new Date()

    const result = await startFullScan({
      projectId: schedule.projectId,
      mode,
      trigger: 'scheduled',
      actorUserId: schedule.userId,
      scheduleId: schedule.id,
    })

    // A one-off schedule is spent after it fires; recurring ones roll forward.
    // `enabled` is never written back for a recurring one: the value read above
    // predates the start, and a pause made meanwhile (a rescope that widened the
    // batch, or a person) must survive it.
    const nextRunAt = computeNextRun(schedule, now)
    await prisma.scanSchedule.update({
      where: { id: scheduleId },
      data: {
        lastRunAt: now,
        nextRunAt,
        ...(schedule.mode === 'once' ? { enabled: false } : {}),
      },
    })

    if (!result.ok) {
      const cls = classifyStartFailure(result.status, {
        error: result.error,
        limit: result.limit as { limitType?: string } | undefined,
        activationInProgress: result.activationInProgress,
        busy: result.busy,
      })

      // Phase 4: a TEMPORARY refusal (RAM/hard limit, activation, or the graph is
      // busy) must NOT burn the occurrence. Advancing nextRunAt above is correct
      // precisely because the occurrence becomes a durable queue row here, which
      // the dispatcher runs when resources free up. This replaces the old
      // defer-and-retry-every-tick path.
      if (cls.temporary) {
        const enq = await enqueueJob({
          projectId: schedule.projectId,
          userId: schedule.userId,
          kind: 'full_recon',
          payload: { mode },
          priority: 0, // scheduled
          scheduleId: schedule.id,
        }).catch(err => {
          console.error('[scanScheduler] could not enqueue deferred scheduled run:', err)
          return { ok: false, status: 500, error: String(err), id: undefined as string | undefined }
        })
        console.info(
          `[scanScheduler] schedule ${scheduleId} refused (${cls.blockedCode || 'temporary'}); ` +
          `enqueued as ${enq.id ?? 'none'}`
        )
        return NextResponse.json(
          { ok: false, queued: enq.ok, jobId: enq.id ?? null, blockedCode: cls.blockedCode, error: result.error, nextRunAt },
          { status: 200 },
        )
      }

      // PERMANENT: nothing to queue. Record a failed ScanJob so the run history
      // shows why (an admission-limit rejection already recorded its own).
      console.warn(`[scanScheduler] schedule ${scheduleId} could not start: ${result.error}`)
      let scanJobId = result.scanJobId ?? null
      if (!scanJobId) {
        const job = await createScanJob({
          projectId: schedule.projectId,
          trigger: 'scheduled',
          mode: parseScanMode(schedule.scanMode),
          status: 'failed',
          initiatedByUserId: schedule.userId,
          scheduleId: schedule.id,
          ramReason: result.error,
        }).catch(err => {
          console.error('[scanScheduler] could not record skipped scheduled run:', err)
          return null
        })
        scanJobId = job?.id ?? null
      }
      return NextResponse.json(
        {
          ok: false,
          error: result.error,
          ...(result.snapshotFailed ? { snapshotFailed: true } : {}),
          scanJobId,
          nextRunAt,
        },
        { status: 200 },
      )
    }

    console.info(
      `[scanScheduler] started scheduled scan for project ${schedule.projectId} ` +
      `(schedule ${scheduleId}, mode ${mode}, version ${result.versionSeq})`
    )
    return NextResponse.json({
      ok: true,
      projectId: schedule.projectId,
      scanJobId: result.scanJobId,
      versionId: result.versionId,
      frozenVersionId: result.frozenVersionId,
      nextRunAt,
    })
  } catch (error) {
    console.error('[scanScheduler] run failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to run the schedule' },
      { status: 500 }
    )
  }
}
