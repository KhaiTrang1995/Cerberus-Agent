/**
 * Scan Timeline - the project activation lock (Section 4A.3).
 *
 * Activating a version DELETES the live recon graph and rebuilds it from stored
 * bytes. Anything else that reads or writes that graph while the swap is in
 * flight sees a half-built world, so activation must be mutually exclusive with:
 *   - a full scan (start is rejected while activating; activation is rejected
 *     while a scan runs)
 *   - a partial recon run
 *   - an agent session (swapping the graph mid-reasoning changes the agent's
 *     world; we block rather than corrupt the session)
 *   - the scheduler worker (F3 - it defers instead of spawning into a swap)
 *
 * The lock is a single project-scoped row flag (`Project.activationState`), taken
 * with a conditional UPDATE so two concurrent activations cannot both win. It is
 * released in a `finally`, and a stale lock (process died mid-activation) expires
 * after ACTIVATION_LOCK_TTL_MS so a project can never be wedged forever.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export const ACTIVATION_STATE_IDLE = 'idle'
export const ACTIVATION_STATE_ACTIVATING = 'activating'

export function activationLockTtlMs(): number {
  const raw = parseInt(process.env.ACTIVATION_LOCK_TTL_MS || '', 10)
  return Number.isFinite(raw) && raw > 0 ? raw : 15 * 60 * 1000
}

function isStale(startedAt: Date | null | undefined, now: number): boolean {
  if (!startedAt) return true
  return now - new Date(startedAt).getTime() > activationLockTtlMs()
}

/** True when a (non-stale) activation currently holds the project's graph. */
export async function isActivationInProgress(projectId: string): Promise<boolean> {
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select: { activationState: true, activationStartedAt: true },
  })
  if (!row || row.activationState !== ACTIVATION_STATE_ACTIVATING) return false
  return !isStale(row.activationStartedAt, Date.now())
}

/**
 * Batched form for callers that hold a LIST of projects (the scheduler's due
 * feed). One query for N projects: asking per project turned a 25-schedule tick
 * into 25 sequential round-trips.
 */
export async function activationStates(projectIds: string[]): Promise<Map<string, boolean>> {
  const states = new Map<string, boolean>(projectIds.map(id => [id, false]))
  if (projectIds.length === 0) return states
  const rows = await prisma.project.findMany({
    where: { id: { in: projectIds } },
    select: { id: true, activationState: true, activationStartedAt: true },
  })
  const now = Date.now()
  for (const row of rows) {
    states.set(
      row.id,
      row.activationState === ACTIVATION_STATE_ACTIVATING && !isStale(row.activationStartedAt, now)
    )
  }
  return states
}

/**
 * Guard for every path that touches the live graph while an activation may be
 * running (scan start, partial-recon start, agent-session start, scheduler).
 * Returns a 409 response to return, or null when the graph is free.
 *
 * Best-effort by design: if the check itself fails (DB hiccup) we allow the
 * operation rather than hard-blocking normal work on a lock read.
 */
export async function assertGraphNotActivating(projectId: string): Promise<NextResponse | null> {
  try {
    if (!(await isActivationInProgress(projectId))) return null
  } catch (err) {
    console.error('[activationLock] state check failed (allowing):', err)
    return null
  }
  return NextResponse.json(
    {
      error: 'A version activation is in progress for this project - the graph is being swapped. Try again once it finishes.',
      activationInProgress: true,
    },
    { status: 409 }
  )
}

/**
 * The FAIL-CLOSED form, for writes that an activation would silently lose.
 *
 * `assertGraphNotActivating` allows the operation when the lock cannot be read,
 * which is right for starting work. A mute or unmute is different: activation
 * freezes, clears and restores the graph, so one landing in between returns
 * success and is then gone. When the lock cannot be read, that is "busy".
 */
export async function activationBusy(projectId: string): Promise<boolean> {
  try {
    return await isActivationInProgress(projectId)
  } catch (err) {
    console.error('[activationLock] state check failed (treating as busy):', err)
    return true
  }
}

/** The 409 a mute or unmute route returns while an activation holds the graph. */
export function activationBusyResponse(): NextResponse {
  return NextResponse.json(
    {
      error: 'A version activation is in progress for this project (or its state could not be ' +
        'read), and a mute or unmute written now could be lost. Try again once it finishes.',
      activationInProgress: true,
    },
    { status: 409 }
  )
}

export interface LockHandle {
  acquired: boolean
  /** Set when the lock could not be taken. */
  reason?: string
}

/**
 * Take the lock, or report why not. Atomic: the conditional `updateMany` only
 * matches a project that is idle (or whose lock has expired), so exactly one
 * concurrent caller can win.
 */
export async function acquireActivationLock(
  projectId: string,
  versionId: string
): Promise<LockHandle> {
  const now = new Date()
  const staleBefore = new Date(now.getTime() - activationLockTtlMs())

  const res = await prisma.project.updateMany({
    where: {
      id: projectId,
      OR: [
        { activationState: ACTIVATION_STATE_IDLE },
        { activationStartedAt: null },
        { activationStartedAt: { lt: staleBefore } },
      ],
    },
    data: {
      activationState: ACTIVATION_STATE_ACTIVATING,
      activationStartedAt: now,
      activationVersionId: versionId,
    },
  })

  if (res.count === 0) {
    return { acquired: false, reason: 'Another activation is already in progress for this project.' }
  }
  return { acquired: true }
}

/** Always call from a `finally` - a leaked lock blocks scans and the agent. */
export async function releaseActivationLock(projectId: string): Promise<void> {
  try {
    await prisma.project.update({
      where: { id: projectId },
      data: {
        activationState: ACTIVATION_STATE_IDLE,
        activationStartedAt: null,
        activationVersionId: null,
      },
    })
  } catch (err) {
    // The TTL is the backstop: a lock we failed to release expires on its own.
    console.error('[activationLock] release failed (will expire via TTL):', err)
  }
}
