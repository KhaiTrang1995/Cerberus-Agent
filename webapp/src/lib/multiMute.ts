/**
 * Multi mute: the shared constants and helpers of its webapp routes.
 *
 * A Multi mute is a person's mute, confirmed in the modal but chosen in bulk
 * from AI suggestions. The agent stores each suggestion as a batch and its
 * write accepts only that batch's keys; this side checks ownership, the
 * activation lock and the input shape before anything reaches it.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

/** A batch id as the agent issues it (`multi_mute/batches.py`). */
export const MULTI_BATCH_PATTERN = /^mm-[0-9a-f]{8}$/

/** One write's ceiling; the modal chunks a larger selection under one batch id. */
export const MULTI_MUTE_MAX_KEYS = 500

/** What a write says it muted: the five groupings, the footer's whole selection, the seed alone. */
export const MULTI_MUTE_CONCEPTS = [
  'same_problem', 'same_detector', 'same_host', 'same_fp_pattern', 'same_low_risk',
  'selected', 'seed',
] as const
export type MultiMuteConcept = (typeof MULTI_MUTE_CONCEPTS)[number]

export function isMultiMuteConcept(x: unknown): x is MultiMuteConcept {
  return typeof x === 'string' && (MULTI_MUTE_CONCEPTS as readonly string[]).includes(x)
}

/** CypherFix work items still open; a mute can empty one at the next triage run. */
export const OPEN_REMEDIATION_STATUSES = ['pending', 'in_progress', 'code_review', 'pr_created']

/**
 * The project's Mute Rules exemptions as `[label, key]` pairs: findings a person
 * brought back, which Multi mute never proposes and never writes. Throws on a
 * database error, and the caller refuses: an empty list would re-hide them.
 */
export async function exemptPairs(projectId: string): Promise<[string, string][]> {
  const rows = await prisma.nodeFilterExemption.findMany({
    where: { projectId },
    select: { label: true, nodeKey: true },
  })
  return rows.map(r => [r.label, r.nodeKey])
}

/** 409 while a version activation holds the graph, with the modal's code. */
export function activationBusyCoded(): NextResponse {
  return NextResponse.json(
    {
      error: 'A version is being activated; try again when it finishes.',
      code: 'activation_busy',
      activationInProgress: true,
    },
    { status: 409 },
  )
}
