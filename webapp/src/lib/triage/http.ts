/**
 * The UI door's half of `lib/triage/actions.ts`: argument parsing and turning a
 * `TriageActionError` into the HTTP answer the Priority Board reads.
 */
import { NextResponse } from 'next/server'
import {
  DECIDED_BY, FINDING_ID_RE, FINDING_LABELS, REVIEW_CURRENT, REVIEWED_VIA,
  TriageActionError, type BoardFilters,
} from '@/lib/triage/actions'

export function actionErrorResponse(err: unknown): NextResponse {
  if (err instanceof TriageActionError) {
    return NextResponse.json({ error: err.message, code: err.code, ...err.details },
                             { status: err.status })
  }
  console.error('[triage] unexpected error:', err)
  return NextResponse.json({ error: 'The triage request failed.' }, { status: 500 })
}

/** A finding id and optional label, validated; or the 400 to send. */
export function parseFindingRef(
  findingId: unknown, label: unknown,
): { findingId: string; label?: string } | NextResponse {
  if (typeof findingId !== 'string' || !FINDING_ID_RE.test(findingId)) {
    return NextResponse.json({ error: 'findingId is required' }, { status: 400 })
  }
  if (label !== undefined && label !== null && label !== '') {
    if (typeof label !== 'string' || !(FINDING_LABELS as readonly string[]).includes(label)) {
      return NextResponse.json(
        { error: `label must be one of ${FINDING_LABELS.join(', ')}` }, { status: 400 })
    }
    return { findingId, label }
  }
  return { findingId }
}

/** The board's filters from a query string; an unknown value is a 400, never ignored. */
export function parseBoardFilters(params: URLSearchParams): BoardFilters | NextResponse {
  const out: BoardFilters = {}
  const checks: Array<[keyof BoardFilters, string, readonly string[]]> = [
    ['decidedBy', 'decidedBy', DECIDED_BY],
    ['reviewedVia', 'reviewedVia', REVIEWED_VIA],
    ['reviewCurrent', 'reviewCurrent', REVIEW_CURRENT],
  ]
  for (const [key, param, allowed] of checks) {
    const value = params.get(param)
    if (value === null || value === '') continue
    if (!allowed.includes(value)) {
      return NextResponse.json(
        { error: `${param} must be one of ${allowed.join(', ')}` }, { status: 400 })
    }
    ;(out as Record<string, string>)[key] = value
  }
  return out
}
