import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner } from '@/lib/triageClient'
import { readFinding } from '@/lib/triage/actions'
import { actionErrorResponse, parseFindingRef } from '@/lib/triage/http'

/**
 * GET /api/triage/finding?projectId=&findingId=&label= - everything behind one
 * finding's place on the Priority Board: the result, the rules, the review, the
 * decision, the detector and the group. The detail panel's source.
 *
 * A muted finding, a wrong id and another project's id all answer 404.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const caller = await requireProjectOwner(params.get('projectId'))
  if (caller instanceof NextResponse) return caller
  const ref = parseFindingRef(params.get('findingId'), params.get('label'))
  if (ref instanceof NextResponse) return ref
  try {
    return NextResponse.json(await readFinding(caller, ref.findingId, ref.label, 'app'))
  } catch (err) {
    return actionErrorResponse(err)
  }
}
