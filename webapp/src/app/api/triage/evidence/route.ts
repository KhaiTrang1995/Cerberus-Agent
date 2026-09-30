import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner } from '@/lib/triageClient'
import { readEvidence } from '@/lib/triage/actions'
import { actionErrorResponse, parseFindingRef } from '@/lib/triage/http'

/**
 * GET /api/triage/evidence?projectId=&findingId=&label= - the evidence a
 * reviewer reads for one finding: normalised, secret shapes redacted, capped.
 * The same bundle MCP `get_finding_evidence` returns and the built-in review
 * is shown. It is scanner output, so the panel renders it as untrusted text.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const caller = await requireProjectOwner(params.get('projectId'))
  if (caller instanceof NextResponse) return caller
  const ref = parseFindingRef(params.get('findingId'), params.get('label'))
  if (ref instanceof NextResponse) return ref
  try {
    return NextResponse.json(await readEvidence(caller, ref.findingId, ref.label, 'app'))
  } catch (err) {
    return actionErrorResponse(err)
  }
}
