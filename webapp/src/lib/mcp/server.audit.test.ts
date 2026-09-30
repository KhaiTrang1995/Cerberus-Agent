/**
 * L5: what `submit_finding_review` leaves in the audit log, through the real
 * MCP server.
 *
 * The server writes one `mcp.<tool>` row per call from the tool's arguments,
 * and that row is also printed as a console line. A review's quotes are
 * target text (a response body, a credential-shaped string) and its why and
 * fix lever are an agent's words, so none of them may reach either. The
 * guard is `UNAUDITED_ARGS` plus the refusal's own audit details; this drives
 * a real SDK client against `buildMcpServer` and reads every row written.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ audit: vi.fn(), submitReview: vi.fn() }))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ id: 'p1', userId: 'owner' }) },
    mcpAccessToken: { update: () => Promise.resolve() },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/triage/actions', async (orig) => ({
  ...(await orig<typeof import('@/lib/triage/actions')>()),
  submitReview: (...a: unknown[]) => h.submitReview(...a),
}))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { TriageActionError } from '@/lib/triage/actions'
import { buildMcpServer } from './server'
import type { McpContext } from './tools'

const ctx: McpContext = {
  token: { tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
           name: 'audit', scopes: ['triage:review'] as never },
}

const REVIEW = {
  projectId: 'p1', findingId: 'v1', evidenceHash: 'a'.repeat(40), verdict: 'doubtful',
  evidenceQuote: 'QUOTE-MARKER from the response body',
  disputedFacts: [{ fact: 'reachable', quote: 'DISPUTE-MARKER in the body' }],
  impactMultiplier: 0.8, impactQuote: 'IMPACT-MARKER in the body',
  why: 'WHY-MARKER an agent wrote', fixLever: 'LEVER-MARKER an agent wrote',
}
const MARKERS = /QUOTE-MARKER|DISPUTE-MARKER|IMPACT-MARKER|WHY-MARKER|LEVER-MARKER/

async function callReview() {
  const server = buildMcpServer(ctx)
  const client = new Client({ name: 'audit-test', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const result = await client.callTool({ name: 'submit_finding_review', arguments: REVIEW })
  await new Promise((resolve) => setTimeout(resolve, 0))
  return result
}

function auditRows(): Array<Record<string, unknown>> {
  return h.audit.mock.calls.map((call) => call[0] as Record<string, unknown>)
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.submitReview.mockResolvedValue({
    label: 'Vulnerability', rescored: true, before: { score: 62.5 }, after: { score: 30 },
    accepted: { verdict: 'doubtful', impact_multiplier: 0.8, disputed_facts: ['reachable'] },
    dropped: [], reviewSurvivesRescan: true,
  })
})

describe('mcp.submit_finding_review audit rows', () => {
  test('an accepted review leaves no quote, why or fix lever in the row', async () => {
    const result = await callReview()
    expect(result.isError).toBeFalsy()
    const row = auditRows().find((r) => r.action === 'mcp.submit_finding_review')
    expect(row).toBeDefined()
    expect(row!.after).toMatchObject({ outcome: 'ok', tokenPrefix: 'rdmn_mcp_aaaaaaaa' })
    expect(JSON.stringify(auditRows())).not.toMatch(MARKERS)
  })

  test('a refused review leaves none of it either', async () => {
    h.submitReview.mockRejectedValue(new TriageActionError(
      'The evidence changed since it was read.', 'evidence_changed', 409, { labels: ['Vulnerability'] }))
    const result = await callReview()
    expect(result.isError).toBe(true)
    const row = auditRows().find((r) => r.action === 'mcp.submit_finding_review')
    expect(row!.after).toMatchObject({ outcome: 'evidence_changed' })
    expect(JSON.stringify(auditRows())).not.toMatch(MARKERS)
  })
})
