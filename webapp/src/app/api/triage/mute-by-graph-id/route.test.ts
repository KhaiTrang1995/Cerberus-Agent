/**
 * `/api/triage/mute-by-graph-id`: the graph tables' way into the same mute the
 * Priority Board issues. It adds a graph READ before the write, so on top of
 * the mute route's BOLA rules it must scope that read to the caller's tenant,
 * refuse asset nodes, and send the finding's stored key, never the graph id.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireEff = vi.fn()
const mockFindUnique = vi.fn()
const mockAgentFetch = vi.fn()
const mockRun = vi.fn()
const mockClose = vi.fn()

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
}))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (b: Record<string, string> = {}) => ({ ...b, 'x-internal-key': 'k' }),
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: mockRun, close: mockClose }),
}))

import { POST } from './route'

const OWNER = 'alice'
const PROJECT = 'p1'

function req(body: unknown) {
  return new NextRequest('http://x/api/triage/mute-by-graph-id', {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
  })
}

function node(labels: string[], id: unknown, findingId: unknown = null) {
  const fields: Record<string, unknown> = { labels, id, findingId }
  return { records: [{ get: (k: string) => fields[k] }] }
}

function sentToAgent() {
  return JSON.parse((mockAgentFetch.mock.calls[0][1] as RequestInit).body as string)
}

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEff.mockResolvedValue({ userId: OWNER })
  mockFindUnique.mockResolvedValue({ id: PROJECT, userId: OWNER })
  mockAgentFetch.mockResolvedValue(
    new Response(JSON.stringify({ muted: true, label: 'Vulnerability' }), { status: 200 }))
  mockRun.mockResolvedValue(node(['Vulnerability'], 'vuln-abc'))
})

describe('authorisation', () => {
  test('someone else\'s project is 404 and neither the graph nor the agent is touched', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'mallory' })
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(404)
    expect(mockRun).not.toHaveBeenCalled()
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('no session is 401', async () => {
    mockRequireEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(401)
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('the lookup is scoped to the tenant from the PROJECT, not the body', async () => {
    await POST(req({ projectId: PROJECT, graphId: '12', userId: 'x', user_id: 'x' }))
    const [cypher, params] = mockRun.mock.calls[0]
    expect(cypher).toContain('n.user_id = $userId')
    expect(cypher).toContain('n.project_id = $projectId')
    expect(params).toEqual({ graphId: '12', userId: OWNER, projectId: PROJECT })
    expect(sentToAgent().user_id).toBe(OWNER)
    expect(sentToAgent().project_id).toBe(PROJECT)
  })
})

describe('input', () => {
  test.each([undefined, 12, '', 'abc', '1 OR 1=1', '-1', '1'.repeat(19)])(
    'graphId %j is rejected before the graph is read', async graphId => {
      const res = await POST(req({ projectId: PROJECT, graphId }))
      expect(res.status).toBe(400)
      expect(mockRun).not.toHaveBeenCalled()
    })
})

describe('resolution', () => {
  test('a finding is muted by its stored id, never the graph id', async () => {
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(200)
    const sent = sentToAgent()
    expect(sent.op).toBe('mute')
    expect(sent.node_id).toBe('vuln-abc')
    expect(sent.muted_by).toBe(OWNER)
    expect(mockClose).toHaveBeenCalledOnce()
  })

  test('MalPackageFinding is muted by its finding_id', async () => {
    mockRun.mockResolvedValue(node(['MalPackageFinding'], null, 'mf-9'))
    await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(sentToAgent().node_id).toBe('mf-9')
  })

  test('an asset node is refused with a reason, and nothing is written', async () => {
    mockRun.mockResolvedValue(node(['Subdomain'], 'sub-1'))
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(422)
    expect((await res.json()).error).toMatch(/^Subdomain nodes cannot be muted/)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a node that is gone is 409, the "changed while open" status', async () => {
    mockRun.mockResolvedValue({ records: [] })
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(409)
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockClose).toHaveBeenCalledOnce()
  })

  test('a finding with no stored key is refused rather than muted by nothing', async () => {
    mockRun.mockResolvedValue(node(['Vulnerability'], null))
    const res = await POST(req({ projectId: PROJECT, graphId: '12' }))
    expect(res.status).toBe(422)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})
