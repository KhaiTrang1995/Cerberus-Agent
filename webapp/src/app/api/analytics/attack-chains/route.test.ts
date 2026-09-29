/**
 * The Insights "Chain Findings" rows carry the ChainFinding's graph Node ID.
 *
 * Run: npx vitest run src/app/api/analytics/attack-chains/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: string[] = []
let topRows: Array<Record<string, unknown>> = []

/** Only the top-findings query (the one following FOUND_ON) returns rows. */
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      runCalls.push(cypher)
      const rows = cypher.includes('[:FOUND_ON]') ? topRows : []
      return { records: rows.map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const route = await import('./route')

const request = (projectId: string): any => ({
  nextUrl: new URL(`http://localhost/api/analytics/attack-chains?projectId=${projectId}`),
})

beforeEach(() => {
  runCalls.length = 0
  topRows = []
})

describe('Chain Findings Node ID', () => {
  test('the query projects the row node\'s internal id as a string', async () => {
    await route.GET(request('p1'))
    const top = runCalls.find(c => c.includes('[:FOUND_ON]'))!
    expect(top).toContain('toString(id(f)) AS nodeId')
    // Still one row per finding-and-target, capped and severity-ordered.
    expect(top).toContain('LIMIT 20')
  })

  test('each row maps it, and a missing one is null rather than absent', async () => {
    topRows = [
      { nodeId: '4711', title: 'SQLi', severity: 'high', findingType: 'sqli' },
      { title: 'Old row', severity: 'low', findingType: 'info' },
    ]
    const body = await (await route.GET(request('p1'))).json()
    expect(body.topFindings.map((f: { nodeId: unknown }) => f.nodeId)).toEqual(['4711', null])
  })
})
