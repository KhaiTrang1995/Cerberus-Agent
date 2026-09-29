/** @vitest-environment node */
/**
 * L4, real Neo4j: the report counts a person's, an agent's and a rule's mutes
 * apart.
 *
 * An agent's (MCP) mute carries its token owner's user id in `muted_by`, the
 * same as that person's own mute. Only `muted_channel` tells them apart, and
 * the split is Cypher the unit tests never run (they mock the session). Were
 * the channel check wrong, the report would present an unattended agent's
 * suppressions as findings a person reviewed.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/report/reportData.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import { queryGraphOverview } from './reportData'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `REPORT_MUTES_${Math.random().toString(36).slice(2, 10)}`
const UID = `report-mutes-${Math.random().toString(36).slice(2, 10)}`

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
})

afterAll(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('the suppressed-findings line', () => {
  test('a person\'s, an agent\'s and a rule\'s mute are counted 1/1/1 in separate fields', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `UNWIND $rows AS row
       CREATE (n:Vulnerability:Muted {id: row.id, user_id: $uid, project_id: $pid, severity: 'info',
                                      muted: true, muted_at: datetime(), muted_by: row.by,
                                      muted_reason: row.reason})
       SET n.muted_channel = row.channel, n.muted_token = row.token`,
      {
        uid: UID, pid: PID,
        rows: [
          { id: 'v-person', by: UID, reason: 'noise', channel: null, token: null },
          { id: 'v-agent', by: UID, reason: 'dev-only banner', channel: 'mcp', token: 'rdmn_mcp_ab12cd34' },
          { id: 'v-rule', by: 'rule:vuln.nuclei/k3f9a2', reason: 'Filter rule: Informational templates',
            channel: null, token: null },
        ],
      },
    )

    const overview = await queryGraphOverview(session, PID)

    expect({
      people: overview.suppressedByPeople,
      agents: overview.suppressedByAgents,
      rules: overview.suppressedByRules,
      total: overview.suppressedCount,
    }).toEqual({ people: 1, agents: 1, rules: 1, total: 3 })
    expect(overview.suppressedRules).toEqual([{ name: 'Informational templates', count: 1 }])
  })
})
