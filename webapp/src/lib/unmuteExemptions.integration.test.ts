/** @vitest-environment node */
/**
 * L4, real Postgres: an unmute that is rolled back removes only the
 * exemptions IT created.
 *
 * MCP `unmute_findings` writes its exemptions before the graph write and
 * removes them when the unmute does not happen. What makes that safe is that
 * `ensureExemptions` reports exactly the rows its INSERT created, which rests on
 * `createManyAndReturn({ skipDuplicates: true })` returning no row for a
 * conflict. The unit tests mock Prisma, so they take that on faith: were a
 * pre-existing row returned too, a failed agent unmute would delete an
 * exemption a person made, and the next Mute Rules sweep would hide that
 * finding again.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network redamon-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://redamon:<pw>@postgres:5432/redamon' \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/unmuteExemptions.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { ensureExemptions, removeExemptions } from './unmuteExemptions'

const HAS_DB = process.env.DATABASE_URL !== undefined

let prisma: PrismaClient
let userId = ''
let projectId = ''

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const user = await prisma.user.create({
    data: { email: `unmute-exemptions-int-${Date.now()}@example.invalid`, name: 'unmute int', password: 'x' },
  })
  userId = user.id
  const project = await prisma.project.create({
    data: { name: 'unmute exemptions integration', userId, targetDomain: 'example.invalid' },
  })
  projectId = project.id
}, 60_000)

afterAll(async () => {
  if (!HAS_DB || !prisma) return
  try { await prisma.project.delete({ where: { id: projectId } }) } catch { /* cascade */ }
  try { await prisma.user.delete({ where: { id: userId } }) } catch { /* ignore */ }
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('a rolled-back unmute removes only its own exemptions', () => {
  test('after ensure then remove, the pre-existing exemption row still exists', async () => {
    const personsRow = await prisma.nodeFilterExemption.create({
      data: { projectId, label: 'Vulnerability', nodeKey: 'v-person', createdBy: userId },
    })

    const ensured = await ensureExemptions(
      projectId,
      [{ label: 'Vulnerability', key: 'v-person' }, { label: 'Secret', key: 's-agent' }],
      { createdBy: userId, realActorUserId: null },
    )
    expect(ensured.created).toEqual([{ label: 'Secret', key: 's-agent' }])
    expect(ensured.total).toBe(2)

    expect(await removeExemptions(projectId, ensured.created)).toBe(true)

    const left = await prisma.nodeFilterExemption.findMany({
      where: { projectId },
      select: { id: true, label: true, nodeKey: true, createdAt: true },
    })
    expect(left).toEqual([{
      id: personsRow.id, label: 'Vulnerability', nodeKey: 'v-person', createdAt: personsRow.createdAt,
    }])
  })
})
