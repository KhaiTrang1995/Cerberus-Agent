/**
 * Recon coverage carried by the graph (scanCoverage.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const run = vi.fn()
const close = vi.fn()
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run, close }),
}))

import { parseCoverageGaps, readDegradedSourceCount } from './scanCoverage'

const records = (gapsPerDomain: unknown[]) => ({
  records: gapsPerDomain.map(g => ({ get: (_k: string) => g })),
})

describe('parseCoverageGaps', () => {
  test('parses a JSON string array of source objects', () => {
    expect(parseCoverageGaps('[{"source":"shodan"},{"source":"otx"}]'))
      .toEqual([{ source: 'shodan' }, { source: 'otx' }])
  })
  test('accepts an already-parsed array', () => {
    expect(parseCoverageGaps([{ source: 'a' }])).toEqual([{ source: 'a' }])
  })
  test('rejects malformed JSON', () => {
    expect(parseCoverageGaps('{not json')).toBeNull()
  })
  test('rejects a non-array', () => {
    expect(parseCoverageGaps('{"source":"x"}')).toBeNull()
  })
  test('rejects an entry without a string source', () => {
    expect(parseCoverageGaps([{ nope: 1 }])).toBeNull()
  })
  test('rejects a source over 64 chars', () => {
    expect(parseCoverageGaps([{ source: 'x'.repeat(65) }])).toBeNull()
  })
})

describe('readDegradedSourceCount', () => {
  beforeEach(() => {
    run.mockReset()
    close.mockReset()
  })

  test('returns null when no Domain carries a coverage record', async () => {
    run.mockResolvedValue({ records: [] })
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('counts distinct sources across every covered Domain', async () => {
    run.mockResolvedValue(records([
      '[{"source":"shodan"},{"source":"nuclei"}]',
      '[{"source":"shodan"},{"source":"otx"}]',
    ]))
    expect(await readDegradedSourceCount('p1')).toBe(3) // shodan, nuclei, otx
  })

  test('returns 0 for a clean recorded run (empty gaps)', async () => {
    run.mockResolvedValue(records(['[]']))
    expect(await readDegradedSourceCount('p1')).toBe(0)
  })

  test('fails closed to null on an unparseable record', async () => {
    run.mockResolvedValue(records(['[{"source":"ok"}]', '{bad']))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('returns null and never throws on a query error', async () => {
    run.mockRejectedValue(new Error('neo4j down'))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('always closes the session', async () => {
    run.mockResolvedValue({ records: [] })
    await readDegradedSourceCount('p1')
    expect(close).toHaveBeenCalledOnce()
  })
})
