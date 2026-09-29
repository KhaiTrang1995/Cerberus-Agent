/**
 * The webapp's copy of the triage property list must match the graph mixin's.
 *
 * Run: npx vitest run src/lib/triage/properties.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'fs'
import path from 'path'
import { TRIAGE_PROPERTIES, TRIAGE_TEXT_PROPERTIES } from './properties'

const MIXIN = path.resolve(__dirname, '../../../../graph_db/mixins/recon/triage_mixin.py')

describe('TRIAGE_PROPERTIES', () => {
  test.skipIf(!existsSync(MIXIN))('mirrors TRIAGE_PROPS in the graph mixin', () => {
    const src = readFileSync(MIXIN, 'utf8')
    const block = src.slice(src.indexOf('TRIAGE_PROPS = ('), src.indexOf('\n)\n', src.indexOf('TRIAGE_PROPS = (')))
    const python = [...block.matchAll(/^\s+"(triage_[a-z_]+|triaged_at)",/gm)].map((m) => m[1])
    expect(python.length).toBeGreaterThan(30)
    expect([...TRIAGE_PROPERTIES].sort()).toEqual([...python].sort())
  })

  test('the text properties are all triage properties', () => {
    for (const prop of TRIAGE_TEXT_PROPERTIES) {
      expect(TRIAGE_PROPERTIES as readonly string[]).toContain(prop)
    }
  })
})
