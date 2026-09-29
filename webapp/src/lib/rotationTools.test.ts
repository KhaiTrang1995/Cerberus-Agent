/**
 * ROTATION_TOOLS is the one list of Key Rotation tools. Three consumers used to
 * keep their own copies and disagreed: the settings PUT lacked wpscan,
 * securitytrails and viewdns, so extra keys typed for them vanished on save.
 * These tests pin that every consumer reads the shared list.
 *
 * Run: npx vitest run src/lib/rotationTools.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  ROTATION_TOOLS,
  ROTATION_TOOL_NAMES,
  ROTATION_TOOL_BY_FIELD,
  isRotationTool,
} from './rotationTools'
import { buildTemplate, validateAndParse, isValidationError } from './apiKeysTemplate'

const PAGE = join(process.cwd(), 'src/app/settings/page.tsx')
const SETTINGS_ROUTE = join(process.cwd(), 'src/app/api/users/[id]/settings/route.ts')

describe('ROTATION_TOOLS', () => {
  test('carries the three tools the PUT used to drop', () => {
    for (const tool of ['wpscan', 'securitytrails', 'viewdns']) {
      expect(ROTATION_TOOL_NAMES).toContain(tool)
    }
  })

  test('censys stays out: no scan builds a Censys rotator and the page never offered one', () => {
    expect(isRotationTool('censys')).toBe(false)
  })

  test('tool names and fields are unique', () => {
    expect(new Set(ROTATION_TOOL_NAMES).size).toBe(ROTATION_TOOLS.length)
    expect(new Set(ROTATION_TOOLS.map(t => t.field)).size).toBe(ROTATION_TOOLS.length)
  })

  test('every field maps back to its tool', () => {
    for (const t of ROTATION_TOOLS) expect(ROTATION_TOOL_BY_FIELD[t.field]).toBe(t.tool)
  })

  test('every rotation field has a Key Rotation button on the page', () => {
    const src = readFileSync(PAGE, 'utf8')
    for (const t of ROTATION_TOOLS) {
      expect(src, `${t.field} has no Key Rotation button`).toContain(`openRotationModal('${t.field}')`)
    }
  })
})

describe('the consumers read the shared list', () => {
  test('the settings PUT loops over ROTATION_TOOL_NAMES, with no private copy', () => {
    const src = readFileSync(SETTINGS_ROUTE, 'utf8')
    expect(src).toContain("from '@/lib/rotationTools'")
    expect(src).toMatch(/for \(const toolName of ROTATION_TOOL_NAMES\)/)
    expect(src).not.toMatch(/const TOOL_NAMES\s*=/)
  })

  test('the settings page has no private field -> tool map', () => {
    const src = readFileSync(PAGE, 'utf8')
    expect(src).toContain("from '@/lib/rotationTools'")
    expect(src).not.toMatch(/const TOOL_NAME_MAP\b/)
  })

  test('the template exports and accepts exactly the shared tools', () => {
    const tpl = buildTemplate({}, {})
    expect(Object.keys(tpl.rotation).filter(k => !k.startsWith('_'))).toEqual([...ROTATION_TOOL_NAMES])

    const rotation = Object.fromEntries(ROTATION_TOOL_NAMES.map(t => [t, { extraKeys: [`k-${t}`], rotateEveryN: 3 }]))
    const parsed = validateAndParse(JSON.stringify({ rotation }), 5000)
    expect(isValidationError(parsed)).toBe(false)
    if (isValidationError(parsed)) return
    expect(Object.keys(parsed.rotation).sort()).toEqual([...ROTATION_TOOL_NAMES].sort())
  })
})
