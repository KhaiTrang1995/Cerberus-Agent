/**
 * B-9: the LLM-facing text about what settings a token can write.
 *
 * `update_recon_settings` kept describing the 126-field allowlist it replaced -
 * "can NEVER change ... wordlists, request headers, any agent setting" - long
 * after every one of those became settable. Agents believed the description,
 * not the tool, and concluded that editing an existing project's settings was
 * impossible. The refusal sentence is now BUILT from the registry; this pins
 * that it names every refused class and every create-only key, so it cannot
 * describe a different surface from the one the filter enforces.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import type { Tool } from '@modelcontextprotocol/sdk/types.js'

import { createOnlyFields, neverFields } from '@/lib/reconSettings/registry'
import { settableFieldCount } from '@/lib/reconSettings/filter'
import { listAdvertisedTools } from './apiReference'

let tools: Map<string, Tool>

beforeAll(async () => {
  tools = new Map((await listAdvertisedTools()).map(t => [t.name, t]))
})

const description = (name: string) => tools.get(name)?.description ?? ''

describe('update_recon_settings describes the surface the filter enforces', () => {
  test('every create-only key is named', () => {
    const text = description('update_recon_settings')
    const missing = createOnlyFields().map(f => f.key).filter(k => !text.includes(k))
    expect(missing).toEqual([])
  })

  test('every refused class is named', () => {
    const text = description('update_recon_settings')
    const classes = [...new Set(neverFields().map(f => f.deny_reason).filter(Boolean))] as string[]
    expect(classes.length).toBeGreaterThan(0)
    expect(classes.filter(c => !text.includes(c))).toEqual([])
  })

  test('it states the real settable count', () => {
    expect(description('update_recon_settings')).toContain(`${settableFieldCount()} settable fields`)
  })

  test('none of the old allowlist claims survive', () => {
    const text = description('update_recon_settings')
    for (const stale of ['Allowlisted', 'any agent setting', 'request headers, any intrusiveness']) {
      expect(text, stale).not.toContain(stale)
    }
    const arg = (tools.get('update_recon_settings')?.inputSchema as {
      properties?: Record<string, { description?: string }>
    }).properties?.settings?.description ?? ''
    expect(arg).not.toMatch(/allowlist/i)
  })
})

describe('get_recon_settings is not described as a narrow subset', () => {
  test('it says what it returns, and what no read returns', () => {
    const text = description('get_recon_settings')
    expect(text).not.toMatch(/narrow subset/)
    expect(text).toMatch(/updatedAt/)
    expect(text).toMatch(/write-only/)
  })
})

describe('create_project names no tool that does not exist', () => {
  test('the batch-host argument no longer points at update_project', () => {
    const schema = tools.get('create_project')?.inputSchema as {
      properties?: Record<string, { description?: string }>
    }
    expect(schema.properties?.domainBatchHosts?.description ?? '').not.toMatch(/\bupdate_project\b/)
  })
})
