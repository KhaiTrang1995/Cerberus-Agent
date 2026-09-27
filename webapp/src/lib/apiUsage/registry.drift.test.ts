/**
 * The report must cover every credential a user can save. A new key field, a
 * Secret Multiscanner credential, an LLM provider type or a rotation tool added
 * without a probe (or a companion slot, or a NOT_PROBED reason) fails here,
 * instead of silently never being checked.
 */
import { describe, test, expect } from 'vitest'
import { LLM_PROBES, NOT_PROBED, PROBES } from './registry'
import { ALLOWED_KEY_FIELDS, ALLOWED_TUNNEL_FIELDS } from '@/lib/apiKeysTemplate'
import { TRUFFLEHOG_KEY_FIELDS } from '@/lib/credentialFields'
import { PROVIDER_TYPES } from '@/lib/llmProviderPresets'
import { ROTATION_TOOLS } from '@/lib/rotationTools'
import { trackedFields } from './credentials'

const claimed = new Map<string, string>()
for (const p of PROBES) {
  for (const f of [p.field, ...(p.companions ?? []).map(c => c.field)]) {
    if (!claimed.has(f)) claimed.set(f, p.id)
  }
}

describe('coverage', () => {
  test('every key and tunnel field of the API Keys tab is a probe key, a companion, or NOT_PROBED', () => {
    for (const field of [...ALLOWED_KEY_FIELDS, ...ALLOWED_TUNNEL_FIELDS]) {
      expect(claimed.has(field) || field in NOT_PROBED, `${field} is saved in Settings but the usage report does not know it`).toBe(true)
    }
  })

  test('every Secret Multiscanner credential is covered', () => {
    for (const f of TRUFFLEHOG_KEY_FIELDS) {
      expect(claimed.has(f.name) || f.name in NOT_PROBED, `${f.name} is not covered`).toBe(true)
    }
  })

  test('every LLM provider type has a probe', () => {
    for (const t of PROVIDER_TYPES) {
      expect(LLM_PROBES[t.id], `LLM provider type ${t.id} has no probe`).toBeDefined()
      expect(LLM_PROBES[t.id].group).toBe('llm')
    }
    expect(Object.keys(LLM_PROBES).sort()).toEqual(PROVIDER_TYPES.map(t => t.id).sort())
  })

  test('every rotation tool is checked by the probe of its own field', () => {
    for (const t of ROTATION_TOOLS) {
      const probe = PROBES.find(p => p.rotationTool === t.tool)
      expect(probe, `rotation tool ${t.tool} has no probe`).toBeDefined()
      expect(probe!.field, `rotation tool ${t.tool} is attached to the wrong field`).toBe(t.field)
    }
  })

  test('a NOT_PROBED field says why, and is not also claimed', () => {
    for (const [field, reason] of Object.entries(NOT_PROBED)) {
      expect(reason.length, field).toBeGreaterThan(10)
      expect(claimed.has(field), field).toBe(false)
    }
  })
})

describe('registry hygiene', () => {
  const all = [...PROBES, ...Object.values(LLM_PROBES)]

  test('probe ids are unique, and so is each settings field\'s owner', () => {
    const ids = all.map(p => p.id)
    expect(new Set(ids).size).toBe(ids.length)
    const keyFields = PROBES.map(p => p.field)
    expect(new Set(keyFields).size).toBe(keyFields.length)
  })

  test('each probe either calls (run) or says why not', () => {
    for (const p of all) {
      if (p.kind === 'none') {
        expect(p.run, p.id).toBeUndefined()
        expect(p.notCheckedReason, p.id).toBeTruthy()
      } else {
        expect(typeof p.run, p.id).toBe('function')
      }
    }
  })

  test('every row can explain itself: a cost note, https dashboard/docs links, a display endpoint', () => {
    for (const p of all) {
      expect(p.costNote.length, p.id).toBeGreaterThan(3)
      expect(p.dashboardUrl, p.id).toMatch(/^https:\/\//)
      expect(p.docsUrl, p.id).toMatch(/^https:\/\//)
      expect(p.endpoint, p.id).toBeTruthy()
      // The display endpoint is method + host + path: never a query string that could hold a key.
      expect(p.endpoint, p.id).not.toMatch(/[?&](key|api_key|apikey|api-key|token)=/i)
    }
  })

  test('per-IP limited providers pace themselves', () => {
    for (const p of all.filter(x => x.limitScope === 'ip')) {
      expect(p.minIntervalMs ?? 0, p.id).toBeGreaterThanOrEqual(1000)
    }
  })

  test('the tracked list the page receives names each key field once', () => {
    const tracked = trackedFields(PROBES)
    const fields = tracked.map(t => t.field)
    expect(new Set(fields).size).toBe(fields.length)
    expect(tracked.filter(t => t.role === 'key').length).toBe(PROBES.length)
  })
})
