/**
 * The key inventory: which credentials exist, in the settings page's own terms
 * (the masked last-4 hint and the number of rotation keys). The server stores it
 * in each report; the page recomputes it from what it shows now and compares, to
 * say "your keys changed since this report".
 *
 * maskSecret is idempotent on its own output (a masked '••••••••1234' masks to
 * itself), so the server can feed raw values and the page masked ones and both
 * land on the same hints. Client-safe: no server imports.
 */
import { maskSecret } from '@/lib/mcp/mask'
import type { KeyInventory } from './types'

/** A settings field the report checks, the probe that owns it and its rotation list. */
export interface TrackedField {
  field: string
  probeId: string
  label: string
  /** 'companion' = read alongside the key (an org id, a host), never a key itself. */
  role: 'key' | 'companion'
  rotationTool?: string
}

export interface LlmInventoryRow {
  id: string
  providerType: string
  apiKey?: string
  baseUrl?: string
  awsRegion?: string
  awsAccessKeyId?: string
  awsBearerToken?: string
}

export function llmInventoryKey(id: string): string {
  return `llm:${id}`
}

/** The credential that identifies an LLM provider row, plus what else decides the probe. */
export function llmInventoryHint(row: LlmInventoryRow): string {
  if (row.providerType === 'bedrock') {
    const cred = row.awsBearerToken || row.awsAccessKeyId || ''
    return `${maskSecret(cred)}|${row.awsRegion ?? ''}`
  }
  const hint = maskSecret(row.apiKey ?? '')
  return row.providerType === 'openai_compatible' ? `${hint}|${row.baseUrl ?? ''}` : hint
}

export function buildInventory(
  values: Record<string, unknown>,
  extraKeyCounts: Record<string, number>,
  tracked: readonly TrackedField[],
  llmRows: readonly LlmInventoryRow[] = [],
): KeyInventory {
  const inv: KeyInventory = {}
  for (const t of tracked) {
    const raw = values[t.field]
    const value = typeof raw === 'string' ? raw : ''
    const extra = t.rotationTool ? extraKeyCounts[t.rotationTool] ?? 0 : 0
    if (!value && extra === 0) continue
    inv[t.field] = { hint: maskSecret(value), extraKeys: extra }
  }
  for (const row of llmRows) {
    inv[llmInventoryKey(row.id)] = { hint: llmInventoryHint(row), extraKeys: 0 }
  }
  return inv
}

/** Fields whose presence, hint or rotation count differ between two inventories. */
export function inventoryChanges(saved: KeyInventory, current: KeyInventory): string[] {
  const changed: string[] = []
  for (const field of new Set([...Object.keys(saved), ...Object.keys(current)])) {
    const a = saved[field]
    const b = current[field]
    if (!a || !b || a.hint !== b.hint || a.extraKeys !== b.extraKeys) changed.push(field)
  }
  return changed
}

/**
 * What a check would cover right now, from the page's own (masked) state: the
 * services with at least one saved key, and the number of keys. Mirrors the
 * server's job building closely enough for a button label and the pending list.
 */
export function savedKeySummary(
  values: Record<string, unknown>,
  extraKeyCounts: Record<string, number>,
  tracked: readonly TrackedField[],
  llmRows: readonly (LlmInventoryRow & { name?: string })[] = [],
  llmLabel: (providerType: string) => string = t => t,
): { keys: number; services: { id: string; label: string }[] } {
  let keys = 0
  const services: { id: string; label: string }[] = []
  for (const t of tracked) {
    if (t.role !== 'key') continue
    const raw = values[t.field]
    const count = (typeof raw === 'string' && raw ? 1 : 0) + (t.rotationTool ? extraKeyCounts[t.rotationTool] ?? 0 : 0)
    if (count === 0) continue
    keys += count
    services.push({ id: t.probeId, label: t.label })
  }
  for (const row of llmRows) {
    const cred = row.providerType === 'bedrock' ? row.awsBearerToken || row.awsAccessKeyId : row.apiKey
    if (!cred && row.providerType !== 'openai_compatible') continue
    keys += 1
    services.push({ id: llmInventoryKey(row.id), label: row.name ? `${llmLabel(row.providerType)} · ${row.name}` : llmLabel(row.providerType) })
  }
  return { keys, services }
}
