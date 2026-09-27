/**
 * Turns the stored credentials into check jobs: one job per key, in registry
 * order, primary before rotation. Values are used EXACTLY as stored: the PUT
 * keeps keys as typed and recon/the agent receive them that way, so trimming
 * here would check a key the scans never send. Surrounding whitespace becomes a
 * row warning instead.
 */
import { maskSecret } from '@/lib/mcp/mask'
import { buildInventory, llmInventoryKey, type LlmInventoryRow, type TrackedField } from './inventory'
import { notCheckedResult } from './results'
import type { KeyInventory, ProbeDef, ProbeResult } from './types'

export interface ProbeJob {
  /** Registry position, then key position: the report's stable order. */
  order: number
  probe: ProbeDef
  field: string
  key: string
  keyRole: 'primary' | 'rotation'
  keyIndex: number
  keyHint: string
  companions: Record<string, string>
  sourceName?: string
  warnings: string[]
  notes: string[]
  /** Set when no call is made (kind 'none', a required companion missing). */
  immediate?: ProbeResult
}

export interface JobPlan {
  jobs: ProbeJob[]
  skippedEmpty: { field: string; label: string }[]
  inventory: KeyInventory
  /** Every secret value of the run, for scrubbing messages and logs. */
  secrets: string[]
}

export interface RotationRow {
  toolName: string
  extraKeys: string
}

export interface LlmProviderRow extends LlmInventoryRow {
  name: string
  apiKey: string
  baseUrl: string
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
  awsBearerToken: string
}

export const WHITESPACE_WARNING = 'The saved key has surrounding whitespace or a line break; scans send it exactly as stored'

/** Plain values that are not secrets (never scrubbed, still masked in hints). */
const NOT_SECRET = new Set(['githubEnterpriseHost', 'chiselServerUrl'])

function hasSurroundingWhitespace(v: string): boolean {
  return v !== v.trim()
}

/** Split exactly like the settings GET does for recon and the agent: on \n, blank lines dropped, lines kept as typed. */
export function splitExtraKeys(raw: string | null | undefined): string[] {
  return (raw ?? '').split('\n').filter(k => k.trim())
}

function ordinal(n: number): string {
  return n === 0 ? 'the primary key' : `rotation #${n}`
}

export function trackedFields(probes: readonly ProbeDef[]): TrackedField[] {
  const out: TrackedField[] = []
  const seen = new Set<string>()
  for (const p of probes) {
    for (const f of [p.field, ...(p.companions ?? []).map(c => c.field)]) {
      if (seen.has(f)) continue
      seen.add(f)
      const isKey = f === p.field
      out.push({
        field: f, probeId: p.id, label: p.label, role: isKey ? 'key' : 'companion',
        ...(isKey && p.rotationTool ? { rotationTool: p.rotationTool } : {}),
      })
    }
  }
  return out
}

function valueOf(settings: Record<string, unknown> | null, field: string): string {
  const v = settings?.[field]
  return typeof v === 'string' ? v : ''
}

export function buildJobs(input: {
  settings: Record<string, unknown> | null
  rotationRows: readonly RotationRow[]
  llmRows?: readonly LlmProviderRow[]
  probes: readonly ProbeDef[]
  llmProbes?: Readonly<Record<string, ProbeDef>>
}): JobPlan {
  const { settings, rotationRows, probes } = input
  const llmRows = input.llmRows ?? []
  const llmProbes = input.llmProbes ?? {}
  const jobs: ProbeJob[] = []
  const skippedEmpty: JobPlan['skippedEmpty'] = []
  const secrets = new Set<string>()
  const extraCounts: Record<string, number> = {}

  probes.forEach((probe, probeIndex) => {
    const primary = valueOf(settings, probe.field)
    const companions: Record<string, string> = {}
    for (const c of probe.companions ?? []) {
      companions[c.field] = valueOf(settings, c.field)
      if (companions[c.field] && !NOT_SECRET.has(c.field)) secrets.add(companions[c.field])
    }
    const row = probe.rotationTool ? rotationRows.find(r => r.toolName === probe.rotationTool) : undefined
    const extras = splitExtraKeys(row?.extraKeys)
    if (probe.rotationTool) extraCounts[probe.rotationTool] = extras.length

    const base = { probe, field: probe.field, companions }
    const missingCompanion = (probe.companions ?? []).find(c => c.required && !companions[c.field])
    const anyCompanionSet = (probe.companions ?? []).some(c => companions[c.field])

    // Nothing to check. A lone required companion is still reported when the
    // probe asks for it (an AWS secret key with no key id is a broken pair).
    if (!primary && extras.length === 0) {
      if (probe.reportLoneCompanion && anyCompanionSet) {
        const lone = (probe.companions ?? []).find(c => companions[c.field])!
        jobs.push({
          ...base, order: probeIndex * 1000, key: '', keyRole: 'primary', keyIndex: 0,
          keyHint: maskSecret(companions[lone.field]), warnings: [], notes: [],
          immediate: notCheckedResult('companion_missing', `${probe.label}: the other half of the credential is not saved`),
        })
      } else if (probe.kind === 'none' && anyCompanionSet) {
        const set = (probe.companions ?? []).find(c => companions[c.field])!
        jobs.push({
          ...base, order: probeIndex * 1000, key: '', keyRole: 'primary', keyIndex: 0,
          keyHint: maskSecret(companions[set.field]), warnings: [], notes: [],
          immediate: notCheckedResult(probe.notCheckedReason ?? 'pending', probe.notCheckedMessage),
        })
      } else {
        skippedEmpty.push({ field: probe.field, label: probe.label })
      }
      return
    }

    const keys = [primary, ...extras]
    // One row for a probe that never calls: N identical "not checked" rows say nothing more.
    if (probe.kind === 'none') {
      const first = keys.findIndex(k => k)
      const extraCount = keys.filter((k, i) => k && i !== first).length
      for (const k of keys) if (k) secrets.add(k)
      jobs.push({
        ...base, order: probeIndex * 1000 + first, key: keys[first], keyRole: first === 0 ? 'primary' : 'rotation',
        keyIndex: first, keyHint: maskSecret(keys[first]), warnings: [],
        notes: extraCount ? [`Also covers ${extraCount} rotation key${extraCount > 1 ? 's' : ''}`] : [],
        immediate: missingCompanion
          ? notCheckedResult('companion_missing', `${probe.label}: ${missingCompanion.field} is not saved`)
          : notCheckedResult(probe.notCheckedReason ?? 'pending', probe.notCheckedMessage),
      })
      return
    }

    const firstIndexOf = new Map<string, number>()
    keys.forEach((key, index) => {
      if (!key) return
      secrets.add(key)
      const earlier = firstIndexOf.get(key)
      if (earlier !== undefined) {
        const kept = jobs.find(j => j.probe === probe && j.keyIndex === earlier)
        kept?.notes.push(`Also listed as ${ordinal(index)}`)
        return
      }
      firstIndexOf.set(key, index)
      jobs.push({
        ...base,
        order: probeIndex * 1000 + index,
        key,
        keyRole: index === 0 ? 'primary' : 'rotation',
        keyIndex: index,
        keyHint: maskSecret(key),
        warnings: hasSurroundingWhitespace(key) ? [WHITESPACE_WARNING] : [],
        notes: [],
        immediate: missingCompanion
          ? notCheckedResult('companion_missing', `${probe.label}: ${missingCompanion.field} is not saved`)
          : undefined,
      })
    })
  })

  const llmBase = probes.length * 1000
  llmRows.forEach((row, i) => {
    const probe = llmProbes[row.providerType]
    const field = llmInventoryKey(row.id)
    const companions = {
      baseUrl: row.baseUrl ?? '', awsRegion: row.awsRegion ?? '', awsAccessKeyId: row.awsAccessKeyId ?? '',
      awsSecretKey: row.awsSecretKey ?? '', awsBearerToken: row.awsBearerToken ?? '',
    }
    for (const s of [row.apiKey, row.awsAccessKeyId, row.awsSecretKey, row.awsBearerToken]) if (s) secrets.add(s)
    const identifying = row.providerType === 'bedrock' ? (row.awsBearerToken || row.awsAccessKeyId) : row.apiKey
    // A keyless OpenAI-compatible provider (a local Ollama) still gets a row: its
    // probe says why it is not checked. Any other keyless row has nothing to check.
    if (!identifying && row.providerType !== 'openai_compatible') {
      skippedEmpty.push({ field, label: row.name || probe?.label || row.providerType })
      return
    }
    if (!probe) {
      jobs.push({
        probe: unknownLlmProbe(row.providerType), field, companions, order: llmBase + i, key: row.apiKey ?? '',
        keyRole: 'primary', keyIndex: 0, keyHint: maskSecret(identifying ?? ''), sourceName: row.name,
        warnings: [], notes: [], immediate: notCheckedResult('pending', 'This build has no check for this provider type'),
      })
      return
    }
    jobs.push({
      probe, field, companions, order: llmBase + i, key: row.apiKey ?? '', keyRole: 'primary', keyIndex: 0,
      keyHint: maskSecret(identifying ?? ''), sourceName: row.name,
      warnings: identifying && hasSurroundingWhitespace(identifying) ? [WHITESPACE_WARNING] : [],
      notes: [],
    })
  })

  const inventory = buildInventory(settings ?? {}, extraCounts, trackedFields(probes), llmRows)
  return { jobs, skippedEmpty, inventory, secrets: [...secrets] }
}

function unknownLlmProbe(providerType: string): ProbeDef {
  return {
    id: `llm-${providerType}`, service: `llm-${providerType}`, label: providerType, group: 'llm', field: 'apiKey',
    kind: 'none', notCheckedReason: 'pending', costNote: 'Not checked', docsUrl: '', dashboardUrl: '',
    verifiedOn: null, endpoint: '—',
  }
}
