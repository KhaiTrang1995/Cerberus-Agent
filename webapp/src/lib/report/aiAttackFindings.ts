// Pure cross-tool corroboration logic for AI Attack Surface findings (§9).
// Kept dependency-free (no prisma / neo4j imports) so it is directly unit-testable
// without pulling in the DB layer. reportData.ts imports from here.
//
// The graph keeps a separate Vulnerability node per tool (keyed on
// source+OWASP+payload+target); the REPORT groups them by (OWASP-LLM id, target)
// so the same vuln found by e.g. garak AND promptfoo becomes one row with two
// evidence sources (promptfoo's "second opinion" payoff).

// One CONFIRMED finding, corroborated across tools.
export interface AiAttackFindingRecord {
  owaspLlmId: string          // LLM01..LLM10, or 'safety' for toxicity/harmful
  attackChip: string          // from v.type (ai_attack_<chip>), e.g. 'jailbreak'
  target: string              // attacked endpoint URL (or custom off-graph URL)
  endpointPath: string | null
  sources: string[]           // tools that found it, sorted (corroboration set)
  severity: string            // max severity across the corroborating findings
  maxAsr: number | null       // worst attack-success-rate across tools (0..1)
  totalTrials: number         // summed trials across tools
  payloadClasses: string[]    // distinct ai_payload_class values
  transcriptRefs: string[]    // distinct native-report paths (drill-down, §9c)
  probePackVersions: string[] // tool+version envelope, e.g. ['promptfoo/0.121.17']
  evidence: string            // representative evidence (worst-ASR finding)
  // `updated_at` of the representative row, NOT the newest across the group:
  // this module stays free of the Neo4j temporal decoding needed to compare
  // two of them, and the representative is the row whose evidence and ASR the
  // record already shows - so the timestamp matches the data on screen.
  updatedAt?: unknown
  /** Graph node id of the same representative row, for the same reason. */
  nodeId?: string | null
}

// Raw per-tool row straight off the graph, before cross-tool corroboration.
export interface RawAttackRow {
  source: string
  severity: string
  type: string | null
  owaspLlmId: string | null
  asr: number | null
  trials: number | null
  payloadClass: string | null
  transcriptRef: string | null
  evidence: string | null
  probePackVersion: string | null
  target: string | null
  endpointPath: string | null
  /** Optional: a caller with no timestamp to hand still builds a valid row. */
  updatedAt?: unknown
  nodeId?: string | null
}

export const ATTACK_SEV_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
}

// Group per-tool attack findings by (OWASP-LLM id, target) into corroborated
// records. Pure. Sorted by corroboration breadth, then worst ASR, then severity.
export function corroborateAttackFindings(rows: RawAttackRow[]): AiAttackFindingRecord[] {
  const groups = new Map<string, RawAttackRow[]>()
  for (const r of rows) {
    const key = `${r.owaspLlmId || '?'}::${r.target || '?'}`
    const g = groups.get(key)
    if (g) g.push(r)
    else groups.set(key, [r])
  }
  const uniq = (xs: (string | null)[]) => [...new Set(xs.filter(Boolean) as string[])]
  const out: AiAttackFindingRecord[] = []
  for (const group of groups.values()) {
    const rep = [...group].sort((a, b) =>
      (b.asr ?? 0) - (a.asr ?? 0) ||
      (ATTACK_SEV_RANK[b.severity] ?? 0) - (ATTACK_SEV_RANK[a.severity] ?? 0))[0]
    const severity = group.reduce((s, r) =>
      (ATTACK_SEV_RANK[r.severity] ?? 0) > (ATTACK_SEV_RANK[s] ?? 0) ? r.severity : s, 'info')
    const maxAsr = group.reduce<number | null>((m, r) =>
      r.asr != null && (m == null || r.asr > m) ? r.asr : m, null)
    out.push({
      owaspLlmId: rep.owaspLlmId || '-',
      attackChip: (rep.type || '').replace(/^ai_attack_/, '') || 'unknown',
      target: rep.target || '-',
      endpointPath: rep.endpointPath,
      sources: uniq(group.map(r => r.source)),
      severity,
      maxAsr,
      totalTrials: group.reduce((s, r) => s + (r.trials ?? 0), 0),
      payloadClasses: uniq(group.map(r => r.payloadClass)),
      transcriptRefs: uniq(group.map(r => r.transcriptRef)),
      probePackVersions: uniq(group.map(r => r.probePackVersion)),
      evidence: rep.evidence || '',
      updatedAt: rep.updatedAt ?? null,
      nodeId: rep.nodeId ?? null,
    })
  }
  out.sort((a, b) =>
    b.sources.length - a.sources.length ||
    (b.maxAsr ?? 0) - (a.maxAsr ?? 0) ||
    (ATTACK_SEV_RANK[b.severity] ?? 0) - (ATTACK_SEV_RANK[a.severity] ?? 0))
  return out
}
