/**
 * Who muted a finding is four-valued: `person`, `multi`, `mcp`, `rule`.
 *
 * `muted_by` alone cannot tell three of them apart (a person, their Multi
 * mute and their MCP agent all carry the same user id), so every place that
 * shows or counts mutes must know all four. A consumer that reads `multi` as
 * unknown falls back to `person`, and presents a bulk, AI-suggested mute as a
 * one-by-one judgement: in Muted Nodes, over MCP, or in a client's report.
 *
 * This enumerates the values across the three consumers. Adding a fifth value
 * to either union also breaks the type-check below until every consumer here
 * handles it.
 */
import { describe, test, expect, vi } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { mutedViaOf, type MutedVia } from '@/lib/nodeFilters/mutedAnnotate'
import {
  exportRows, MUTED_VIA_VALUES, mutedByText, type MutedRow, type RowMutedVia,
} from '@/app/graph/components/MutedNodes/mutedNodes'
import { generateReportHtml } from '@/lib/report/reportTemplate'

const ALL = ['rule', 'mcp', 'person', 'multi'] as const

// Compile-time halves of the guard: a missing or extra key fails type-check.
const MCP_SIDE: Record<MutedVia, true> = { rule: true, mcp: true, person: true, multi: true }
const TABLE_SIDE: Record<RowMutedVia, true> = { rule: true, mcp: true, person: true, multi: true }

const SRC = (rel: string) => readFileSync(join(__dirname, rel), 'utf8')

/** The raw agent row for each value, as the graph stores it. */
const RAW: Record<(typeof ALL)[number], Record<string, unknown>> = {
  rule: { muted_by: 'rule:vuln.nuclei/k3f9a2' },
  mcp: { muted_by: 'u1', muted_channel: 'mcp', muted_token: 'rdmn_mcp_ab12cd34' },
  person: { muted_by: 'u1' },
  multi: { muted_by: 'u1', muted_channel: 'multi', muted_token: 'mm-3f9a2c1d' },
}

describe('the muted_via values every consumer knows', () => {
  test('both unions are exactly the four values', () => {
    expect(Object.keys(MCP_SIDE).sort()).toEqual([...ALL].sort())
    expect(Object.keys(TABLE_SIDE).sort()).toEqual([...ALL].sort())
    expect([...MUTED_VIA_VALUES].sort()).toEqual([...ALL].sort())
  })

  test('MCP: mutedViaOf tells each apart from the raw fields, and trusts the agent\'s own value', () => {
    for (const via of ALL) {
      expect(mutedViaOf(RAW[via])).toBe(via)
      expect(mutedViaOf({ ...RAW.person, muted_via: via })).toBe(via)
    }
    // The MCP tools read it through mutedViaOf, and the playbook explains each.
    expect(SRC('mcp/findingTools.ts')).toContain('mutedViaOf(')
    const playbook = SRC('mcp/playbook.ts')
    for (const via of ALL) expect(playbook).toContain(`\`muted_via: ${via}\``)
  })

  test('Muted Nodes: each reads differently, and only a one-by-one mute reads as "you"', () => {
    const row = (via: RowMutedVia): MutedRow => ({
      id: 'v1', label: 'Vulnerability', name: 'n', severity: 'low', source: 'nuclei', host: 'h',
      muted_at: null, muted_by: String(RAW[via].muted_by), muted_via: via,
      muted_token: RAW[via].muted_token as string | undefined, muted_reason: '', stale_since: null,
      triage_status: 'unreviewed', triage_reason: null, rule_kind: null, rule_id: null,
      rule_name: via === 'rule' ? 'Info' : null, rule_deleted: false,
    })
    const texts = ALL.map(via => mutedByText(row(via), 'u1'))
    expect(new Set(texts).size).toBe(ALL.length)
    expect(texts.filter(t => t === 'you')).toEqual(['you'])
    expect(mutedByText(row('person'), 'u1')).toBe('you')
    for (const via of ALL) expect(exportRows([row(via)], 'u1')[0].muted_via).toBe(via)
  })

  test('the report: each has its own row, and only a one-by-one mute is called reviewed', () => {
    const data = SRC('report/reportData.ts')
    expect(data).toContain("STARTS WITH 'rule:' AS byRule")
    expect(data).toContain("coalesce(n.muted_channel, '') = 'mcp') AS byAgent")
    expect(data).toContain("coalesce(n.muted_channel, '') = 'multi') AS byMulti")

    const html = generateReportHtml({
      project: { name: 'p', targetDomain: 'example.com' },
      remediations: [],
      generatedAt: '2026-09-29T00:00:00Z',
      graphOverview: {
        totalNodes: 0, nodeCounts: [],
        suppressedCount: 1 + 2 + 4 + 8,
        suppressedByPeople: 1 + 2,
        suppressedByMultiMute: 2,
        suppressedByAgents: 4,
        suppressedByRules: 8,
        suppressedRules: [],
        subdomainStats: { total: 0, resolved: 0, uniqueIps: 0 },
        endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
        certificateHealth: { total: 0, expired: 0, expiringSoon: 0 },
        infrastructureStats: { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
        subdomainMappings: [], ipMappings: [],
      },
      attackSurface: {
        services: [], ports: [], technologies: [], dnsRecords: [],
        securityHeaders: [], endpointCategories: [], parameterAnalysis: [],
      },
      vulnerabilities: { severityDistribution: [], findings: [], cvssHistogram: [], cveSeverity: [], gvmRemediation: [] },
      cveIntelligence: { cveChains: [], exploits: [], githubSecrets: { repos: 0, secrets: 0, sensitiveFiles: 0 } },
      trufflehog: { totalFindings: 0, verifiedFindings: 0, repositories: 0, findings: [] },
      secrets: { total: 0, bySeverity: [], bySource: [], byType: [], findings: [] },
      jsRecon: { totalFindings: 0, bySeverity: [], byType: [], findings: [] },
      graphqlScan: { totalFindings: 0, endpointsTested: 0, introspectionEnabled: 0, bySeverity: [], byType: [], endpoints: [], findings: [] },
      otx: { totalPulses: 0, totalMalware: 0, enrichedIps: 0, adversaries: [], pulses: [], malware: [] },
      vhostSni: { totalFindings: 0, ipsTested: 0, bySeverity: [], byType: [], findings: [] },
      webCachePoison: { totalFindings: 0, confirmed: 0, strong: 0, bySeverity: [], byImpact: [], findings: [] },
      aiSurface: {
        totalAiEndpoints: 0, ragIngestEndpoints: 0, promptInjectableParams: 0, mcpServers: 0,
        mcpPoisoningFindings: 0, vectorDbs: 0, modelFamilies: [], byInterfaceType: [], findings: [],
        attackFindings: [], attackToolsRun: [],
      },
      attackChains: { chains: [], exploitSuccesses: [], topFindings: [], totalChainFindings: 0 },
      metrics: {
        riskScore: 0, riskLabel: 'Low', totalVulnerabilities: 0, totalRemediations: 0,
        criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, exploitableCount: 0, totalCves: 0,
        cveCriticalCount: 0, cveHighCount: 0, cveMediumCount: 0, cveLowCount: 0,
        cvssAverage: 0, attackSurfaceSize: 0, secretsExposed: 0,
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any, null)
    const rows = [...html.matchAll(/<tr><td>Suppressed[^<]*<\/td><td>([^<]*)<\/td><\/tr>/g)].map(m => m[1])
    expect(rows).toHaveLength(ALL.length)
    expect(rows.filter(r => /\breviewed\b/.test(r) && !/not reviewed/.test(r))).toEqual([
      '1 finding(s) reviewed and excluded from this report',
    ])
  })
})
