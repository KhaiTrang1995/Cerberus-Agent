export interface GraphOverviewData {
  nodeCounts: { label: string; count: number }[]
  relationshipCounts: { type: string; count: number }[]
  totalNodes: number
  totalRelationships: number
  subdomainStats: { total: number; resolved: number; uniqueIps: number }
  endpointCoverage: { baseUrls: number; endpoints: number; parameters: number }
  certificateHealth: { total: number; expired: number; expiringSoon: number }
  topConnected: { label: string; name: string; degree: number }[]
  infrastructureStats: {
    totalIps: number; ipv4: number; ipv6: number
    cdnCount: number; uniqueAsns: number; uniqueCdns: number
  }
}

export interface SecurityFinding {
  name: string
  severity: string
  source: string
  category: string | null
  cvssScore: number | null
  matchedAt: string | null
  host: string | null
  targetIp: string | null
  targetPort: number | null
  target: string | null
  parentType: string | null
  endpointPath: string | null
  paramName: string | null
  findingSource: string
}

export interface CveChain {
  tech: string
  techVersion: string | null
  cveId: string
  cvss: number | null
  cveSeverity: string | null
  cweId: string | null
  cweName: string | null
  capecId: string | null
  capecName: string | null
  capecSeverity: string | null
}

export interface Exploit {
  name: string
  severity: string
  targetIp: string | null
  targetPort: number | null
  cvssScore: number | null
  cisaKev: boolean | null
  evidence: string | null
  cveIds: string[]
}

export interface VulnerabilityData {
  severityDistribution: { severity: string; count: number }[]
  vulnTypes: { name: string; severity: string; source: string; count: number }[]
  findings: SecurityFinding[]
  cvssHistogram: { bucket: number; count: number }[]
  cveSeverity: { severity: string; count: number }[]
  cveChains: CveChain[]
  exploits: Exploit[]
  githubSecrets: { repos: number; secrets: number; sensitiveFiles: number }
  gvmRemediation: { status: string; count: number }[]
}

export interface AttackSurfaceData {
  services: { service: string; port: number; count: number }[]
  ports: { port: number; protocol: string; count: number }[]
  technologies: { name: string; version: string | null; cveCount: number }[]
  dnsRecords: { type: string; count: number }[]
  securityHeaders: { name: string; isSecurity: boolean; count: number }[]
  headerCategories: { category: string; count: number }[]
  endpointCategories: { category: string; count: number }[]
  endpointTypes: { type: string; count: number }[]
  parameterAnalysis: { position: string; total: number; injectable: number }[]
  cdnDistribution: { segment: string; count: number }[]
  ipConcentration: { ip: string; subCount: number; isCdn: boolean }[]
}

export interface ActivityData {
  project: {
    name: string
    targetDomain: string
    ipMode: boolean
    scanModules: string[]
    createdAt: string
    updatedAt: string
  }
  conversations: {
    total: number
    totalIterations: number
    avgIterations: number
    byStatus: { status: string; count: number }[]
    byPhase: { phase: string; count: number }[]
  }
  remediations: {
    bySeverity: { severity: string; count: number }[]
    byStatus: { status: string; count: number }[]
    byCategory: { category: string; count: number }[]
    exploitableCount: number
  }
  totalMessages: number
  timeline: {
    conversations: { date: string; count: number; iterations: number }[]
    remediations: { date: string; count: number; [severity: string]: unknown }[]
  }
}

export interface AttackChainsData {
  chains: { title: string; status: string; steps: number; findings: number; failures: number }[]
  chainToolUsage: { tool: string; uses: number; successes: number }[]
  chainSuccessRate: { status: string; count: number }[]
  findingsByType: { findingType: string; count: number }[]
  findingsBySeverity: { severity: string; count: number }[]
  phaseProgression: { phase: string; totalSteps: number; successSteps: number }[]
  exploitSuccesses: {
    title: string; targetIp: string | null; targetPort: number | null
    module: string | null; payload: string | null
    evidence: string | null; attackType: string | null; cveIds: string[]
  }[]
  topFindings: {
    /** The ChainFinding's Neo4j internal id, for the Node ID column. */
    nodeId?: string | null
    title: string; severity: string; findingType: string
    evidence: string | null; confidence: number | null; phase: string | null
    targetHost: string | null
  }[]
  failuresByType: { failureType: string; count: number }[]
  decisions: { decisionType: string; count: number }[]
  gvmExploits: {
    name: string; targetIp: string | null; targetPort: number | null
    cvssScore: number | null; evidence: string | null; cisaKev: boolean | null
    family: string | null; cveIds: string[]
  }[]
  targetsAttacked: { targetHost: string; targetType: string | null; attackCount: number; successCount: number }[]
  attackFlowRows: { target: string; tool: string; findingType: string; severity: string }[]
}

export interface PipelineStatusData {
  recon: { status: string; currentPhase?: string; startedAt?: string; completedAt?: string } | null
  gvm: { status: string; startedAt?: string; completedAt?: string } | null
  githubHunt: { status: string; startedAt?: string; completedAt?: string } | null
}
