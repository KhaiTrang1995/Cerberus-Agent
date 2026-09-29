/**
 * The API usage report: what one "Check API usage" run found for every saved
 * credential. The JSON is persisted (`ApiUsageReport.report`), so this file is
 * the storage contract too: bump REPORT_SCHEMA_VERSION when a shape changes, and
 * keep the reader tolerant of values it does not know (a report written by an
 * older or newer build renders them as "unknown").
 *
 * A report holds numbers, plan names and last-4 key hints only. Never a key, an
 * email, or a raw provider body: providers are parsed through allowlisted fields
 * and every message is scrubbed of the key before it gets here.
 */

export const REPORT_SCHEMA_VERSION = 1

export type Outcome = 'usage' | 'valid_no_usage' | 'not_checked' | 'error'

/** Usage rows only, computed from the primary meters (health.ts). */
export type Health = 'ok' | 'low' | 'exhausted'

export type ErrorKind =
  | 'invalid_key'         // 401/403-bad-credentials or the provider's own "invalid key" code
  | 'forbidden'           // key accepted, but this account/plan may not call the endpoint
  | 'rate_limited'        // per-second/minute throttle hit while checking
  | 'quota_exhausted'     // the provider says the quota or credits are used up
  | 'timeout'
  | 'network'
  | 'provider_error'      // 5xx, or a block page in front of the provider
  | 'unexpected_response' // a 2xx we could not parse, an HTML page, shape drift

export type NotCheckedReason =
  | 'costs_credits'      // the only possible check spends a query
  | 'plan_restricted'    // the account API needs a paid plan
  | 'companion_missing'  // e.g. a Google key without its CX, a GHE token without its host
  | 'host_per_scan'      // Jenkins, Elasticsearch, generic Git: the host is chosen per scan
  | 'needs_username'     // Docker Hub: RedAmon stores the token only
  | 'custom_endpoint'    // an OpenAI-compatible provider on a user-chosen base URL
  | 'no_api'             // ngrok authtoken, chisel: nothing to ask
  | 'pending'            // known field, probe not shipped by this build

export type MeterUnit =
  | 'requests' | 'searches' | 'credits' | 'points' | 'coins' | 'rows' | 'queries'
  | 'bytes' | 'usd' | 'cny' | 'count'

export type MeterWindow = 'second' | 'minute' | 'hour' | 'day' | 'week' | 'month' | 'balance' | 'lifetime'

export type ProbeGroup = 'keys' | 'uncover' | 'github' | 'llm' | 'sources'

export interface Meter {
  id: string
  label: string
  unit: MeterUnit
  window: MeterWindow
  used: number | null
  /** null = unlimited or not reported (see `note`). 0 = not in plan. */
  limit: number | null
  remaining: number | null
  /** ISO-8601 UTC, or null when the provider does not say and nothing can be computed. */
  resetsAt: string | null
  /** 'computed' = derived from documented rules (e.g. the 1st of next month), not reported. */
  resetsAtSource: 'provider' | 'computed' | null
  /** Primary meters drive Health; secondary ones render collapsed. */
  primary: boolean
  note?: string
}

export interface AccountInfo {
  plan?: string
  /** A username or token name. Never an email address. */
  label?: string
  expiresAt?: string
}

export interface ProbeError {
  kind: ErrorKind
  httpStatus?: number
  providerCode?: string
  message: string
}

/** What a provider returns for one key: the provider-specific part of a KeyResult. */
export interface ProbeResult {
  outcome: Outcome
  account?: AccountInfo
  meters: Meter[]
  error?: ProbeError
  notCheckedReason?: NotCheckedReason
  notes?: string[]
  /**
   * The probe's own verdict where the primary meters cannot express it, and
   * REPLACES theirs: DeepSeek `is_available: false` is exhausted whatever the
   * balances say; a used-up plan still carried by a top-up balance is low, not
   * exhausted.
   */
  healthOverride?: Health
}

export interface KeyResult {
  serviceId: string
  serviceLabel: string
  group: ProbeGroup
  /** The settings field (or `llm:<providerId>`) the key came from. */
  field: string
  keyRole: 'primary' | 'rotation'
  /** 0 = primary, 1..n = rotation key #n. */
  keyIndex: number
  /** maskSecret(key), the same last-4 format the settings page shows. */
  keyHint: string
  /** The saved name of an LLM provider row. */
  sourceName?: string
  outcome: Outcome
  health?: Health
  account?: AccountInfo
  meters: Meter[]
  error?: ProbeError
  notCheckedReason?: NotCheckedReason
  notes?: string[]
  warnings?: string[]
  costNote: string
  dashboardUrl: string
  docsUrl: string
  /** 'GET api.shodan.io/api-info': method and host+path, never a key or a query. */
  endpoint: string
  experimental?: boolean
  checkedAt: string
  latencyMs: number | null
}

export interface ReportCounts {
  services: number
  keys: number
  usage: number
  validNoUsage: number
  notChecked: number
  errors: number
  low: number
  exhausted: number
}

/**
 * The key inventory the run saw, in the settings page's own terms (masked hint
 * of the primary + number of rotation keys). The page compares it with what it
 * shows now to tell the user the report no longer matches their keys.
 */
export type KeyInventory = Record<string, { hint: string; extraKeys: number }>

export interface ApiUsageReportV1 {
  schemaVersion: 1
  startedAt: string
  finishedAt: string
  durationMs: number
  counts: ReportCounts
  skippedEmpty: { field: string; label: string }[]
  inventory: KeyInventory
  results: KeyResult[]
}

/** Scans and agent runs in flight on the user's own projects. */
export interface UserActivity {
  runningScans: { projectId: string; projectName: string; kind: string; startedAt: string | null }[]
  agentRuns: { projectId: string; projectName: string }[]
}

// ---------------------------------------------------------------------------
// Probe plumbing
// ---------------------------------------------------------------------------

export interface ProbeRequest {
  method: 'GET' | 'POST'
  url: string
  headers?: Record<string, string>
  body?: string
}

export interface ProbeResponse {
  status: number
  /** Allowlisted response headers, lowercased names. */
  headers: Record<string, string>
  /** Parsed body when it looks like JSON (sniffed, not trusted from Content-Type). */
  json: unknown
  /** The first 2 KB of the body, for classification only. Never stored. */
  text: string
  contentType: string
  latencyMs: number
  /** The body was longer than the read cap and was cut. */
  truncated: boolean
}

export type ProbeHttp = (req: ProbeRequest) => Promise<ProbeResponse>

export interface ProbeContext {
  key: string
  /** Companion settings values, e.g. { censysOrgId: '…' }. Empty string when unset. */
  companions: Record<string, string>
  http: ProbeHttp
  now: Date
}

export interface Companion {
  field: string
  required: boolean
}

export interface ProbeDef {
  /** Report service id; unique per registry entry. */
  id: string
  /** The provider behind it: keys of one service run one after another and share pacing. */
  service: string
  label: string
  group: ProbeGroup
  /** The settings column holding the key. */
  field: string
  companions?: Companion[]
  /** A required companion set without the key is reported (AWS secret without its id). */
  reportLoneCompanion?: boolean
  /** ApiKeyRotationConfig.toolName whose extra keys are checked too. */
  rotationTool?: string
  kind: 'usage' | 'validity' | 'none'
  /** For kind 'none': why nothing is called. */
  notCheckedReason?: NotCheckedReason
  notCheckedMessage?: string
  costNote: string
  docsUrl: string
  dashboardUrl: string
  /** Date the parser last matched a live response; null = written from the docs only. */
  verifiedOn: string | null
  endpoint: string
  /** Gap between two keys of this service (default 250 ms). */
  minIntervalMs?: number
  /** 'ip': the provider limits per source IP, so the gap holds across every user's run. */
  limitScope?: 'key' | 'ip'
  /** Undocumented endpoint: any unrecognised answer is "not checked", never an error. */
  experimental?: boolean
  /** Parts of a stored value the probe sends separately (FOFA's `email:key`): scrubbed like the key. */
  secretParts?: (stored: string) => string[]
  run?: (ctx: ProbeContext) => Promise<ProbeResult>
}
