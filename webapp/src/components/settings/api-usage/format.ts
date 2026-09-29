/**
 * Words and number formats for the API usage report. Every lookup falls back
 * to "unknown" rather than failing: a saved report can come from an older or
 * newer build than the one rendering it.
 */
import type { ErrorKind, KeyResult, Meter, MeterUnit, MeterWindow, NotCheckedReason } from '@/lib/apiUsage/types'

export const ERROR_TEXT: Record<ErrorKind, { title: string; action: string }> = {
  invalid_key: { title: 'Key rejected', action: 'Re-enter the key or remove it' },
  forbidden: { title: 'Not allowed for this key or plan', action: 'Check the plan or the key permissions on the provider dashboard' },
  rate_limited: { title: 'Rate limited while checking', action: 'Try again in a minute' },
  quota_exhausted: { title: 'Quota used up', action: 'Wait for the reset or top up on the provider dashboard' },
  timeout: { title: 'Timed out', action: 'Try again later' },
  network: { title: 'Provider unreachable', action: 'Check the host network and try again' },
  provider_error: { title: 'Provider error', action: 'Try again later' },
  unexpected_response: { title: 'Unexpected answer', action: 'The provider may have changed its API; check its dashboard' },
}

export const NOT_CHECKED_TEXT: Record<NotCheckedReason, string> = {
  costs_credits: 'Checking would spend credits',
  plan_restricted: 'Needs a paid plan to check',
  companion_missing: 'Incomplete credential',
  host_per_scan: 'Host chosen per scan',
  needs_username: 'Needs a username',
  custom_endpoint: 'Custom endpoint',
  no_api: 'Nothing to check',
  pending: 'Not supported yet',
}

export function errorText(kind: string | undefined): { title: string; action: string } {
  return (kind && ERROR_TEXT[kind as ErrorKind]) || { title: 'Unknown error', action: 'Run a new check' }
}

export function notCheckedText(reason: string | undefined): string {
  return (reason && NOT_CHECKED_TEXT[reason as NotCheckedReason]) || 'Unknown reason'
}

const WINDOW_TEXT: Record<MeterWindow, string> = {
  second: 'per second', minute: 'per minute', hour: 'per hour', day: 'per day', week: 'per week', month: 'per month',
  balance: 'balance', lifetime: 'lifetime',
}

export function windowText(w: string): string {
  return WINDOW_TEXT[w as MeterWindow] ?? w
}

const SCAN_KIND_TEXT: Record<string, string> = {
  full_recon: 'Recon', partial_recon: 'Partial recon', gvm: 'GVM', github_hunt: 'GitHub Secret Hunt',
  trufflehog: 'Secret Multiscanner', supply_chain: 'Supply Chain', supply_chain_repo: 'Supply Chain',
  ai_attack: 'AI Attack Surface',
}

export function scanKindText(kind: string): string {
  return SCAN_KIND_TEXT[kind] ?? kind
}

const INT = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })
const DEC = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 })

function bytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (Math.abs(v) >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${DEC.format(v)} ${units[i]}`
}

export function formatAmount(n: number | null, unit: MeterUnit | string): string {
  if (n == null) return '—'
  if (unit === 'usd') return `$${DEC.format(n)}`
  if (unit === 'cny') return `¥${DEC.format(n)}`
  if (unit === 'bytes') return bytes(n)
  return Number.isInteger(n) ? INT.format(n) : DEC.format(n)
}

/** "84 / 100 credits", "12,000 credits", "unlimited", "not in plan", "not reported". */
export function meterFigure(m: Meter): string {
  const unit = m.unit === 'usd' || m.unit === 'cny' || m.unit === 'bytes' ? '' : ` ${m.unit}`
  if (m.limit === 0) return 'not in plan'
  if (m.limit != null && m.remaining != null) return `${formatAmount(m.remaining, m.unit)} / ${formatAmount(m.limit, m.unit)}${unit} left`
  if (m.remaining != null) return `${formatAmount(m.remaining, m.unit)}${unit} left`
  if (m.used != null && m.limit != null) return `${formatAmount(m.used, m.unit)} / ${formatAmount(m.limit, m.unit)}${unit} used`
  if (m.used != null) return `${formatAmount(m.used, m.unit)}${unit} used`
  // A plan cap with nothing measured against it (Criminal IP's search cap).
  if (m.limit != null) return `cap ${formatAmount(m.limit, m.unit)}${unit}`
  return m.note === 'unlimited' ? 'unlimited' : 'not reported'
}

/** Share of the limit still available, 0..1, or null when there is nothing to draw. */
export function meterShare(m: Meter): number | null {
  if (m.limit == null || m.limit <= 0) return null
  const remaining = m.remaining ?? (m.used != null ? Math.max(0, m.limit - m.used) : null)
  if (remaining == null) return null
  return Math.max(0, Math.min(1, remaining / m.limit))
}

export function formatDateTime(iso: string | null | undefined, withSeconds = false): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
    ...(withSeconds ? { second: '2-digit' } : {}),
  })
}

/** "2 hours ago", "in 3 d", "just now". */
export function formatRelative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const diff = t - now
  const abs = Math.abs(diff)
  const past = diff < 0
  const fmt = (n: number, unit: string, short: string) => {
    const v = Math.round(n)
    const text = abs < 48 * 3_600_000 ? `${v} ${unit}${v === 1 ? '' : 's'}` : `${v} ${short}`
    return past ? `${text} ago` : `in ${text}`
  }
  if (abs < 45_000) return past ? 'just now' : 'in a moment'
  if (abs < 3_600_000) return fmt(abs / 60_000, 'minute', 'min')
  if (abs < 48 * 3_600_000) return fmt(abs / 3_600_000, 'hour', 'h')
  return fmt(abs / 86_400_000, 'day', 'd')
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  return s < 60 ? `${DEC.format(s)} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`
}

export function keyRoleText(r: Pick<KeyResult, 'keyRole' | 'keyIndex'>): string {
  return r.keyRole === 'rotation' ? `rotation #${r.keyIndex}` : 'primary'
}
