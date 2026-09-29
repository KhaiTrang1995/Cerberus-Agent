/**
 * Small, pure parsing helpers shared by every provider parser. Providers type
 * the same number as an int, a numeric string, or a string with thousands
 * separators ("20,000,000"), and report times as epoch seconds, epoch ms, ISO
 * strings or zone-less "YYYY-MM-DD HH:mm:ss": these normalize all of it.
 */
import type { MeterWindow } from './types'

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** A finite number from a number or a numeric string ("20,000,000", " 0.000 "); else null. */
export function num(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v !== 'string') return null
  const s = v.replace(/[,\s]/g, '')
  if (s === '') return null
  const n = Number(s)
  return Number.isFinite(n) ? n : null
}

export function intOrNull(v: unknown): number | null {
  const n = num(v)
  return n == null ? null : Math.trunc(n)
}

/** A non-empty trimmed string, else undefined. */
export function str(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined
  const s = v.trim()
  return s ? s : undefined
}

/** remaining = max(0, limit - used): soft caps let `used` pass `limit`. */
export function clampRemaining(limit: number | null, used: number | null): number | null {
  if (limit == null || used == null) return null
  return Math.max(0, limit - used)
}

/**
 * Epoch seconds or milliseconds -> ISO. Anything below 1e12 is taken as
 * seconds (1e12 ms is 2001; 1e12 s is the year 33658).
 */
export function epochToIso(v: unknown): string | null {
  const n = num(v)
  if (n == null || n <= 0) return null
  const ms = n < 1e12 ? n * 1000 : n
  const d = new Date(ms)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

/**
 * A date string -> ISO UTC. Zone-less values ("2022-04-11 06:06:54",
 * "2026-10-26") are read as UTC, which is what the providers that send them
 * document or imply. Returns null for '', 0 and anything unparseable.
 */
export function isoOrNull(v: unknown): string | null {
  if (typeof v === 'number') return epochToIso(v)
  const s = str(v)
  if (!s) return null
  let candidate = s
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) candidate = `${s}T00:00:00Z`
  else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) candidate = `${s.replace(' ', 'T')}Z`
  const d = new Date(candidate)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

/** '+08:00' / '-0530' / 'Z' -> minutes east of UTC. */
function offsetMinutes(offset: string): number {
  if (offset === 'Z' || offset === '') return 0
  const m = offset.match(/^([+-])(\d{2}):?(\d{2})$/)
  if (!m) return 0
  const mins = Number(m[2]) * 60 + Number(m[3])
  return m[1] === '-' ? -mins : mins
}

/** The next 1st of the month at 00:00 in the given UTC offset, as ISO UTC. */
export function firstOfNextMonth(offset: string, now: Date): string {
  const shift = offsetMinutes(offset) * 60_000
  const local = new Date(now.getTime() + shift)
  const next = Date.UTC(local.getUTCFullYear(), local.getUTCMonth() + 1, 1)
  return new Date(next - shift).toISOString()
}

export function firstOfNextMonthUtc(now: Date): string {
  return firstOfNextMonth('Z', now)
}

/** The next 00:00 in the given UTC offset, as ISO UTC. */
export function nextMidnight(offset: string, now: Date): string {
  const shift = offsetMinutes(offset) * 60_000
  const local = new Date(now.getTime() + shift)
  const next = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() + 1)
  return new Date(next - shift).toISOString()
}

/** The next Monday 00:00 UTC (ISO weeks, the ones OpenRouter bills by). */
export function nextMondayUtc(now: Date): string {
  const daysAhead = ((8 - now.getUTCDay()) % 7) || 7
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + daysAhead)).toISOString()
}

/** The next UTC boundary of a calendar window; null for windows that do not reset. */
export function nextUtcBoundary(window: MeterWindow, now: Date): string | null {
  const t = now.getTime()
  switch (window) {
    case 'second': return new Date(Math.floor(t / 1000) * 1000 + 1000).toISOString()
    case 'minute': return new Date(Math.floor(t / 60_000) * 60_000 + 60_000).toISOString()
    case 'hour': return new Date(Math.floor(t / 3_600_000) * 3_600_000 + 3_600_000).toISOString()
    case 'day': return nextMidnight('Z', now)
    case 'week': return nextMondayUtc(now)
    case 'month': return firstOfNextMonthUtc(now)
    default: return null
  }
}

/** JSON.parse that returns undefined instead of throwing. */
export function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

const ACRONYMS: Record<string, string> = { api: 'API', ip: 'IP', ips: 'IPs', url: 'URL', urls: 'URLs', dns: 'DNS', sbom: 'SBOM', scim: 'SCIM', ssl: 'SSL', tls: 'TLS' }

/** 'api_requests_daily' -> 'API requests daily': a label for an id no map names. */
export function humanize(id: string): string {
  const words = id.replace(/[_.]+/g, ' ').trim().split(/\s+/).filter(Boolean)
  if (words.length === 0) return id
  const out = words.map(w => ACRONYMS[w.toLowerCase()] ?? w.toLowerCase())
  out[0] = out[0].charAt(0).toUpperCase() + out[0].slice(1)
  return out.join(' ')
}
