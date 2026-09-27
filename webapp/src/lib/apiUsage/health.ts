/**
 * Health of a usage row, from its PRIMARY meters only. Secondary meters (a
 * per-minute window, a VirusTotal monitor quota) never colour a row: they are
 * rate headroom, not the plan the user is paying for.
 */
import type { Health, Meter } from './types'

/** Below this share of the limit left, a meter is "low". */
export const LOW_THRESHOLD = 0.10

const RANK: Record<Health, number> = { ok: 0, low: 1, exhausted: 2 }

export function meterHealth(m: Meter): Health {
  // limit 0 = "not in plan" (Shodan oss 0/0, urlscan livescan), never exhausted.
  if (m.limit === 0) return 'ok'
  if (m.limit != null && m.limit > 0) {
    const remaining = m.remaining ?? (m.used != null ? Math.max(0, m.limit - m.used) : null)
    if (remaining == null) return 'ok'
    if (remaining <= 0) return 'exhausted'
    return remaining / m.limit < LOW_THRESHOLD ? 'low' : 'ok'
  }
  // A balance has nothing to compute "low" against: only empty is a signal.
  if (m.remaining != null && m.remaining <= 0) return 'exhausted'
  return 'ok'
}

export function computeHealth(meters: Meter[]): Health {
  let worst: Health = 'ok'
  for (const m of meters) {
    if (!m.primary) continue
    const h = meterHealth(m)
    if (RANK[h] > RANK[worst]) worst = h
  }
  return worst
}

export function worseHealth(a: Health, b: Health): Health {
  return RANK[a] >= RANK[b] ? a : b
}
