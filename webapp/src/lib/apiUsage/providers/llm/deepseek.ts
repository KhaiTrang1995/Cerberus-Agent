/**
 * DeepSeek: `GET api.deepseek.com/user/balance` (catalogue C2). The agent's base
 * is `…/v1`, but the balance route hangs off the origin: the gateway answers
 * `/v1/user/balance` with a 401 before routing. Amounts are decimal STRINGS,
 * one entry per currency (CNY and USD can both appear).
 */
import { isPlainObject, num, str } from '../../parse'
import { body, errorResult, meter, shapeError, usageResult, validResult } from '../../results'
import type { Meter, ProbeContext, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail, listed, withNote } from './common'

const ORIGIN = 'https://api.deepseek.com'
const UNITS = new Map<string, 'usd' | 'cny'>([['USD', 'usd'], ['CNY', 'cny']])
const TOO_LOW = 'DeepSeek reports the balance is too low for API calls'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: `${ORIGIN}/user/balance`, headers: bearer(key) }
}

export function modelsRequest(key: string): ProbeRequest {
  return { method: 'GET', url: `${ORIGIN}/models`, headers: bearer(key) }
}

function failure(res: ProbeResponse): ProbeResult {
  // Documented on inference ("Insufficient Balance"); anywhere else it means the same.
  if (res.status === 402) return fail(res, 'quota_exhausted')
  // A missing or malformed key gets a plain-text 401, "Authentication Fails (governor)".
  return fail(res)
}

export function parse(res: ProbeResponse): ProbeResult {
  if (res.status !== 200) return failure(res)
  const b = body(res)
  if (!Array.isArray(b.balance_infos)) return shapeError(res)

  const entries = b.balance_infos.filter(isPlainObject).map(e => ({
    currency: str(e.currency)?.toUpperCase(),
    total: num(e.total_balance),
    granted: num(e.granted_balance),
    toppedUp: num(e.topped_up_balance),
  }))
  const funded = entries.some(e => (e.total ?? 0) > 0)
  const meters: Meter[] = []
  const notes: string[] = []
  for (const e of entries) {
    if (e.total == null || !e.currency) continue
    const unit = UNITS.get(e.currency)
    if (!unit) {
      notes.push(`DeepSeek also reported a ${e.currency} balance, which this report cannot show`)
      continue
    }
    meters.push(meter({
      id: `balance_${unit}`, label: `Balance (${e.currency})`, unit, window: 'balance',
      remaining: e.total,
      // An empty currency next to a funded one does not stop the account.
      primary: e.total > 0 || !funded,
      note: e.granted != null && e.toppedUp != null
        ? `granted ${e.granted.toFixed(2)} + topped-up ${e.toppedUp.toFixed(2)}`
        : undefined,
    }))
  }

  const unavailable = b.is_available === false
  if (meters.length === 0) {
    if (unavailable) return errorResult('quota_exhausted', TOO_LOW, { httpStatus: 200 })
    return validResult({ notes: [...notes, 'DeepSeek reported no balance'] })
  }
  if (unavailable) notes.push(TOO_LOW)
  return usageResult(meters, {
    notes: notes.length ? notes : undefined,
    // `is_available` is DeepSeek's own verdict; it overrides what the amounts suggest.
    ...(unavailable ? { healthOverride: 'exhausted' as const } : {}),
  })
}

/** The validity fallback: the balance route did not answer as documented. */
export function parseModels(res: ProbeResponse): ProbeResult {
  const ok = listed(res)
  if (ok?.outcome === 'valid_no_usage') {
    return withNote(ok, 'DeepSeek did not return the balance as documented; the key was checked on /models instead')
  }
  return ok ?? failure(res)
}

async function run(ctx: ProbeContext): Promise<ProbeResult> {
  const res = await ctx.http(request(ctx.key))
  const hasBalances = res.status === 200 && Array.isArray(body(res).balance_infos)
  // A moved route (404) or a 2xx without balances still leaves the key to check.
  const drifted = res.status === 404 || (res.status >= 200 && res.status < 300 && !hasBalances)
  if (!drifted) return parse(res)
  return parseModels(await ctx.http(modelsRequest(ctx.key)))
}

export const deepseekProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-deepseek',
  service: 'deepseek',
  label: 'DeepSeek',
  kind: 'usage',
  costNote: 'Free: reading the balance is not billed',
  docsUrl: 'https://api-docs.deepseek.com/api/get-user-balance',
  dashboardUrl: 'https://platform.deepseek.com/usage',
  endpoint: 'GET api.deepseek.com/user/balance',
  run,
}
