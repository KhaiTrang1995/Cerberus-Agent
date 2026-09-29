/**
 * Kimi / Moonshot: `GET {base}/users/me/balance` (catalogue C3). A key only
 * works on the platform that issued it, and each platform bills in its own
 * currency: api.moonshot.ai in USD, api.moonshot.cn in CNY. The agent calls
 * api.moonshot.ai, so the check does too: a .cn key fails there exactly as it
 * fails in a scan.
 */
import { isPlainObject, num } from '../../parse'
import { body, meter, shapeError, usageResult } from '../../results'
import type { MeterUnit, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail, providerCode, withNote } from './common'

export const AGENT_BASE = 'https://api.moonshot.ai/v1'

const WRONG_PLATFORM_NOTE = 'Kimi keys only work on the platform that issued them: RedAmon calls api.moonshot.ai, which rejects keys from platform.moonshot.cn'

export function request(key: string, base: string = AGENT_BASE): ProbeRequest {
  return { method: 'GET', url: `${base}/users/me/balance`, headers: bearer(key) }
}

export function balanceUnit(base: string): MeterUnit {
  return new URL(base).hostname.endsWith('.cn') ? 'cny' : 'usd'
}

function failure(res: ProbeResponse): ProbeResult {
  if (res.status === 401) return withNote(fail(res), WRONG_PLATFORM_NOTE)
  // One status, two meanings: no balance left vs a throttle (or an overloaded engine).
  if (res.status === 429) {
    return fail(res, providerCode(res) === 'exceeded_current_quota_error' ? 'quota_exhausted' : 'rate_limited')
  }
  return fail(res)
}

export function parse(res: ProbeResponse, unit: MeterUnit): ProbeResult {
  if (res.status !== 200) return failure(res)
  const d = body(res).data
  const available = isPlainObject(d) ? num(d.available_balance) : null
  if (!isPlainObject(d) || available == null) return shapeError(res)

  // available = voucher + cash; a negative cash balance is money owed. At 0 or
  // below Kimi refuses inference, which health.ts reads as exhausted.
  const voucher = num(d.voucher_balance)
  const cash = num(d.cash_balance)
  const parts: string[] = []
  if (voucher != null) parts.push(`voucher ${voucher.toFixed(2)}`)
  if (cash != null) parts.push(`cash ${cash.toFixed(2)}${cash < 0 ? ' (owed)' : ''}`)
  return usageResult([meter({
    id: 'available_balance', label: 'Available balance', unit, window: 'balance',
    remaining: available, primary: true, note: parts.length ? parts.join(' · ') : undefined,
  })])
}

export const kimiProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-kimi',
  service: 'kimi',
  label: 'Kimi (Moonshot)',
  kind: 'usage',
  costNote: 'Free: reading the balance is not billed',
  docsUrl: 'https://platform.kimi.ai/docs/api/balance',
  dashboardUrl: 'https://platform.moonshot.ai/console',
  endpoint: 'GET api.moonshot.ai/v1/users/me/balance',
  run: async ctx => parse(await ctx.http(request(ctx.key)), balanceUnit(AGENT_BASE)),
}
