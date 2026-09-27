'use client'

import { llmInventoryKey } from '@/lib/apiUsage/inventory'
import type { ApiUsageReportV1, KeyResult } from '@/lib/apiUsage/types'
import { errorText, formatAmount, formatRelative, meterFigure, notCheckedText } from './format'
import styles from './ApiUsageReportModal.module.css'

function chipText(r: KeyResult): { text: string; tone: string } {
  if (r.outcome === 'usage') {
    const m = r.meters.find(x => x.primary) ?? r.meters[0]
    if (!m) return { text: 'Key valid', tone: 'var(--status-success-text)' }
    const text = m.window === 'balance' && m.remaining != null ? `Balance ${formatAmount(m.remaining, m.unit)}` : meterFigure(m)
    const tone = r.health === 'exhausted' ? 'var(--status-error-text)' : r.health === 'low' ? 'var(--status-warning-text)' : 'var(--status-success-text)'
    return { text, tone }
  }
  if (r.outcome === 'valid_no_usage') return { text: 'Key valid', tone: 'var(--status-success-text)' }
  if (r.outcome === 'error') return { text: errorText(r.error?.kind).title, tone: 'var(--status-error-text)' }
  return { text: notCheckedText(r.notCheckedReason), tone: 'var(--text-secondary)' }
}

/** The last report's verdict on one LLM provider row: "Balance $12.40 · 2 hours ago". */
export function ApiUsageLlmChip({ report, providerId }: { report: ApiUsageReportV1 | null | undefined; providerId: string }) {
  const r = report?.results?.find(x => x.field === llmInventoryKey(providerId))
  if (!r || !report) return null
  const { text, tone } = chipText(r)
  return (
    <span className={styles.llmChip} style={{ color: tone }} title="From the last API usage report">
      {text} · {formatRelative(report.finishedAt)}
    </span>
  )
}
