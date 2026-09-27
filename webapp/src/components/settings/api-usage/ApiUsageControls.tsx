'use client'

import { Gauge, History, Loader2 } from 'lucide-react'
import type { ApiUsageController } from './useApiUsageReport'
import { formatDateTime } from './format'
import styles from './ApiUsageReportModal.module.css'

interface Props {
  controller: ApiUsageController
  /** The page's header-button class, so these sit with Download Template / Import Keys. */
  buttonClassName: string
}

function timeOf(iso: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/**
 * "Check API usage" and "Last report". A disabled state keeps the button
 * focusable and hoverable (aria-disabled, not `disabled`) so its reason stays
 * readable in the tooltip.
 */
export function ApiUsageControls({ controller, buttonClassName }: Props) {
  const { meta, running, runStartedAt, startCheck, openReport } = controller
  const keyCount = controller.summary.keys
  const disabledReason = !meta
    ? null
    : !meta.enabled
      ? 'API usage checks are disabled on this host: API_USAGE_CHECK_ENABLED=false'
      : keyCount === 0 && !running
        ? 'No key is saved'
        : null
  const loading = !meta

  const onCheck = () => {
    if (loading || disabledReason) return
    if (running) openReport()
    else void startCheck()
  }

  const label = running
    ? `Checking… since ${timeOf(runStartedAt)}`
    : `Check API usage${meta ? ` (${keyCount} key${keyCount === 1 ? '' : 's'})` : ''}`

  return (
    <>
      <button
        type="button"
        className={`${buttonClassName} ${disabledReason || loading ? styles.controlDisabled : ''}`}
        onClick={onCheck}
        aria-disabled={!!disabledReason || loading}
        title={disabledReason ?? (running
          ? 'A check is running; click to follow it'
          : 'Check every saved key: plan, usage and what is left. Calls only account and usage endpoints.')}
      >
        {running ? <Loader2 size={13} className={styles.spin} /> : <Gauge size={13} />}
        {label}
      </button>
      {meta?.report && (
        <button type="button" className={buttonClassName} onClick={openReport} title="Open the saved API usage report">
          <History size={13} /> Last report · {formatDateTime(meta.report.finishedAt)}
        </button>
      )}
    </>
  )
}
