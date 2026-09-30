'use client'

import { memo } from 'react'
import { Loader2, CheckCircle, AlertCircle, X, Brain, CircleStop, Info } from 'lucide-react'
import {
  PUBLISHING_STOP_REFUSAL,
  TRIAGE_PHASES,
  TRIAGE_PHASE_LABELS,
  triagePhaseLabel,
  type TriagePhase,
  type TriageFindingPayload,
} from '@/lib/cypherfix-types'
import styles from './TriageProgress.module.css'

export const PHASE_LABELS = TRIAGE_PHASE_LABELS

interface TriageProgressProps {
  isVisible: boolean
  phase: TriagePhase | null
  progress: number
  findings: TriageFindingPayload[]
  thinking: string
  error: string | null
  /** A message that is not a failure, e.g. a Stop refused while publishing. */
  notice?: string | null
  status: string
  /** Feature name for the header, e.g. "Priority Board". Defaults to the CypherFix
   *  wording so the CypherFix page is unchanged. */
  title?: string
  onClose: () => void
  onStop: () => void
}

export const TriageProgress = memo(function TriageProgress({
  isVisible,
  phase,
  progress,
  findings,
  thinking,
  error,
  notice = null,
  status,
  title = 'Vulnerability Triage',
  onClose,
  onStop,
}: TriageProgressProps) {
  if (!isVisible) return null

  const isRunning = status === 'running' || status === 'connecting'
  const isCompleted = status === 'completed'
  const isError = status === 'error'
  const isStopped = status === 'stopped'
  const isPublishing = phase === 'publishing'
  const phaseLabel = phase ? triagePhaseLabel(phase) : 'Starting...'
  const phaseIndex = phase ? TRIAGE_PHASES.indexOf(phase) : -1

  return (
    <div className={styles.overlay}>
      <div className={styles.card}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            {isRunning && <Loader2 size={16} className={styles.spinner} />}
            {isCompleted && <CheckCircle size={16} className={styles.successIcon} />}
            {isError && <AlertCircle size={16} className={styles.errorIcon} />}
            {isStopped && <CircleStop size={16} className={styles.stoppedIcon} />}
            <span className={styles.headerTitle}>
              {isCompleted ? `${title} complete`
                : isError ? `${title} failed`
                  : isStopped ? `${title} stopped` : title}
            </span>
          </div>
          <div className={styles.headerRight}>
            {isRunning && (
              // Hiding is not stopping: the run goes on, and the page shows it
              // as its banner.
              <button className={styles.stopBtn} onClick={onClose} title="Hide this panel; the run keeps going">
                Hide
              </button>
            )}
            {isRunning && (
              <button
                className={styles.stopBtn}
                onClick={onStop}
                disabled={isPublishing}
                title={isPublishing ? PUBLISHING_STOP_REFUSAL : 'Stop the run; nothing is published'}
              >
                Stop
              </button>
            )}
            {(isCompleted || isError || isStopped) && (
              <button className={styles.closeBtn} onClick={onClose} aria-label="Close panel">
                <X size={14} />
              </button>
            )}
          </div>
        </div>

        {/* Progress */}
        <div className={styles.progressSection}>
          <div className={styles.progressBar}>
            <div
              className={styles.progressFill}
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>
          <div className={styles.phaseLabel}>{phaseLabel}</div>
          <ol className={styles.steps} aria-label="Run phases">
            {TRIAGE_PHASES.map((step: TriagePhase, i) => {
              const state = isCompleted || i < phaseIndex ? 'done'
                : i === phaseIndex ? 'current' : 'todo'
              return (
                <li
                  key={step}
                  className={`${styles.step} ${styles[`step_${state}`] ?? ''}`}
                  aria-current={state === 'current' ? 'step' : undefined}
                >
                  {TRIAGE_PHASE_LABELS[step]}
                </li>
              )
            })}
          </ol>
        </div>

        {notice && (
          <div className={styles.noticeBox} role="status">
            <Info size={14} />
            {notice}
          </div>
        )}

        {isStopped && (
          <div className={styles.stoppedSection}>
            <p>
              Stopped before publishing, so nothing from this run reached the board or
              the fix list: both keep the previous run&apos;s results.
            </p>
            <button className={styles.stopBtn} onClick={onClose}>Close</button>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className={styles.errorBox}>
            <AlertCircle size={14} />
            {error}
          </div>
        )}

        {/* Thinking */}
        {thinking && isRunning && (
          <div className={styles.thinkingSection}>
            <Brain size={12} className={styles.thinkingIcon} />
            <span className={styles.thinkingText}>
              {thinking.length > 200 ? thinking.slice(-200) + '...' : thinking}
            </span>
          </div>
        )}

        {/* Live findings */}
        {findings.length > 0 && (
          <div className={styles.findingsSection}>
            <div className={styles.findingsHeader}>
              Findings: {findings.length}
            </div>
            <div className={styles.findingsList}>
              {findings.slice(-6).map((f, i) => (
                <div key={i} className={styles.findingItem}>
                  <span className={`${styles.findingSeverity} ${styles[`sev_${f.severity}`]}`}>
                    {f.severity}
                  </span>
                  <span className={styles.findingTitle}>{f.title}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Completed summary */}
        {isCompleted && (
          <div className={styles.completedSection}>
            <p>Generated {findings.length} remediation items.</p>
            <button className={styles.viewBtn} onClick={onClose}>
              View Dashboard
            </button>
          </div>
        )}
      </div>
    </div>
  )
})
