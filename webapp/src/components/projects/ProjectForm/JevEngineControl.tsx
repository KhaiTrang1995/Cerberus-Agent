'use client'

import { AlertTriangle } from 'lucide-react'
import type { JevProviderStatus } from '@/hooks/useHasJevProvider'
import styles from './JevEngineControl.module.css'

interface JevEngineControlProps {
  /** true = the hook runs on Jev; false = on the LLM in aiPipelineModel. */
  value: boolean
  /** Writes the specific *AiUseJev field. Each caller passes a literal field name. */
  onSelect: (useJev: boolean) => void
  /** Whether AI is active for this hook (aiInPipeline, and any per-hook flag). */
  enabled: boolean
  jevStatus: JevProviderStatus
  /** Why the control is disabled when `enabled` is false. Defaults to the master switch. */
  disabledHint?: string
}

/**
 * The LLM | Jev engine switch under a recon AI hook.
 *
 * It never auto-resets a stored `true`: a project whose owner lost the token
 * keeps the choice (the hook falls back to its static list at scan time), and a
 * badge says so. Switching a disabled-but-selected Jev back to LLM is allowed.
 * The server (validateJevEngineChange) is the authority on a switch-on.
 */
export function JevEngineControl({ value, onSelect, enabled, jevStatus, disabledHint }: JevEngineControlProps) {
  const noToken = jevStatus === 'no'
  const loading = jevStatus === 'loading'
  const error = jevStatus === 'error'

  // Jev cannot be CHOSEN when the owner has no token; but a stored true stays.
  const jevButtonDisabled = !enabled || loading || (noToken && !value)

  const jevTitle = !enabled
    ? disabledHint ?? 'Enable "AI in Pipeline" in the Target tab to choose an engine.'
    : loading
    ? 'Checking whether you have a Jev token…'
    : noToken
    ? 'No TypeSafe Jev token on your account. Add one in Settings → LLM Providers.'
    : 'Answer this hook with TypeSafe Jev instead of the LLM.'

  return (
    <div className={styles.wrap}>
      <div className={styles.segmented} role="group" aria-label="AI engine">
        <button
          type="button"
          className={`${styles.option} ${!value ? styles.active : ''}`}
          aria-pressed={!value}
          disabled={!enabled}
          title={!enabled ? jevTitle : 'Answer this hook with the LLM in the AI Model picker.'}
          onClick={() => onSelect(false)}
        >
          LLM
        </button>
        <button
          type="button"
          className={`${styles.option} ${value ? styles.active : ''}`}
          aria-pressed={value}
          disabled={jevButtonDisabled}
          title={jevTitle}
          onClick={() => onSelect(true)}
        >
          Jev
        </button>
      </div>
      {error && (
        <span className={styles.note} role="status">
          <AlertTriangle size={12} /> Couldn&apos;t check your Jev token
        </span>
      )}
      {value && noToken && (
        <span className={styles.badge}>
          No Jev token: this hook uses its static fallback
        </span>
      )}
    </div>
  )
}
