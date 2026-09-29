'use client'

import { Loader2, EyeOff } from 'lucide-react'
import styles from './MuteButton.module.css'

export const MUTE_TITLE = 'Hide this finding from the graph, reports and the AI agent'

interface MuteButtonProps {
  onClick: () => void
  busy?: boolean
  disabled?: boolean
  title?: string
}

/** The Priority Board's Mute button, for every surface that offers a mute. */
export function MuteButton({ onClick, busy = false, disabled = false, title = MUTE_TITLE }: MuteButtonProps) {
  return (
    <button
      type="button"
      className={styles.muteButton}
      disabled={disabled || busy}
      onClick={e => {
        // Several tables select or expand a row on click; muting should do neither.
        e.stopPropagation()
        onClick()
      }}
      title={title}
    >
      {busy ? <Loader2 className={styles.spin} size={13} /> : <EyeOff size={13} />}
      Mute
    </button>
  )
}
