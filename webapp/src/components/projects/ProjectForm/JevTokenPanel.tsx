'use client'

import { AlertTriangle, CheckCircle2, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import { SiTypeSafe } from '@/components/icons/ProviderBrandIcons'
import { JEV_MODEL } from '@/lib/llmProviderKinds'
import { notifyJevProviderChanged, useJevProvider } from '@/hooks/useHasJevProvider'
import styles from './AiPipelinePanel.module.css'

const SETTINGS_URL = '/settings?tab=providers'

/**
 * The TypeSafe Jev token, next to the AI Model picker in the Target AI panel.
 *
 * Without a token it offers the same input as Global Settings, so a person can add
 * one without leaving the project form; with one it only confirms it is there. The
 * token belongs to the account, not the project: saving here is the same as saving
 * it in Global Settings, and every engine switch on the page picks it up at once.
 */
export function JevTokenPanel({ userId }: { userId: string | null }) {
  const { status, provider, refresh } = useJevProvider()

  return (
    <div className={styles.tokenPanel} data-testid="jev-token-panel">
      <div className={styles.tokenHead}>
        <span className={styles.tokenIcon} aria-hidden="true"><SiTypeSafe size={16} /></span>
        <span className={styles.tokenTitle}>TypeSafe AI (Jev)</span>
        {status === 'yes' && <span className={`${styles.chip} ${styles.chipOk}`}>Connected</span>}
        {status === 'no' && <span className={styles.chip}>Not added</span>}
      </div>

      {status === 'loading' && (
        <div className={styles.tokenNote}>
          <Loader2 size={12} className={styles.spin} /> Checking your Jev token…
        </div>
      )}

      {status === 'error' && (
        <div className={styles.tokenNote} role="alert">
          <AlertTriangle size={12} /> Couldn&apos;t check your Jev token.
          <button type="button" className={styles.linkButton} onClick={refresh}>
            <RefreshCw size={11} /> Retry
          </button>
        </div>
      )}

      {status === 'no' && userId && (
        <>
          <p className={styles.tokenIntro}>
            Optional. Lets the FFuf, Nuclei, WAF and takeover hooks run on Jev instead of
            the LLM. Saved to your account, like in Global Settings.
          </p>
          <LlmProviderForm
            userId={userId}
            lockedType="jev"
            embedded
            onSave={notifyJevProviderChanged}
            onCancel={() => {}}
          />
        </>
      )}

      {status === 'yes' && provider && (
        <div className={styles.connected} data-testid="jev-token-connected">
          <CheckCircle2 size={16} className={styles.connectedIcon} />
          <div className={styles.connectedText}>
            <span className={styles.connectedLine}>Your Jev token is included</span>
            <span className={styles.connectedMeta}>
              <span className={styles.mono}>{provider.apiKey}</span> · {provider.modelIdentifier || JEV_MODEL}
            </span>
          </div>
          <a className={styles.manageLink} href={SETTINGS_URL} target="_blank" rel="noopener noreferrer">
            Manage <ExternalLink size={11} />
          </a>
        </div>
      )}
    </div>
  )
}
