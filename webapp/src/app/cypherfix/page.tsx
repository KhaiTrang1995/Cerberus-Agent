'use client'

import { useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { CypherFixTab } from '@/app/graph/components/CypherFixTab/CypherFixTab'
import { useRemediations, useCypherFixTriageWS } from '@/hooks'
import { useProject } from '@/providers/ProjectProvider'
import { WikiInfoButton } from '@/components/ui'
import styles from './page.module.css'

export default function CypherFixPage() {
  const router = useRouter()
  const { projectId, userId, isLoading: projectLoading } = useProject()

  const [showTriageProgress, setShowTriageProgress] = useState(false)

  const { refetch: refetchRemediations } = useRemediations({
    projectId: projectId || '',
    enabled: !!projectId,
  })

  const triage = useCypherFixTriageWS({
    userId: userId || '',
    projectId: projectId || '',
    enabled: !!projectId && !!userId,
    // Connect on open, as the Priority Board does: the server re-attaches a
    // socket to a run already going, which is the only way this page learns of
    // a run started on the board or over MCP. Without it, Run during such a
    // run hit the preflight's "already in progress" and never connected (U11).
    autoConnect: true,
    onComplete: () => {
      refetchRemediations()
    },
  })

  const handleStartTriage = useCallback(() => {
    setShowTriageProgress(true)
    triage.startTriage()
  }, [triage])

  const handleOpenTriageProgress = useCallback(() => setShowTriageProgress(true), [])

  const handleCloseTriageProgress = useCallback(() => {
    setShowTriageProgress(false)
    // Closing the panel is not "stop the run", and dropping the socket
    // mid-run would lose the progress this page is about to want again.
    if (triage.status !== 'running' && triage.status !== 'connecting') {
      triage.disconnect()
    }
    if (triage.status === 'completed') {
      refetchRemediations()
    }
  }, [triage, refetchRemediations])

  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '12px' }}>
          <h2>No Project Selected</h2>
          <p>Select a project from the dropdown in the header or create a new one.</p>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page} style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', top: 12, right: 16, zIndex: 5 }}>
        <WikiInfoButton target="cypherfix" title="Open CypherFix wiki page" />
      </div>
      <CypherFixTab
        projectId={projectId || ''}
        userId={userId || ''}
        triage={triage}
        showTriageProgress={showTriageProgress}
        onStartTriage={handleStartTriage}
        onOpenTriageProgress={handleOpenTriageProgress}
        onCloseTriageProgress={handleCloseTriageProgress}
      />
    </div>
  )
}
