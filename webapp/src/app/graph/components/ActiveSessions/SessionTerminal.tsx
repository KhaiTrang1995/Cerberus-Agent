'use client'

import { useState, useRef, useEffect, useCallback, memo } from 'react'
import { Send, Terminal, AlertTriangle, Sparkles, Loader2 } from 'lucide-react'
import type { SessionInteractResult } from '@/lib/websocket-types'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import styles from './SessionTerminal.module.css'

interface TerminalLine {
  text: string
  type: 'command' | 'output' | 'error' | 'system'
}

interface SessionTerminalProps {
  sessionId: number | null
  sessionType: 'meterpreter' | 'shell' | string
  agentBusy: boolean
  projectId: string
  onInteract: (sessionId: number, command: string) => Promise<SessionInteractResult>
}

export const SessionTerminal = memo(function SessionTerminal({
  sessionId,
  sessionType,
  agentBusy,
  projectId,
  onInteract,
}: SessionTerminalProps) {
  const [lines, setLines] = useState<TerminalLine[]>([])
  const [input, setInput] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [commandHistory, setCommandHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [nlpInput, setNlpInput] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [nlpError, setNlpError] = useState<string | null>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const nlpInputRef = useRef<HTMLInputElement>(null)
  const prevSessionRef = useRef<number | null>(null)
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()

  // Clear terminal when session changes
  useEffect(() => {
    if (sessionId !== prevSessionRef.current) {
      setLines([])
      setInput('')
      setHistoryIndex(-1)
      setNlpInput('')
      setNlpError(null)
      prevSessionRef.current = sessionId
    }
  }, [sessionId])

  // Auto-scroll to bottom on new output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [lines])

  // Focus input when terminal is shown
  useEffect(() => {
    if (sessionId !== null) {
      inputRef.current?.focus()
    }
  }, [sessionId])

  const handleSend = useCallback(async () => {
    if (!input.trim() || !sessionId || isSending) return

    const command = input.trim()
    setInput('')
    setIsSending(true)
    setHistoryIndex(-1)

    // Add to history
    setCommandHistory(prev => {
      const filtered = prev.filter(c => c !== command)
      return [command, ...filtered].slice(0, 50)
    })

    // Show command in terminal
    setLines(prev => [...prev, { text: `$ ${command}`, type: 'command' }])

    const result = await onInteract(sessionId, command)

    if (result.busy) {
      setLines(prev => [...prev, { text: result.message || 'Agent is busy, try again shortly', type: 'error' }])
    } else if (result.output) {
      setLines(prev => [...prev, { text: result.output!, type: 'output' }])
    }

    setIsSending(false)
    inputRef.current?.focus()
  }, [input, sessionId, isSending, onInteract])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleSend()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (commandHistory.length > 0) {
        const newIdx = Math.min(historyIndex + 1, commandHistory.length - 1)
        setHistoryIndex(newIdx)
        setInput(commandHistory[newIdx])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex > 0) {
        const newIdx = historyIndex - 1
        setHistoryIndex(newIdx)
        setInput(commandHistory[newIdx])
      } else {
        setHistoryIndex(-1)
        setInput('')
      }
    }
  }, [handleSend, commandHistory, historyIndex])

  // Command Whisperer - NLP to command translation
  const handleNlpSubmit = useCallback(async () => {
    if (!nlpInput.trim() || isGenerating) return

    setNlpError(null)
    // The route runs the user's own "Command whisperer" model; this only makes
    // sure one is saved before the request.
    if (!(await ensureFeatureModel('command_whisperer'))) return
    setIsGenerating(true)

    try {
      const resp = await fetchWithFeatureModel('command_whisperer', () => fetch('/api/agent/command-whisperer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: nlpInput.trim(),
          session_type: sessionType,
          project_id: projectId,
        }),
      }))

      if (!resp.ok) {
        const data = await resp.json().catch(() => ({ error: 'Request failed' }))
        const code = readFeatureModelCode(data)
        setNlpError(code
          ? featureModelMessage(code, typeof data.model === 'string' ? data.model : undefined)
          : data.error || `Error ${resp.status}`)
        return
      }

      const data = await resp.json()
      if (data.command) {
        setInput(data.command)
        setNlpInput('')
        inputRef.current?.focus()
      }
    } catch (err) {
      setNlpError(err instanceof Error ? err.message : 'Network error')
    } finally {
      setIsGenerating(false)
    }
  }, [nlpInput, isGenerating, sessionType, projectId, ensureFeatureModel, fetchWithFeatureModel])

  const handleNlpKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleNlpSubmit()
    }
  }, [handleNlpSubmit])

  // Empty state - no session selected
  if (sessionId === null) {
    return (
      <div className={styles.emptyTerminal}>
        <Terminal size={32} />
        <p>Select a session to interact</p>
      </div>
    )
  }

  const promptSymbol = sessionType === 'meterpreter' ? 'meterpreter >' : '$'

  return (
    <div className={styles.terminal}>
      <div className={styles.terminalHeader}>
        <div className={styles.terminalTitle}>
          <span className={styles.dot} />
          Session #{sessionId} - {sessionType}
        </div>
      </div>

      {agentBusy && (
        <div className={styles.busyBanner}>
          <AlertTriangle size={12} />
          Agent is executing a command - interaction may be delayed
        </div>
      )}

      <div ref={outputRef} className={styles.outputArea}>
        {lines.map((line, i) => (
          <pre
            key={i}
            className={`${styles.outputLine} ${
              line.type === 'command' ? styles.commandLine :
              line.type === 'error' ? styles.errorLine : ''
            }`}
          >
            {line.text}
          </pre>
        ))}
        {isSending && (
          <pre className={`${styles.outputLine} ${styles.sending}`}>
            Executing...
          </pre>
        )}
      </div>

      {/* Command Whisperer - NLP input */}
      <div className={styles.nlpArea}>
        <Sparkles size={13} className={styles.nlpIcon} />
        <input
          ref={nlpInputRef}
          className={styles.nlpInput}
          value={nlpInput}
          onChange={e => { setNlpInput(e.target.value); setNlpError(null) }}
          onKeyDown={handleNlpKeyDown}
          placeholder="Describe what you want to do..."
          disabled={isGenerating}
          autoComplete="off"
          spellCheck={false}
        />
        {isGenerating ? (
          <Loader2 size={13} className={styles.nlpSpinner} />
        ) : (
          <button
            className={styles.nlpBtn}
            onClick={handleNlpSubmit}
            disabled={!nlpInput.trim() || isGenerating}
            title="Generate command"
          >
            <Send size={11} />
          </button>
        )}
        {nlpError && <span className={styles.nlpError}>{nlpError}</span>}
        <div className={styles.nlpModel}>
          <FeatureModelLine featureId="command_whisperer" />
        </div>
      </div>

      <div className={styles.inputArea}>
        <span className={styles.prompt}>{promptSymbol}</span>
        <input
          ref={inputRef}
          className={styles.input}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type a command..."
          disabled={isSending}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          className={styles.sendBtn}
          onClick={handleSend}
          disabled={!input.trim() || isSending}
          title="Send command"
        >
          <Send size={13} />
        </button>
      </div>
    </div>
  )
})
