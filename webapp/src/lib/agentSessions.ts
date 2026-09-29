/**
 * Is an agent session really running on this project?
 *
 * Conversation.agentRunning is set and cleared by fire-and-forget PATCHes from
 * the agent. An agent that is restarted or killed mid-run never sends the clear,
 * so the flag stays true and locks the project: preset apply, rescope, graph
 * activation and the queued-scan dispatcher all wait on it.
 *
 * There is deliberately no time-to-live. A run legitimately lasts hours, so an
 * age proves nothing. The agent's own task registry is the truth, and it is only
 * asked when a flag is set. A flag whose session the agent does not hold is
 * cleared, conditionally on the row being unchanged since it was read, so a run
 * that starts between the read and the clear keeps its flag.
 *
 * FAIL CLOSED: an agent that cannot answer leaves a set flag counting as running.
 * Server-side only.
 */
import prisma from '@/lib/prisma'
import { agentFetch } from '@/lib/agentFetch'

export type AgentSessionState = 'running' | 'idle' | 'unverified'

const LIVE_CHECK_TIMEOUT_MS = 5_000

/** Session ids the agent holds a running task for, or null when it could not say. */
async function liveSessionIds(projectId: string): Promise<Set<string> | null> {
  try {
    const res = await agentFetch(
      `/agent-sessions/live?project_id=${encodeURIComponent(projectId)}`,
      { method: 'GET' },
      { timeoutMs: LIVE_CHECK_TIMEOUT_MS },
    )
    if (!res.ok) return null
    const ids = (await res.json())?.session_ids
    if (!Array.isArray(ids)) return null
    return new Set(ids.filter((id): id is string => typeof id === 'string'))
  } catch (err) {
    console.error('[agentSessions] live-session check failed (treating a set flag as running):', err)
    return null
  }
}

/**
 * 'running' when the agent confirms a flagged session, 'idle' when no flag is
 * set or every set flag was stale (and is now cleared), 'unverified' when a flag
 * is set and the agent could not be asked. A database error propagates: each
 * caller already treats that as busy.
 */
export async function checkAgentSessions(projectId: string): Promise<AgentSessionState> {
  const flagged = await prisma.conversation.findMany({
    where: { projectId, agentRunning: true },
    select: { id: true, sessionId: true, updatedAt: true },
  })
  if (flagged.length === 0) return 'idle'

  const live = await liveSessionIds(projectId)
  if (!live) return 'unverified'
  if (flagged.some(c => live.has(c.sessionId))) return 'running'

  let cleared = 0
  for (const c of flagged) {
    const res = await prisma.conversation.updateMany({
      where: { id: c.id, agentRunning: true, updatedAt: c.updatedAt },
      data: { agentRunning: false },
    })
    cleared += res.count
  }
  console.warn(`[agentSessions] cleared ${cleared} stale agentRunning flag(s) on project ${projectId}`)
  // A row that changed since it was read may be a run that just started.
  return cleared === flagged.length ? 'idle' : 'running'
}

/** The phrase describeLiveGraphWriters and the MCP busy messages use, or null when idle. */
export function describeAgentSessionState(state: AgentSessionState): string | null {
  if (state === 'running') return 'an agent session is running'
  if (state === 'unverified') return 'an agent session is marked running and the agent could not be reached to confirm it'
  return null
}
