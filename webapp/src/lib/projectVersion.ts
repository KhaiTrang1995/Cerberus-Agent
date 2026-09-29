/**
 * The project row's `updatedAt` as the settings form last saw it written.
 *
 * The form's full save is a compare-and-swap on that value: PUT
 * /api/projects/[id] refuses a body whose `updatedAt` is stale, which is what
 * stops a form left open from reverting a change an MCP agent made meanwhile.
 * So every write the form ITSELF causes must move the value forward, or the
 * next save reads the form's own write as someone else's and refuses it.
 *
 * The form's own PUTs return the row and are adopted where they are made. The
 * file-upload sections write the row through their own endpoints from deep
 * inside the form, so they announce the new value here instead of being
 * threaded a callback through every view that renders them.
 */
type Listener = (updatedAt: string) => void

/** The PUT's 409 when the form's `updatedAt` is stale. */
export const STALE_SAVE_MESSAGE =
  'This project changed since you opened it (possibly by an MCP agent). ' +
  'Reload to see the current settings.'

const listeners = new Map<string, Set<Listener>>()

/** A row's `updatedAt` as the ISO string the form sends back, or null. */
export function versionOf(value: unknown): string | null {
  if (typeof value === 'string' && !Number.isNaN(Date.parse(value))) return value
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString()
  return null
}

/** Tell the open settings form of `projectId` that the row was written. */
export function announceProjectWrite(projectId: string | null | undefined, updatedAt: unknown): void {
  const version = versionOf(updatedAt)
  if (!projectId || !version) return
  for (const listener of listeners.get(projectId) ?? []) listener(version)
}

/** Subscribe to writes of `projectId`. Returns the unsubscribe function. */
export function onProjectWrite(projectId: string, listener: Listener): () => void {
  let set = listeners.get(projectId)
  if (!set) {
    set = new Set()
    listeners.set(projectId, set)
  }
  set.add(listener)
  return () => {
    set!.delete(listener)
    if (set!.size === 0) listeners.delete(projectId)
  }
}
