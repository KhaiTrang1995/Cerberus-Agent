// A node-scoped agent session sends its first query as
//   [Graph Node Context: <label>]\n<context>\n\n[User Query]\n<request>
// The backend persists that exact string as the user_message, so the chat
// renderer and the conversation-title derivation both parse it back out.

const NODE_CONTEXT_PREFIX = '[Graph Node Context: '
const USER_QUERY_MARKER = '\n\n[User Query]\n'

export interface NodeContextQuery {
  nodeLabel: string
  context: string
  request: string
}

const singleLine = (s: string) => s.replace(/\s+/g, ' ').trim()

export function wrapNodeContextQuery(nodeLabel: string, context: string, request: string): string {
  return `${NODE_CONTEXT_PREFIX}${singleLine(nodeLabel)}]\n${context.trim()}${USER_QUERY_MARKER}${request.trim()}`
}

export function parseNodeContextQuery(content: string): NodeContextQuery | null {
  if (!content.startsWith(NODE_CONTEXT_PREFIX)) return null
  const headerEnd = content.indexOf(']\n', NODE_CONTEXT_PREFIX.length)
  // lastIndexOf: node properties are scan output and may contain the marker
  // text themselves; the user's request is always the final section.
  const markerAt = content.lastIndexOf(USER_QUERY_MARKER)
  if (headerEnd === -1 || markerAt === -1 || markerAt < headerEnd) return null
  return {
    nodeLabel: content.slice(NODE_CONTEXT_PREFIX.length, headerEnd),
    context: content.slice(headerEnd + 2, markerAt),
    request: content.slice(markerAt + USER_QUERY_MARKER.length),
  }
}

export function conversationTitleFromUserMessage(content: string): string {
  const parsed = parseNodeContextQuery(content)
  const title = parsed ? `${parsed.nodeLabel}: ${singleLine(parsed.request)}` : content
  return title.substring(0, 100)
}
