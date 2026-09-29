/**
 * Inject a project_id tenant filter into every node pattern of a Cypher query.
 *
 * The earlier version only rewrote `(var:Label ...)` patterns, so an
 * unlabeled or anonymous node pattern (`(n)`, `()`, `MATCH (n) RETURN n`)
 * slipped through with NO project_id predicate and could read across tenants.
 * This version scopes labeled, unlabeled, and anonymous node patterns alike,
 * skips the global reference labels, and never touches function-call parens.
 *
 * Extracted as a standalone function for testability.
 */

// Global node types that exist across all projects (no project_id property).
// These are enrichment/reference data from public databases (NVD, MITRE, CAPEC).
//
// Mirror of graph_db/tenant_filter.py GLOBAL_REFERENCE_LABELS, and it must stay
// in step: ExploitGvm is NOT here, though it once was. An ExploitGvm node is
// per-tenant data (gvm_mixin writes it with user_id + project_id, and triage
// can mute it), so exempting it left `MATCH (e:ExploitGvm) ...` completely
// unscoped - a cross-tenant read on this saved-view path.
const GLOBAL_LABELS = new Set(['CVE', 'MitreData', 'Capec'])

// A label string is exempt ONLY when it is a plain `:A` / `:A:B` conjunction and
// every label is global. A label EXPRESSION never qualifies: `(n:!CVE)` means
// "every node that is NOT a CVE" (i.e. all tenant data), `(n:A|CVE)` is a union,
// and `labelsFrom` would find 'CVE' in both and wrongly exempt them. This is the
// port of _is_global_reference_pattern in the Python filter.
const SIMPLE_LABELS_RE = /^(?::[A-Za-z_]\w*)+$/

function isSimpleGlobalReference(labelStr: string): boolean {
  const raw = labelStr.trim()
  if (!raw || !SIMPLE_LABELS_RE.test(raw)) return false
  const labels = raw.split(':').map(s => s.trim()).filter(Boolean)
  return labels.length > 0 && labels.every(l => GLOBAL_LABELS.has(l))
}

const FILTER_PROP = 'project_id: $projectId'

// A finding an operator suppressed as noise keeps its own label and gains this
// one. A saved view renders into the same graph screen as the live loader, so it
// is an enforcement site in its own right: without the exclusion below, a view
// would show findings the operator has already told the system to hide.
const MUTED_LABEL = 'Muted'

/**
 * Rewrite a label expression so it ALSO excludes `:Muted`.
 *
 * Mirrors `_labels_excluding_muted` in `graph_db/tenant_filter.py`, with one
 * deliberate difference: a union is distributed (`:A&!Muted|B&!Muted`) instead
 * of parenthesised (`:(A|B)&!Muted`). Both mean the same thing, because `&`
 * binds tighter than `|` -- but INTERIOR below cannot parse parentheses, and
 * `findUnscopedNodePattern` re-scans this function's own output. A form it could
 * not read would be reported as unscoped and the query refused.
 *
 * Legacy colon conjunction becomes `&` first: Neo4j 5 rejects `:A:B&!Muted`,
 * which mixes the two syntaxes in one pattern.
 */
function excludeMuted(labelStr: string): string {
  const raw = labelStr.trim()
  const body = raw.startsWith(':') ? raw.slice(1) : raw
  if (!body) return `:!${MUTED_LABEL}`
  const conjunction = body.replace(/:/g, '&')
  return ':' + conjunction.split('|').map(term => `${term}&!${MUTED_LABEL}`).join('|')
}

/**
 * True when the query mentions the reserved `Muted` label.
 *
 * The exclusion is applied automatically, so naming the label can only be an
 * attempt to inspect what was suppressed. Comments and string literals are
 * stripped first, so an ordinary text comparison is not mistaken for one.
 */
export function namesMutedLabel(cypher: string): boolean {
  const code = cypher
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')
  return new RegExp(`\\b${MUTED_LABEL}\\b`).test(code)
}

// A node pattern is a `(...)` group with no nested parens that is NOT preceded
// by a word char or `$` -> that excludes function calls like `count(n)` /
// `id(x)` and parameter refs, matching only true node positions and groupings.
function nodePatternRegex(): RegExp {
  return /(?<![\w$])\(([^()]*)\)/g
}

// Interior grammar of a node pattern: optional variable, optional :Label(s)
// (including label-expression separators), optional {props}. A parenthesized
// expression such as `(a.x > 1)` fails this grammar and is left untouched.
const INTERIOR = /^(\w+)?\s*((?::[\w|&!]+)*)\s*(\{[\s\S]*\})?$/

function labelsFrom(labelStr: string): string[] {
  return labelStr.split(/[:|&!]+/).map(s => s.trim()).filter(Boolean)
}

interface ParsedNode {
  varName: string
  labelStr: string
  labels: string[]
  props?: string // includes the surrounding braces
}

/** Parse a node-pattern interior, or return null if it is not one. */
function parseInterior(interior: string): ParsedNode | null {
  const m = INTERIOR.exec(interior.trim())
  if (!m) return null
  const labelStr = m[2] || ''
  return {
    varName: m[1] || '',
    labelStr,
    labels: labelsFrom(labelStr),
    props: m[3],
  }
}

export function injectProjectFilter(cypher: string): string {
  return cypher.replace(nodePatternRegex(), (match, interior) => {
    const node = parseInterior(interior)
    if (!node) return match // parenthesized expression / function arg, leave as-is
    if (isSimpleGlobalReference(node.labelStr)) return match // global reference data
    if (node.props && /\bproject_id\b/.test(node.props)) return match // already scoped

    const head = `${node.varName}${excludeMuted(node.labelStr)}`
    if (node.props != null) {
      const inner = node.props.slice(1, -1).trim()
      const body = inner ? `${FILTER_PROP}, ${inner}` : FILTER_PROP
      return `(${head} {${body}})`
    }
    return `(${head} {${FILTER_PROP}})`
  })
}

/**
 * Safety net. After injection, scan for any node pattern that still carries a
 * variable or a non-global label but lacks a project_id predicate. Returns the
 * first offending interior, or null when the query is fully tenant-scoped.
 *
 * A global reference pattern is exempt only when the query is ITSELF anchored to
 * the caller's data (at least one scoped pattern). Without that, `MATCH (c:CVE)
 * RETURN c` would dump every CVE in the database - no tenant data, but still the
 * union of what every tenant has scanned. Mirrors find_unscoped_node_pattern in
 * the Python filter.
 */
export function findUnscopedNodePattern(cypher: string): string | null {
  const re = nodePatternRegex()
  const nodes: ParsedNode[] = []
  let m: RegExpExecArray | null
  while ((m = re.exec(cypher)) !== null) {
    const node = parseInterior(m[1])
    if (node) nodes.push({ ...node, interior: m[1].trim() } as ParsedNode & { interior: string })
  }
  const scopedOf = (n: ParsedNode) => !!n.props && /\bproject_id\b/.test(n.props)
  const hasAnchor = nodes.some(scopedOf)
  for (const node of nodes as (ParsedNode & { interior: string })[]) {
    if (scopedOf(node)) continue
    if (hasAnchor && isSimpleGlobalReference(node.labelStr)) continue // reference data, anchored
    if (node.varName || node.labels.length > 0) {
      return node.interior || '(anonymous)'
    }
  }
  return null
}

// A relationship carrying `*` (variable length), or a quantifier on a path /
// relationship group (`{n,m}`). The nodes such a pattern traverses have NO
// node pattern of their own, so injectProjectFilter never reaches them and
// findUnscopedNodePattern never sees them: a `[*]` hop from an exempt reference
// node (or between two of the caller's nodes) reaches other tenants' nodes.
// Comments, string literals and backticked identifiers are blanked first.
function codeOnly(cypher: string): string {
  return cypher
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')
    .replace(/`[^`]*`/g, 'x')
}

export function hasVariableLengthPath(cypher: string): boolean {
  const code = codeOnly(cypher)
  return /\[[^[\]]*\*[^[\]]*\]/.test(code) || /[)\]]\s*(?:<?-+>?)?\s*\{\s*\d/.test(code)
}

// Built-in FUNCTION namespaces a read may legitimately call. Everything else
// namespaced-and-called is refused - notably apoc, whose function forms
// (`apoc.cypher.runFirstColumn*`, `apoc.load.*`) run unscoped Cypher or fetch
// URLs and need no CALL, so the route's CALL block never saw them.
const SAFE_CALL_NAMESPACES = new Set([
  'point', 'duration', 'date', 'time', 'datetime', 'localtime', 'localdatetime', 'vector',
])
const NAMESPACED_CALL_RE = /([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(/g

/**
 * The first namespaced procedure OR function call that is not allowlisted, or
 * null. Runs on a normalised view (comments/strings blanked, backticks
 * unwrapped, whitespace around `.` removed) so `` `apoc`.`cypher`.`run` `` and
 * `apoc . cypher . run` cannot hide the name. Mirrors find_disallowed_call in
 * the Python filter.
 */
export function findDisallowedCall(cypher: string): string | null {
  const normalised = cypher
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\s*\.\s*/g, '.')
  let m: RegExpExecArray | null
  NAMESPACED_CALL_RE.lastIndex = 0
  while ((m = NAMESPACED_CALL_RE.exec(normalised)) !== null) {
    const name = m[1]
    const root = name.split('.', 1)[0].toLowerCase()
    if (SAFE_CALL_NAMESPACES.has(root)) continue
    return name
  }
  return null
}
