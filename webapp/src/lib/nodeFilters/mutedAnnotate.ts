/**
 * Muted rows and facets, annotated from the project's Mute Rules document.
 *
 * Shared by the Muted Nodes route and the two MCP muted-findings tools, so the
 * table a person reads and the list an agent reads name the same rule, flag the
 * same deleted rule, and split who muted the same three ways.
 *
 * `muted_by` alone is two-valued (a user id, or `rule:...`). An agent's (MCP)
 * mute keeps its owner's user id there and is marked by `muted_channel`, so
 * anything that shows who muted a finding reads `mutedViaOf`, never
 * `isRuleMute` alone, or an agent's mute is presented as a person's.
 */
import prisma from '@/lib/prisma'
import {
  coerceDoc,
  describeMutedBy,
  isRuleMute,
  liveRuleMutedBy,
  type NodeFilterDoc,
} from '@/lib/nodeFilters/model'

export type MutedVia = 'person' | 'mcp' | 'rule'

/** The display prefix a token's mutes are stamped with; never the token. */
export const MUTED_TOKEN_PATTERN = /^rdmn_mcp_[0-9a-f]{8}$/

/**
 * The project's rule document, or an empty one. Rule names are an annotation:
 * failing the whole list over them would hide the mutes themselves.
 */
export async function loadMutedRuleDoc(projectId: string): Promise<NodeFilterDoc> {
  try {
    const row = await prisma.projectNodeFilter.findUnique({
      where: { projectId },
      select: { rules: true },
    })
    return coerceDoc(row?.rules)
  } catch (e) {
    console.error('[muted] could not load node filters:', e)
    return coerceDoc(null)
  }
}

/** Who muted a row, three-valued. Falls back to the raw fields for an older agent. */
export function mutedViaOf(row: { muted_via?: unknown; muted_by?: unknown; muted_channel?: unknown }): MutedVia {
  if (row.muted_via === 'rule' || isRuleMute(String(row.muted_by ?? ''))) return 'rule'
  if (row.muted_via === 'mcp' || row.muted_channel === 'mcp') return 'mcp'
  return 'person'
}

/** A Muted Nodes row with its rule named, or flagged as from a deleted rule. */
export function annotateMutedRow<T extends Record<string, unknown>>(doc: NodeFilterDoc, row: T) {
  const state = describeMutedBy(doc, String(row.muted_by ?? ''))
  return state.via === 'rule'
    ? { ...row, rule_kind: state.kind, rule_id: state.ruleId, rule_name: state.ruleName, rule_deleted: state.deleted }
    : { ...row, rule_kind: null, rule_id: null, rule_name: null, rule_deleted: false }
}

/** The agent's facets with each rule named, and flagged when it no longer exists. */
export function annotateMutedFacets(
  doc: NodeFilterDoc,
  facets: Record<string, unknown>,
): Record<string, unknown> & { rules: Record<string, unknown>[] } {
  const live = new Set(liveRuleMutedBy(doc))
  const rules = Array.isArray(facets.rules) ? (facets.rules as Record<string, unknown>[]) : []
  return {
    ...facets,
    rules: rules.map(r => {
      const state = describeMutedBy(doc, String(r.muted_by ?? ''))
      return {
        ...r,
        rule_name: state.via === 'rule' ? state.ruleName : null,
        rule_deleted: !live.has(String(r.muted_by ?? '')),
      }
    }),
  }
}
