/**
 * Which node a mute can target, and the key it is sent under.
 *
 * Shared by the browser (the node drawer decides whether to offer Mute at all)
 * and the server (`/api/triage/mute-by-graph-id` resolves a table row to this
 * key), so the two cannot disagree about what is muteable.
 */
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'

/**
 * The finding label among a node's labels, or null.
 *
 * Null means an asset or reference node (IP, Port, Domain, Endpoint, CVE, ...).
 * The graph refuses to mute those: they are context, and muting one would
 * orphan the real findings hanging off it (`MUTEABLE_LABELS` in
 * `graph_db/mixins/recon/triage_mixin.py`).
 */
export function muteableLabel(labels: readonly string[]): string | null {
  return labels.find(l => MUTEABLE_FINDING_LABELS.includes(l)) ?? null
}

/**
 * The stored property a mute matches the finding on, or null if it has none.
 *
 * MalPackageFinding's uniqueness constraint is on `finding_id`; every other
 * finding is keyed on `id`. Never Neo4j's internal id, which an import or a
 * version activation changes under a finding that is otherwise the same.
 */
export function muteKey(
  label: string,
  props: { id?: unknown; finding_id?: unknown },
): string | null {
  const key = label === 'MalPackageFinding' ? props.finding_id : props.id
  return typeof key === 'string' && key !== '' ? key : null
}
