import type { TableRow } from '../../hooks/useTableData'
import type { CellAccessor } from '../../utils/columnFilters'
import { UPDATED_AT_PROP, nodeUpdatedAt } from '../RedZoneTables/updatedAt'
import { NODE_ID_KEY, formatNodeId } from '../RedZoneTables/nodeId'

/**
 * The Node Inspector's binding to the shared column-filter engine.
 *
 * Everything schema-free lives in `utils/columnFilters` and is re-exported
 * here so existing call sites keep one import. What stays is the part that is
 * specific to this table: its column ids, and how a `TableRow` yields a value
 * for one of them.
 */
export * from '../../utils/columnFilters'

// ---------------------------------------------------------------------------
// Column identity
// ---------------------------------------------------------------------------

export const NAME_COLUMN_ID = 'name'
export const IN_COLUMN_ID = 'connectionsIn'
export const OUT_COLUMN_ID = 'connectionsOut'
export const UPDATED_AT_COLUMN_ID = `prop:${UPDATED_AT_PROP}`
// The internal graph id, not a property: many labels (CVE, Secret, ...) carry
// their own `id` property, which stays its own `prop:id` column.
export const NODE_ID_COLUMN_ID = NODE_ID_KEY

export function propColumnId(key: string): string {
  return `prop:${key}`
}

/**
 * The value a filter sees for a given column. Mirrors the table's accessors
 * exactly - if these ever disagree, a row would be filtered on one value and
 * display another.
 */
export const getCellValue: CellAccessor<TableRow> = (row, columnId) => {
  if (columnId === NAME_COLUMN_ID) return row.node.name
  if (columnId === NODE_ID_COLUMN_ID) return formatNodeId(row.node.id) ?? undefined
  if (columnId === IN_COLUMN_ID) return row.connectionsIn.length
  if (columnId === OUT_COLUMN_ID) return row.connectionsOut.length
  // The pinned `Updated` column falls back through several property names, so
  // the filter has to resolve it the same way the cell does.
  if (columnId === UPDATED_AT_COLUMN_ID) return nodeUpdatedAt(row.node.properties)
  if (columnId.startsWith('prop:')) return row.node.properties[columnId.slice(5)]
  return undefined
}
