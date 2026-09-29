/**
 * Cross-cutting smoke test for the `Node ID` column.
 *
 * The contract is "every table whose rows are graph nodes shows the node's id,
 * leftmost" - the same shape of promise as the `Updated` column, and it decays
 * the same way: a sheet added next month renders, filters and exports fine,
 * and simply has no id to hand an external agent.
 *
 * It reads the SOURCE of the routes as well as the components, because a
 * column wired in the UI against a route that never projects the id is a
 * column of dashes. The agent half (MCP query_graph returning `nodeId` on each
 * node) is pinned in agentic/tests/test_graph_exec_node_id.py.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/nodeIdWiring.smoke.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const DIR = __dirname
const SRC = join(DIR, '../../../..')
const REDZONE_API = join(DIR, '../../../api/analytics/redzone')

const source = (path: string) => readFileSync(path, 'utf8')

const TABLE_FILES = readdirSync(DIR)
  .filter(f => f.endsWith('.tsx') && !f.includes('.test.'))
  .filter(f => source(join(DIR, f)).includes('<RedZoneTableShell'))

const ROUTE_FILES = readdirSync(REDZONE_API)
  .filter(d => statSync(join(REDZONE_API, d)).isDirectory())
  .map(d => join(REDZONE_API, d, 'route.ts'))
  .filter(p => {
    try { return statSync(p).isFile() } catch { return false }
  })

/** Every `<thead>...</thead>` block in a component's source. */
function theadBlocks(src: string): string[] {
  return src.split('<thead>').slice(1).map(s => s.split('</thead>')[0])
}

describe('the file lists are not accidentally empty', () => {
  test('tables were found', () => expect(TABLE_FILES.length).toBeGreaterThanOrEqual(16))
  test('routes were found', () => expect(ROUTE_FILES.length).toBeGreaterThanOrEqual(17))
})

describe('every Red Zone route returns the id', () => {
  test.each(ROUTE_FILES.map(p => [p.split('/redzone/')[1], p]))(
    '%s projects id() as a string `AS nodeId`',
    (_name, path) => {
      // A string, so the value never passes through the driver's Integer or a
      // JS float on its way to the cell. The id() argument varies with the row
      // shape: a variable, `coalesce(v, p)`, `head(collect(ip))`, `min(...)`.
      const s = source(path as string)
      expect(s).toMatch(/toString\((min\()?id\(/)
      expect(s).toMatch(/AS nodeId/)
    },
  )

  test.each(ROUTE_FILES.map(p => [p.split('/redzone/')[1], p]))(
    '%s maps it onto the row it returns',
    (_name, path) => {
      expect(source(path as string)).toMatch(/nodeId:/)
    },
  )

  test.each(ROUTE_FILES.map(p => [p.split('/redzone/')[1], p]))(
    '%s never points a row at an untenanted reference node',
    (_name, path) => {
      // An external agent resolves the id with `MATCH (n) WHERE id(n) = X`, and
      // the tenant filter makes that bare pattern unable to reach CVE /
      // MitreData / Capec nodes, so such an id would look dead.
      const s = source(path as string)
      const NOT_VARS = new Set(['coalesce', 'head', 'collect', 'min', 'max', 'id', 'toString',
        'null', 'case', 'when', 'then', 'else', 'end', 'size', 'is', 'not', 'and', 'or'])
      for (const line of s.split('\n').filter(l => /AS nodeId/.test(l))) {
        const expr = line.slice(line.indexOf('id('), line.indexOf('AS nodeId'))
        for (const [, v] of expr.matchAll(/\b([A-Za-z_]\w*)\b/g)) {
          if (NOT_VARS.has(v.toLowerCase())) continue
          expect(s, `${path}: ${v}`).not.toMatch(new RegExp(`\\(${v}:(CVE|MitreData|Capec)\\b`))
        }
      }
    },
  )
})

describe('every Red Zone table renders the column leftmost', () => {
  test.each(TABLE_FILES)('%s renders the header and the cell', file => {
    const s = source(join(DIR, file))
    expect(s).toContain('NodeIdTh')
    expect(s).toContain('<NodeIdCell')
  })

  test.each(TABLE_FILES.filter(f => f !== 'AiTables.tsx'))(
    '%s puts Node ID first in every header row',
    file => {
      const blocks = theadBlocks(source(join(DIR, file)))
      expect(blocks.length).toBeGreaterThan(0)
      for (const block of blocks) {
        const first = block.match(/<NodeIdTh\b|<UpdatedAtTh\b|<th\b/)
        expect(first?.[0], `${file}: first header`).toBe('<NodeIdTh')
      }
    },
  )

  test('AiTables prepends it to every sheet', () => {
    // Its headers are generated from a column list, so the order lives there.
    expect(source(join(DIR, 'AiTables.tsx'))).toMatch(/\[NODE_ID_CELL, \.\.\.sheet\.columns/)
  })

  test.each(TABLE_FILES.filter(f => f !== 'AiTables.tsx'))(
    '%s declares it FIRST for filtering and export',
    file => {
      const s = source(join(DIR, file))
      expect(s).toMatch(/NODE_ID_COLUMN|withNodeId/)
      // Every column list that carries it starts with it.
      for (const m of s.matchAll(/=\s*\[\s*([A-Z_]+|\{)/g)) {
        if (m[1] === 'NODE_ID_COLUMN') continue
        const listStart = s.slice(m.index!, m.index! + 400)
        if (/NODE_ID_COLUMN/.test(listStart.split('\n]')[0])) {
          expect(m[1], `${file}: a column list has NODE_ID_COLUMN but not first`).toBe('NODE_ID_COLUMN')
        }
      }
    },
  )
})

describe('the node-backed tables outside the Red Zone are wired', () => {
  const CASES: Array<[string, string]> = [
    ['Node Inspector', 'app/graph/components/NodeDetailsTable/NodeDetailsTable.tsx'],
    ['All Nodes', 'app/graph/components/DataTable/DataTable.tsx'],
    ['JS Recon', 'app/graph/components/JsReconTable/JsReconTable.tsx'],
    ['Priority Board', 'app/graph/components/Triage/TriageTable.tsx'],
    ['Muted Nodes', 'app/graph/components/MutedNodes/MutedNodesTable.tsx'],
    ['Recon Delta', 'app/graph/components/ReconDelta/ReconDeltaTable.tsx'],
    ['Insights / Chain Findings', 'app/insights/components/TopFindingsTable.tsx'],
    ['AI Attack Surface / Findings', 'app/ai-attack-surface/page.tsx'],
  ]

  test.each(CASES)('%s renders the cell', (_name, rel) => {
    expect(source(join(SRC, rel))).toContain('<NodeIdCell')
  })

  test('JS Recon renders it in every node-backed sub-table', () => {
    // 13 sub-tables; Subdomains is the one whose rows are plain strings.
    const s = source(join(SRC, 'app/graph/components/JsReconTable/JsReconTable.tsx'))
    expect((s.match(/<NodeIdCell/g) ?? []).length).toBeGreaterThanOrEqual(12)
  })

  test('the Priority Board leads with it, ahead of the rank', () => {
    const s = source(join(SRC, 'app/graph/components/Triage/TriageTable.tsx'))
    const head = theadBlocks(s)[0]
    expect(head.indexOf('NodeIdTh')).toBeGreaterThan(-1)
    expect(head.indexOf('NodeIdTh')).toBeLessThan(head.indexOf('<th>#</th>'))
  })

  test('their data sources project the id', () => {
    const jsRecon = source(join(SRC, 'app/api/js-recon/[projectId]/download/route.ts'))
    expect((jsRecon.match(/AS nodeId/g) ?? []).length).toBeGreaterThanOrEqual(3)
    expect(source(join(SRC, 'app/api/analytics/attack-chains/route.ts'))).toContain('AS nodeId')
    expect(source(join(SRC, 'app/api/ai-attack-surface/[projectId]/findings/route.ts')))
      .toContain('toString(id(v)) AS nodeId')
    // The Priority Board and Muted Nodes read the agent's triage mixin.
    const triage = source(join(SRC, '../../graph_db/mixins/recon/triage_mixin.py'))
    expect((triage.match(/AS node_id/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })
})
