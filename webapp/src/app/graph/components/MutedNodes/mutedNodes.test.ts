/**
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  EMPTY_FILTERS, EXPORT_COLUMNS, exportRows, hasFilters, kindLabel, mutedByText, mutedQuery, stateText,
  type MutedRow,
} from './mutedNodes'
import { toGuardedCsv } from '../../utils/exportHelpers'

const row = (over: Partial<MutedRow> = {}): MutedRow => ({
  id: 'v1', label: 'Vulnerability', name: 'tech-detect:nginx', severity: 'info', source: 'nuclei',
  host: 'api.example.com', muted_at: '2026-09-23T10:00:00Z', muted_by: 'u1', muted_via: 'person',
  muted_reason: '', stale_since: null, triage_status: 'unreviewed', triage_reason: null,
  rule_kind: null, rule_id: null, rule_name: null, rule_deleted: false, ...over,
})

describe('the request', () => {
  test('pages, and sends only the filters that are set', () => {
    const url = mutedQuery('p 1', EMPTY_FILTERS, { offset: 50, limit: 50 })
    expect(url).toBe('/api/triage/muted?projectId=p+1&offset=50&limit=50')
    const filtered = new URL(`http://x${mutedQuery('p1',
      { label: 'Secret', mutedVia: 'deleted_rule', rule: 'rule:secret/abc123', token: '', search: '  aws ' },
      { offset: 0, limit: 50 }, true)}`)
    expect(Object.fromEntries(filtered.searchParams)).toEqual({
      projectId: 'p1', offset: '0', limit: '50', label: 'Secret', mutedVia: 'deleted_rule',
      rule: 'rule:secret/abc123', search: 'aws', facets: '1',
    })
  })

  test('knows when anything is filtered', () => {
    expect(hasFilters(EMPTY_FILTERS)).toBe(false)
    expect(hasFilters({ ...EMPTY_FILTERS, search: '   ' })).toBe(false)
    expect(hasFilters({ ...EMPTY_FILTERS, mutedVia: 'rule' })).toBe(true)
    expect(hasFilters({ ...EMPTY_FILTERS, token: 'rdmn_mcp_ab12cd34' })).toBe(true)
  })

  test('one token\'s agent mutes are asked for by prefix', () => {
    const url = new URL(`http://x${mutedQuery('p1',
      { ...EMPTY_FILTERS, mutedVia: 'mcp', token: 'rdmn_mcp_ab12cd34' }, { offset: 0, limit: 50 })}`)
    expect(url.searchParams.get('mutedVia')).toBe('mcp')
    expect(url.searchParams.get('token')).toBe('rdmn_mcp_ab12cd34')
  })
})

describe('how a row reads', () => {
  test('kind', () => {
    expect(kindLabel(row())).toBe('Vuln · nuclei')
    expect(kindLabel(row({ label: 'MalPackageFinding', source: '' }))).toBe('MalPackageFinding')
  })

  test('muted by a person, you, a rule, or a deleted rule', () => {
    expect(mutedByText(row(), 'u1')).toBe('you')
    expect(mutedByText(row({ muted_by: 'u2' }), 'u1')).toBe('u2')
    expect(mutedByText(row({ muted_via: 'rule', muted_by: 'rule:vuln.nuclei/k3f9a2', rule_name: 'Info' }), 'u1'))
      .toBe('Rule: Info')
    expect(mutedByText(row({
      muted_via: 'rule', muted_by: 'rule:vuln.nuclei/gone01', rule_deleted: true,
      muted_reason: 'Filter rule: Old rule',
    }), 'u1')).toBe('Rule (deleted): Filter rule: Old rule')
  })

  test('an agent\'s mute is never "you", even though it carries your id', () => {
    // muted_by is the token owner's user id: reading it as "you" would present
    // an agent's call as the operator's own judgement.
    const agent = row({ muted_via: 'mcp', muted_channel: 'mcp', muted_token: 'rdmn_mcp_ab12cd34' })
    expect(mutedByText(agent, 'u1')).toBe('Agent (MCP) · rdmn_mcp_ab12cd34')
    expect(mutedByText(row({ muted_via: 'mcp' }), 'u1')).toBe('Agent (MCP)')
  })

  test('a finding the scanner stopped reporting says so', () => {
    expect(stateText(row({ stale_since: '2026-09-20T00:00:00Z' }))).toBe('resolved: no longer reported')
    expect(stateText(row())).toBe('')
  })
})

describe('the export', () => {
  test('one column per field, and scanner text cannot become a formula', () => {
    const rows = exportRows([row({ name: '=HYPERLINK("http://x")', host: '@evil' })], 'u1')
    expect(Object.keys(rows[0])).toEqual([...EXPORT_COLUMNS])
    const csv = toGuardedCsv([...EXPORT_COLUMNS], rows)
    expect(csv).toContain(`"'=HYPERLINK(""http://x"")"`)
    expect(csv).toContain(`'@evil`)
    expect(csv).not.toMatch(/,=HYPERLINK/)
  })

  test('an agent mute exports as mcp, with its token, and never as a person', () => {
    const [out] = exportRows([row({ muted_via: 'mcp', muted_token: 'rdmn_mcp_ab12cd34', muted_reason: 'dev banner' })], 'u1')
    expect(out).toMatchObject({
      muted_by: 'Agent (MCP) · rdmn_mcp_ab12cd34', muted_via: 'mcp', token: 'rdmn_mcp_ab12cd34',
      rule: '', muted_reason: 'dev banner',
    })
    expect(exportRows([row()], 'u1')[0].token).toBe('')
  })

  test('the Node ID leads, as it does in the table, and is blank when the agent sent none', () => {
    expect(EXPORT_COLUMNS[0]).toBe('node_id')
    const [known, unknown] = exportRows([row({ node_id: '812' }), row({ id: 'v2' })], 'u1')
    expect(known).toMatchObject({ node_id: '812', id: 'v1' })
    expect(unknown.node_id).toBe('')
  })
})
