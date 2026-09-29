/**
 * Insights "Chain Findings": the Node ID column leads the table.
 *
 * Run: npx vitest run src/app/insights/components/TopFindingsTable.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { TopFindingsTable } from './TopFindingsTable'

afterEach(cleanup)

const row = (over: Record<string, unknown> = {}) => ({
  title: 'SQL injection', severity: 'high', findingType: 'sql_injection',
  evidence: null, confidence: null, phase: null, targetHost: '10.0.0.1', ...over,
})

describe('TopFindingsTable', () => {
  test('Node ID is the leftmost column, and a row without one shows "-"', () => {
    render(<TopFindingsTable isLoading={false} data={[row({ nodeId: '4711' }), row({ title: 'Other' })]} />)
    expect(screen.getAllByRole('columnheader')[0].textContent).toBe('Node ID')
    expect(screen.getByRole('button', { name: 'Copy node ID 4711' })).toBeTruthy()
    const other = screen.getAllByRole('row').find(r => r.textContent?.includes('Other'))!
    expect(other.querySelector('td')!.textContent).toBe('-')
  })
})
