/**
 * The chip on an LLM provider card: the last report's verdict on that row's key,
 * and only while the row still holds the key the report checked.
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import { ApiUsageLlmChip } from './ApiUsageLlmChip'
import type { ApiUsageReportV1, KeyResult } from '@/lib/apiUsage/types'

afterEach(cleanup)

const CHECKED_HINT = '••••••••a1b2'

function report(result: Partial<KeyResult>): ApiUsageReportV1 {
  return {
    schemaVersion: 1, startedAt: '2026-09-26T14:32:00.000Z', finishedAt: '2026-09-26T14:32:05.000Z', durationMs: 900,
    counts: { services: 1, keys: 1, usage: 0, validNoUsage: 0, notChecked: 0, errors: 1, low: 0, exhausted: 0 },
    skippedEmpty: [],
    inventory: { 'llm:p1': { hint: CHECKED_HINT, extraKeys: 0 } },
    results: [{
      serviceId: 'llm-openai', serviceLabel: 'OpenAI', group: 'llm', field: 'llm:p1', keyRole: 'primary', keyIndex: 0,
      keyHint: CHECKED_HINT, outcome: 'error', error: { kind: 'invalid_key', httpStatus: 401, message: 'Incorrect API key' },
      meters: [], costNote: '', dashboardUrl: '', docsUrl: '', endpoint: 'GET api.openai.com/v1/models',
      checkedAt: '2026-09-26T14:32:01.000Z', latencyMs: 80, ...result,
    }],
  }
}

describe('ApiUsageLlmChip', () => {
  test('shows the verdict for the key the report checked', () => {
    const { container } = render(<ApiUsageLlmChip report={report({})} providerId="p1" hint={CHECKED_HINT} />)
    expect(container.textContent).toContain('Key rejected')
  })

  test('REGRESSION llm-chip-stale-verdict: a key replaced after the report does not inherit its verdict', () => {
    const { container } = render(<ApiUsageLlmChip report={report({})} providerId="p1" hint="••••••••c3d4" />)
    expect(container.textContent).not.toContain('Key rejected')
    expect(container.textContent).toContain('Key changed since the last check')
  })

  test('no row for this provider in the report: nothing', () => {
    const { container } = render(<ApiUsageLlmChip report={report({})} providerId="other" hint={CHECKED_HINT} />)
    expect(container.textContent).toBe('')
  })
})
