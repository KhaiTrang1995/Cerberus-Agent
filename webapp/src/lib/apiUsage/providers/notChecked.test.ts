import { describe, test, expect } from 'vitest'
import * as notChecked from './notChecked'
import type { ProbeDef } from '../types'

const ALL = Object.values(notChecked) as ProbeDef[]

describe('not-checked entries', () => {
  test('never call anything: no run(), kind none, a reason and a message', () => {
    for (const p of ALL) {
      expect(p.run, p.id).toBeUndefined()
      expect(p.kind, p.id).toBe('none')
      expect(p.notCheckedReason, p.id).toBeTruthy()
      expect(p.notCheckedMessage, p.id).toBeTruthy()
      expect(p.dashboardUrl, p.id).toMatch(/^https:\/\//)
    }
  })

  test('the reasons the plan assigns', () => {
    const reason = Object.fromEntries(ALL.map(p => [p.id, p.notCheckedReason]))
    expect(reason).toEqual({
      hunterhow: 'costs_credits',
      'google-cse': 'costs_credits',
      ngrok: 'no_api',
      chisel: 'no_api',
      docker: 'needs_username',
      jenkins: 'host_per_scan',
      elasticsearch: 'host_per_scan',
      git: 'host_per_scan',
    })
  })

  test('Google needs its CX as a required companion; the CSE sunset is on the row', () => {
    expect(notChecked.googleCseProbe.companions).toEqual([{ field: 'googleApiCx', required: true }])
    expect(notChecked.googleCseProbe.notCheckedMessage).toMatch(/1 January 2027/)
  })
})
