import { describe, test, expect } from 'vitest'
import { muteableLabel, muteKey } from './muteTarget'

describe('muteableLabel', () => {
  test('a finding label is returned whatever its position', () => {
    expect(muteableLabel(['Vulnerability'])).toBe('Vulnerability')
    expect(muteableLabel(['Extra', 'Secret'])).toBe('Secret')
  })

  test('asset and reference nodes are not muteable', () => {
    for (const label of ['IP', 'Port', 'Domain', 'Subdomain', 'Endpoint', 'CVE', 'Technology']) {
      expect(muteableLabel([label]), label).toBeNull()
    }
  })

  test('the Muted marker is never mistaken for the node type', () => {
    expect(muteableLabel(['Muted'])).toBeNull()
    expect(muteableLabel(['Muted', 'JsReconFinding'])).toBe('JsReconFinding')
  })
})

describe('muteKey', () => {
  test('findings are keyed on their stored id', () => {
    expect(muteKey('Vulnerability', { id: 'v-1', finding_id: 'other' })).toBe('v-1')
  })

  test('MalPackageFinding is keyed on finding_id, its uniqueness constraint', () => {
    expect(muteKey('MalPackageFinding', { id: 'not-it', finding_id: 'mf-1' })).toBe('mf-1')
  })

  test('a node without a usable key yields null rather than an empty mute', () => {
    expect(muteKey('Vulnerability', {})).toBeNull()
    expect(muteKey('Vulnerability', { id: '' })).toBeNull()
    expect(muteKey('Vulnerability', { id: 42 })).toBeNull()
    expect(muteKey('MalPackageFinding', { id: 'v-1' })).toBeNull()
  })
})
