/**
 * Unit tests for cross-tool corroboration of AI Attack Surface findings (§9).
 * Pure logic — imports the real function directly (no DB layer).
 */
import { describe, test, expect } from 'vitest'
import { corroborateAttackFindings, type RawAttackRow } from './aiAttackFindings'

function row(p: Partial<RawAttackRow>): RawAttackRow {
  return {
    source: 'garak', severity: 'medium', type: 'ai_attack_jailbreak',
    owaspLlmId: 'LLM01', asr: 0.5, trials: 4, payloadClass: 'garak-dan',
    transcriptRef: '/out/garak.jsonl', evidence: 'dan hit', probePackVersion: 'garak/0.15.1',
    target: 'http://h/v1/chat/completions', endpointPath: '/v1/chat/completions', ...p,
  }
}

describe('corroborateAttackFindings', () => {
  test('groups same (OWASP, target) across tools into one corroborated finding', () => {
    const out = corroborateAttackFindings([
      row({ source: 'garak', asr: 0.4, trials: 5, payloadClass: 'garak-dan' }),
      row({ source: 'promptfoo', asr: 0.7, trials: 3, payloadClass: 'promptfoo-pliny' }),
    ])
    expect(out).toHaveLength(1)
    const f = out[0]
    expect(f.sources).toEqual(['garak', 'promptfoo'])     // sorted, corroborated
    expect(f.maxAsr).toBe(0.7)                            // worst ASR across tools
    expect(f.totalTrials).toBe(8)                         // summed
    expect(f.payloadClasses.sort()).toEqual(['garak-dan', 'promptfoo-pliny'])
    expect(f.transcriptRefs).toHaveLength(1)              // both share the same ref here
  })

  test('different OWASP or different target stay separate', () => {
    const out = corroborateAttackFindings([
      row({ owaspLlmId: 'LLM01', target: 'http://a' }),
      row({ owaspLlmId: 'LLM02', target: 'http://a' }),   // different OWASP
      row({ owaspLlmId: 'LLM01', target: 'http://b' }),   // different target
    ])
    expect(out).toHaveLength(3)
  })

  test('severity is the max across the group; chip stripped from type', () => {
    const out = corroborateAttackFindings([
      row({ source: 'garak', severity: 'low' }),
      row({ source: 'pyrit', severity: 'high', type: 'ai_attack_jailbreak' }),
    ])
    expect(out[0].severity).toBe('high')
    expect(out[0].attackChip).toBe('jailbreak')
  })

  test('sorts by corroboration breadth, then ASR, then severity', () => {
    const out = corroborateAttackFindings([
      // single-tool, very high ASR
      row({ owaspLlmId: 'LLM02', target: 'http://x', source: 'giskard', asr: 0.9 }),
      // two-tool corroborated, lower ASR -> should rank FIRST (breadth wins)
      row({ owaspLlmId: 'LLM01', target: 'http://y', source: 'garak', asr: 0.3 }),
      row({ owaspLlmId: 'LLM01', target: 'http://y', source: 'promptfoo', asr: 0.3 }),
    ])
    expect(out[0].sources).toHaveLength(2)
    expect(out[0].owaspLlmId).toBe('LLM01')
    expect(out[1].owaspLlmId).toBe('LLM02')
  })

  test('null ASR / missing fields do not crash; trials default to 0', () => {
    const out = corroborateAttackFindings([
      row({ asr: null, trials: null, payloadClass: null, transcriptRef: null, probePackVersion: null }),
    ])
    expect(out[0].maxAsr).toBeNull()
    expect(out[0].totalTrials).toBe(0)
    expect(out[0].payloadClasses).toEqual([])
  })

  test('empty input -> empty output', () => {
    expect(corroborateAttackFindings([])).toEqual([])
  })

  test('same tool twice on the same vuln dedupes the source', () => {
    const out = corroborateAttackFindings([
      row({ source: 'promptfoo', payloadClass: 'promptfoo-beavertails' }),
      row({ source: 'promptfoo', payloadClass: 'promptfoo-harmbench' }),
    ])
    expect(out[0].sources).toEqual(['promptfoo'])
    expect(out[0].payloadClasses.sort()).toEqual(['promptfoo-beavertails', 'promptfoo-harmbench'])
  })

  test('nodeId is the representative (worst-ASR) row, matching the evidence shown', () => {
    // Input order puts the weaker row first, so a "first row wins" merge fails.
    const out = corroborateAttackFindings([
      row({ source: 'garak', asr: 0.2, evidence: 'weak', nodeId: '11' }),
      row({ source: 'promptfoo', asr: 0.8, evidence: 'strong', nodeId: '42' }),
    ])
    expect(out[0].evidence).toBe('strong')
    expect(out[0].nodeId).toBe('42')
  })

  test('a row without a nodeId yields null, not undefined', () => {
    expect(corroborateAttackFindings([row({})])[0].nodeId).toBeNull()
  })
})
