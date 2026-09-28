/**
 * Import coercion for ScanJob.degradedSources (untrusted bundle input).
 *
 * A project export bundle is untrusted, so the import must accept only a
 * non-negative integer or null and reject everything else rather than writing a
 * hostile value into the column.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { coerceDegradedSources } from './route'

describe('coerceDegradedSources', () => {
  test('a non-negative integer passes through', () => {
    expect(coerceDegradedSources(0)).toBe(0)
    expect(coerceDegradedSources(3)).toBe(3)
  })

  test('a numeric string is parsed', () => {
    expect(coerceDegradedSources('5')).toBe(5)
  })

  test('a float is floored', () => {
    expect(coerceDegradedSources(2.9)).toBe(2)
  })

  test('null and undefined map to null (unknown)', () => {
    expect(coerceDegradedSources(null)).toBeNull()
    expect(coerceDegradedSources(undefined)).toBeNull()
  })

  test('a negative number is rejected', () => {
    expect(coerceDegradedSources(-1)).toBeNull()
  })

  test('a non-numeric string is rejected', () => {
    expect(coerceDegradedSources('abc')).toBeNull()
    expect(coerceDegradedSources('')).toBeNull() // Number('') is 0 — guard below
  })

  test('Infinity and NaN are rejected', () => {
    expect(coerceDegradedSources(Infinity)).toBeNull()
    expect(coerceDegradedSources(NaN)).toBeNull()
    expect(coerceDegradedSources('Infinity')).toBeNull()
  })

  test('objects and arrays are rejected', () => {
    expect(coerceDegradedSources({})).toBeNull()
    expect(coerceDegradedSources([1, 2])).toBeNull()
  })
})
