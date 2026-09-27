import { describe, test, expect } from 'vitest'
import { computeHealth, meterHealth } from './health'
import { meter } from './results'

const m = (over: Partial<Parameters<typeof meter>[0]>) =>
  meter({ id: 'x', label: 'X', unit: 'credits', window: 'month', primary: true, ...over })

describe('meterHealth with a limit', () => {
  test('exhausted at 0 remaining', () => {
    expect(meterHealth(m({ limit: 100, remaining: 0 }))).toBe('exhausted')
  })
  test('low under 10% left', () => {
    expect(meterHealth(m({ limit: 100, remaining: 9 }))).toBe('low')
  })
  test('ok at exactly 10% left', () => {
    expect(meterHealth(m({ limit: 100, remaining: 10 }))).toBe('ok')
  })
  test('remaining derived from used when not reported', () => {
    expect(meterHealth(m({ limit: 500, used: 499 }))).toBe('low')
    expect(meterHealth(m({ limit: 500, used: 600 }))).toBe('exhausted')
  })
  test('nothing reported -> ok', () => {
    expect(meterHealth(m({ limit: 500 }))).toBe('ok')
  })
})

describe('meterHealth special cases', () => {
  test('limit 0 is "not in plan", never exhausted', () => {
    expect(meterHealth(m({ limit: 0, remaining: 0, used: 0 }))).toBe('ok')
  })
  test('a balance without a limit is only ever ok or exhausted', () => {
    expect(meterHealth(m({ window: 'balance', remaining: 3 }))).toBe('ok')
    expect(meterHealth(m({ window: 'balance', remaining: 0 }))).toBe('exhausted')
    expect(meterHealth(m({ window: 'balance', remaining: -2.5 }))).toBe('exhausted')
  })
})

describe('computeHealth', () => {
  test('the worst PRIMARY meter wins', () => {
    expect(computeHealth([m({ limit: 100, remaining: 50 }), m({ limit: 100, remaining: 5 })])).toBe('low')
    expect(computeHealth([m({ limit: 100, remaining: 5 }), m({ limit: 10, remaining: 0 })])).toBe('exhausted')
  })
  test('secondary meters never colour the row', () => {
    expect(computeHealth([
      m({ limit: 100, remaining: 80 }),
      m({ id: 'minute', window: 'minute', limit: 30, remaining: 0, primary: false }),
    ])).toBe('ok')
  })
  test('no meters -> ok', () => {
    expect(computeHealth([])).toBe('ok')
  })
})
