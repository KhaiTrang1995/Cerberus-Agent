import { describe, test, expect } from 'vitest'
import {
  clampRemaining, epochToIso, firstOfNextMonth, firstOfNextMonthUtc, humanize, intOrNull, isoOrNull, nextMidnight,
  nextUtcBoundary, num, safeJson, str,
} from './parse'

const NOW = new Date('2026-09-26T14:32:05.000Z')

describe('num', () => {
  test.each([
    [42, 42],
    [0, 0],
    [-1, -1],
    ['20,000,000', 20_000_000],
    ['0.000', 0],
    [' 1 234 ', 1234],
    ['110.00', 110],
  ])('%j -> %j', (input, expected) => {
    expect(num(input)).toBe(expected)
  })

  test.each([[''], [null], [undefined], ['abc'], [NaN], [Infinity], [{}], [[]], [true]])('%j -> null', input => {
    expect(num(input)).toBeNull()
  })

  test('intOrNull truncates', () => {
    expect(intOrNull('7.9')).toBe(7)
    expect(intOrNull('x')).toBeNull()
  })
})

describe('str', () => {
  test('non-empty trimmed strings only', () => {
    expect(str(' a ')).toBe('a')
    expect(str('  ')).toBeUndefined()
    expect(str(5)).toBeUndefined()
  })
})

describe('dates', () => {
  test('epoch seconds and milliseconds both land on the same instant', () => {
    expect(epochToIso(1787961600)).toBe('2026-08-29T00:00:00.000Z')
    expect(epochToIso(1787961600000)).toBe('2026-08-29T00:00:00.000Z')
    expect(epochToIso('1787961600')).toBe('2026-08-29T00:00:00.000Z')
    expect(epochToIso(0)).toBeNull()
    expect(epochToIso(null)).toBeNull()
  })

  test('zone-less "YYYY-MM-DD HH:mm:ss" and bare dates are read as UTC', () => {
    expect(isoOrNull('2022-04-11 06:06:54')).toBe('2022-04-11T06:06:54.000Z')
    expect(isoOrNull('2026-10-26')).toBe('2026-10-26T00:00:00.000Z')
    expect(isoOrNull('2027-12-31T23:59:59Z')).toBe('2027-12-31T23:59:59.000Z')
    expect(isoOrNull('2024-01-20T00:00:00+08:00')).toBe('2024-01-19T16:00:00.000Z')
  })

  test('empty, zero and garbage are null', () => {
    expect(isoOrNull('')).toBeNull()
    expect(isoOrNull(0)).toBeNull()
    expect(isoOrNull('not a date')).toBeNull()
    expect(isoOrNull(undefined)).toBeNull()
  })

  test('first of next month, UTC and in a provider offset', () => {
    expect(firstOfNextMonthUtc(NOW)).toBe('2026-10-01T00:00:00.000Z')
    // 00:00 on 1 Oct in UTC+8 is 16:00 on 30 Sep UTC.
    expect(firstOfNextMonth('+08:00', NOW)).toBe('2026-09-30T16:00:00.000Z')
    expect(firstOfNextMonthUtc(new Date('2026-12-15T00:00:00Z'))).toBe('2027-01-01T00:00:00.000Z')
  })

  test('next midnight in an offset, including when the offset already crossed the date', () => {
    expect(nextMidnight('Z', NOW)).toBe('2026-09-27T00:00:00.000Z')
    expect(nextMidnight('+08:00', NOW)).toBe('2026-09-26T16:00:00.000Z')
    // 17:00Z is already the 27th in UTC+8, so the next local midnight is the 28th.
    expect(nextMidnight('+08:00', new Date('2026-09-26T17:00:00Z'))).toBe('2026-09-27T16:00:00.000Z')
  })

  test('next UTC boundary per window', () => {
    expect(nextUtcBoundary('minute', NOW)).toBe('2026-09-26T14:33:00.000Z')
    expect(nextUtcBoundary('hour', NOW)).toBe('2026-09-26T15:00:00.000Z')
    expect(nextUtcBoundary('day', NOW)).toBe('2026-09-27T00:00:00.000Z')
    expect(nextUtcBoundary('month', NOW)).toBe('2026-10-01T00:00:00.000Z')
    expect(nextUtcBoundary('balance', NOW)).toBeNull()
    expect(nextUtcBoundary('lifetime', NOW)).toBeNull()
  })
})

describe('misc', () => {
  test('clampRemaining never goes negative (soft caps let used pass limit)', () => {
    expect(clampRemaining(25, 1829)).toBe(0)
    expect(clampRemaining(100, 16)).toBe(84)
    expect(clampRemaining(null, 1)).toBeNull()
  })

  test('safeJson', () => {
    expect(safeJson('{"a":1}')).toEqual({ a: 1 })
    expect(safeJson('Please check user credentials')).toBeUndefined()
  })

  test('humanize keeps common acronyms upper-case', () => {
    expect(humanize('api_requests_daily')).toBe('API requests daily')
    expect(humanize('files.public')).toBe('Files public')
    expect(humanize('monitored_ips')).toBe('Monitored IPs')
    expect(humanize('')).toBe('')
  })
})
