/**
 * The shared `Node ID` column: normalising the id, and the copy-on-click cell.
 *
 * The id is what a user hands an external agent to point at one row, so the
 * failure that matters is a WRONG number, not a missing one: a lossy Integer
 * conversion or a stray non-numeric value would send the agent to a different
 * node. Everything unrecognised therefore renders as `-`, never as a guess.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/nodeId.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, act, cleanup } from '@testing-library/react'
import {
  NODE_ID_COLUMN,
  NODE_ID_KEY,
  NodeIdCell,
  NodeIdTh,
  formatNodeId,
  withNodeId,
} from './nodeId'

describe('formatNodeId', () => {
  test('passes a route projection (a digit string) through', () => {
    expect(formatNodeId('1234')).toBe('1234')
  })

  test('accepts a number, as GraphNode ids sometimes arrive', () => {
    expect(formatNodeId(0)).toBe('0')
    expect(formatNodeId(42)).toBe('42')
  })

  test('reads the driver Integer, including the high word', () => {
    expect(formatNodeId({ low: 7, high: 0 })).toBe('7')
    // Reading only `low` would silently turn this into 5.
    expect(formatNodeId({ low: 5, high: 1 })).toBe(String(2 ** 32 + 5))
    // `low` is signed 32-bit on the wire; -1 is 0xFFFFFFFF, not a negative id.
    expect(formatNodeId({ low: -1, high: 0 })).toBe(String(2 ** 32 - 1))
  })

  test('refuses anything that is not a node id rather than guessing', () => {
    for (const v of [null, undefined, '', 'abc', '12a', '4:db:12', -1, 1.5, NaN, {}, []]) {
      expect(formatNodeId(v)).toBeNull()
    }
  })
})

describe('the column descriptor', () => {
  test('is keyed on the row field the routes return', () => {
    expect(NODE_ID_KEY).toBe('nodeId')
    expect(NODE_ID_COLUMN).toEqual({ key: 'nodeId', header: 'Node ID' })
  })

  test('withNodeId puts it FIRST, so it is the leftmost column in exports too', () => {
    const cols = withNodeId([{ key: 'host', header: 'Host' }])
    expect(cols.map(c => c.key)).toEqual(['nodeId', 'host'])
  })
})

describe('NodeIdTh', () => {
  test('explains what the number is for', () => {
    const { container } = render(<table><thead><tr><NodeIdTh /></tr></thead></table>)
    const th = container.querySelector('th')!
    expect(th.textContent).toBe('Node ID')
    expect(th.getAttribute('title')).toMatch(/query_graph/)
    expect(th.getAttribute('title')).toMatch(/id\(n\)/)
  })
})

describe('NodeIdCell', () => {
  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.unstubAllGlobals()
    delete (document as { execCommand?: unknown }).execCommand
  })

  test('renders a dash for a row with no node', () => {
    const { container } = render(<NodeIdCell value={null} />)
    expect(container.textContent).toBe('-')
    expect(container.querySelector('button')).toBeNull()
  })

  test('copies the id and keeps the click away from the row', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const onRowClick = vi.fn()
    const { getByRole } = render(
      <div onClick={onRowClick}><NodeIdCell value="1234" /></div>,
    )
    const btn = getByRole('button', { name: 'Copy node ID 1234' })
    await act(async () => { fireEvent.click(btn) })
    expect(writeText).toHaveBeenCalledWith('1234')
    // Several tables expand or select a row on click; copying must do neither.
    expect(onRowClick).not.toHaveBeenCalled()
    expect(btn.textContent).toBe('copied')
  })

  test('goes back to showing the id after the confirmation', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
    const { getByRole } = render(<NodeIdCell value={{ low: 9, high: 0 }} />)
    const btn = getByRole('button')
    await act(async () => { fireEvent.click(btn) })
    expect(btn.textContent).toBe('copied')
    act(() => { vi.advanceTimersByTime(1300) })
    expect(btn.textContent).toBe('9')
  })

  /** jsdom has no execCommand; install one for the legacy-copy path. */
  function stubExecCommand(result: boolean) {
    const exec = vi.fn().mockReturnValue(result)
    Object.defineProperty(document, 'execCommand', { value: exec, configurable: true, writable: true })
    return exec
  }

  test('copies over plain http, where the Clipboard API does not exist', async () => {
    // A LAN deployment on http://192.168.x.x is not a secure context, so
    // navigator.clipboard is undefined. The id must still reach the clipboard.
    vi.stubGlobal('navigator', {})
    const exec = stubExecCommand(true)
    const { getByRole } = render(<NodeIdCell value="77" />)
    const btn = getByRole('button')
    await act(async () => { fireEvent.click(btn) })
    expect(exec).toHaveBeenCalledWith('copy')
    expect(btn.textContent).toBe('copied')
    expect(btn.getAttribute('aria-label')).toBe('Node ID 77 copied')
    // The hidden textarea is cleaned up.
    expect(document.querySelector('textarea')).toBeNull()
  })

  test('falls back when the Clipboard API rejects', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('not focused')) } })
    const exec = stubExecCommand(true)
    const { getByRole } = render(<NodeIdCell value="78" />)
    await act(async () => { fireEvent.click(getByRole('button')) })
    expect(exec).toHaveBeenCalledWith('copy')
    expect(getByRole('button').textContent).toBe('copied')
  })

  test('says so when nothing could copy, never a false "copied"', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
    stubExecCommand(false)
    const { getByRole } = render(<NodeIdCell value="55" />)
    const btn = getByRole('button')
    await act(async () => { fireEvent.click(btn) })
    expect(btn.textContent).toBe('copy failed')
    expect(btn.getAttribute('aria-label')).toBe('Could not copy node ID 55')
  })

  test('the confirmation does not follow the cell to another row', async () => {
    // Tables keyed by index reuse this cell for a different node after a sort
    // or refetch; the "copied" belongs to the id that was copied.
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
    const { getByRole, rerender } = render(<NodeIdCell value="100" />)
    await act(async () => { fireEvent.click(getByRole('button')) })
    expect(getByRole('button').textContent).toBe('copied')
    rerender(<NodeIdCell value="200" />)
    expect(getByRole('button').textContent).toBe('200')
    expect(getByRole('button').getAttribute('aria-label')).toBe('Copy node ID 200')
  })
})
