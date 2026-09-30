/**
 * The "Edited by an MCP agent" badge and the name filter on saved presets.
 *
 * The badge is the one mitigation for an agent holding preset:write: it can
 * store a configuration that a person applies later without reading it. If the
 * badge stops rendering, the library looks exactly as trustworthy as before the
 * agent wrote to it, and nothing else fails.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  useAlertModal: () => ({ dangerConfirm: vi.fn().mockResolvedValue(false) }),
}))

import { UserPresetDrawer } from './UserPresetDrawer'
import { PRESET_FILTER_THRESHOLD, filterPresetsByName, mcpEditedLabel } from './presetProvenance'

const preset = (i: number, over: Record<string, unknown> = {}) => ({
  id: `p${i}`, name: `Preset ${i}`, description: '', createdAt: '2026-09-29T08:00:00.000Z',
  updatedVia: 'ui', lastWriterTokenPrefix: null, ...over,
})

function mockPresets(list: unknown[]) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => list }))
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the badge text', () => {
  test('names the token prefix when an agent wrote last', () => {
    expect(mcpEditedLabel({ updatedVia: 'mcp', lastWriterTokenPrefix: 'rdmn_mcp_ab12cd34' }))
      .toBe('Edited by an MCP agent (rdmn_mcp_ab12cd34)')
    expect(mcpEditedLabel({ updatedVia: 'mcp' })).toBe('Edited by an MCP agent')
  })

  test('is absent when a person or an import wrote last', () => {
    expect(mcpEditedLabel({ updatedVia: 'ui' })).toBeNull()
    expect(mcpEditedLabel({ updatedVia: 'import' })).toBeNull()
    expect(mcpEditedLabel({})).toBeNull()
  })

  test('the filter matches names, ignoring case, and an empty query keeps all', () => {
    const list = [{ name: 'Stealth copy' }, { name: 'API deep' }]
    expect(filterPresetsByName(list, 'STEALTH')).toEqual([{ name: 'Stealth copy' }])
    expect(filterPresetsByName(list, '  ')).toEqual(list)
  })
})

describe('the My Presets drawer', () => {
  test('badges the agent-written preset, and only that one', async () => {
    mockPresets([
      preset(1, { updatedVia: 'mcp', lastWriterTokenPrefix: 'rdmn_mcp_ab12cd34' }),
      preset(2),
    ])
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    expect(await screen.findByText('Edited by an MCP agent (rdmn_mcp_ab12cd34)')).toBeTruthy()
    expect(screen.getAllByText(/Edited by an MCP agent/)).toHaveLength(1)
  })

  test('offers a name filter only past the threshold, and it filters', async () => {
    mockPresets(Array.from({ length: PRESET_FILTER_THRESHOLD }, (_, i) => preset(i)))
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    await screen.findByText('Preset 0')
    expect(screen.queryByLabelText('Filter presets by name')).toBeNull()
    cleanup()

    mockPresets(Array.from({ length: PRESET_FILTER_THRESHOLD + 2 }, (_, i) => preset(i)))
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    const filter = await screen.findByLabelText('Filter presets by name')
    fireEvent.change(filter, { target: { value: 'Preset 11' } })
    await waitFor(() => expect(screen.queryByText('Preset 3')).toBeNull())
    expect(screen.getByText('Preset 11')).toBeTruthy()
  })
})
