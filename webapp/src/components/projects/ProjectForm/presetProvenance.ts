/**
 * What the preset lists show about who last wrote a saved preset, and how a
 * long library is filtered. Shared by the "My Presets" drawer and the preset
 * modal so the two lists cannot describe the same preset differently.
 *
 * The badge is the mitigation for the one thing a preset library adds: an MCP
 * agent holding preset:write can store a configuration that a person applies
 * later, usually without reading six hundred values. It stays visible for as
 * long as the agent's write is the latest one.
 */
export interface PresetProvenance {
  updatedVia?: string | null
  lastWriterTokenPrefix?: string | null
}

/** The badge text, or null when a person (or an import) wrote it last. */
export function mcpEditedLabel(preset: PresetProvenance): string | null {
  if (preset.updatedVia !== 'mcp') return null
  return preset.lastWriterTokenPrefix
    ? `Edited by an MCP agent (${preset.lastWriterTokenPrefix})`
    : 'Edited by an MCP agent'
}

/** Past this many saved presets the lists offer a name filter. */
export const PRESET_FILTER_THRESHOLD = 10

export function filterPresetsByName<T extends { name: string }>(presets: T[], query: string): T[] {
  const q = query.trim().toLowerCase()
  return q ? presets.filter(p => p.name.toLowerCase().includes(q)) : presets
}
