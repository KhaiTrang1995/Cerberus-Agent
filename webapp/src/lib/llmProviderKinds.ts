/**
 * Provider-type facts with no UI dependency, so server routes can import them
 * without pulling in the icon set that llmProviderPresets.ts carries.
 */

/**
 * Provider types whose key is not for a chat model (TypeSafe Jev). Every place
 * that treats "any provider row" as a chat LLM must skip them, or the token is
 * forwarded to the agent's model discovery and counted as a configured LLM.
 * Twin of NON_CHAT_PROVIDER_TYPES in agentic/llm_builder.py.
 */
export const NON_CHAT_PROVIDER_TYPES: ReadonlySet<string> = new Set(['jev'])

export const isChatProvider = (p: { providerType: string }): boolean =>
  !NON_CHAT_PROVIDER_TYPES.has(p.providerType)

/**
 * The Jev version every saved Jev row is pinned to. The recon hook thresholds
 * are calibrated against it, so moving on is a deliberate edit here and in
 * agentic/jev_client.py (JEV_MODEL), never an alias drift.
 */
export const JEV_MODEL = 'jev-1.13.0'
export const JEV_PROVIDER_NAME = 'TypeSafe AI (Jev)'
