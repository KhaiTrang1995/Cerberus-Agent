/**
 * The numeric limits on Priority Board runs, with no imports so a client
 * component (the token modal's warnings) can quote them.
 */

/** The most findings one run reviews, whatever the project stores (U10). */
export const MAX_REVIEW_BUDGET = 1000

/**
 * The spacing and the daily cap on runs an MCP agent starts, per project and
 * across every token. A person's runs are not limited; an unattended agent's
 * are, because each run spends the owner's model budget and holds up version
 * switching, Recon Delta and Mute Rules while it works (product decision P3).
 */
export const MCP_RUN_COOLDOWN_MS = 30 * 60 * 1000
export const MCP_RUNS_PER_DAY = 12
