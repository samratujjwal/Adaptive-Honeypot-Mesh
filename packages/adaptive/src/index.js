import { correlateProfiles, mergeAttacker } from "./correlation.js";
import { decideStrategy } from "./strategy.js";
import { validateAttacker } from "./schema.js";

/**
 * Build a complete attacker document from profiles: correlate
 * then decide strategy. Correlation already attaches strategy.
 *
 * @param {object[]} profiles
 * @returns {object}
 */
export function buildAttackerProfile(profiles) {
  const attacker = correlateProfiles(profiles);
  attacker.strategy = decideStrategy(attacker);
  return attacker;
}

export { correlateProfiles, decideStrategy, validateAttacker, mergeAttacker };
