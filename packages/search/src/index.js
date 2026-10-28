export { createEsClient } from "./es-client.js";
export { buildTemplates } from "./templates.js";
export { eventsIndexName } from "./index-name.js";
export { createBulkIndexer } from "./bulk-indexer.js";
export { ensureTemplates } from "./setup.js";
export { getSessions } from "./session-store.js";
export { searchEvents, searchSessions, searchProfiles, searchAttackers, getAttackerByIp, getStats } from "./reads.js";
export { validateDocument } from "./validate.js";

/**
 * Fetch the existing attacker document for a source IP, or null.
 * Never throws: any failure returns null and the caller logs a code.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {string} sourceIp
 * @returns {Promise<object|null>}
 */
export async function getAttacker(es, prefix, sourceIp) {
  try {
    const response = await es.get({ index: `${prefix}-attackers`, id: sourceIp });
    const body = response && typeof response === "object" && "body" in response ? response.body : response;
    if (!body || !body.found) return null;
    return body._source || null;
  } catch {
    return null;
  }
}

/**
 * Index one attacker document, keyed by attackerId (sourceIp).
 *
 * @param {object} es
 * @param {string} prefix
 * @param {object} doc
 * @returns {Promise<void>}
 */
export async function indexAttacker(es, prefix, doc) {
  await es.index({ index: `${prefix}-attackers`, id: doc.attackerId, document: doc });
}
