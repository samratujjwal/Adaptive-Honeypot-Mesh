import { sanitizeDoc } from "./sanitize.js";
import { searchEvents, searchProfiles, searchAttackers } from "../../../packages/search/src/reads.js";

/**
 * Create a live feed that polls Elasticsearch for documents newer
 * than the last seen timestamp, deduplicated by _id, and emits
 * them over Socket.IO. Polling stops cleanly on close.
 *
 * @param {object} deps
 * @param {object} deps.es
 * @param {string} deps.prefix
 * @param {object} deps.io
 * @param {number} deps.pollMs
 * @param {object} deps.logger
 * @param {Function} deps.getStats
 * @returns {{ start: () => void, close: () => void, pollOnce: () => Promise<void> }}
 */
export function createLiveFeed({ es, prefix, io, pollMs, logger, getStats }) {
  const log = logger || { warn: () => {}, error: () => {} };
  const seen = new Set();
  let lastSeen = new Date(0).toISOString();
  let timer = null;
  let closed = false;

  async function pollOnce() {
    if (closed) return;
    try {
      const [events, profiles, attackers] = await Promise.all([
        searchEvents(es, prefix, { limit: 200, offset: 0, from: lastSeen }),
        searchProfiles(es, prefix, { limit: 200, offset: 0 }),
        searchAttackers(es, prefix, { limit: 200, offset: 0 }),
      ]);
      const batches = [
        ["event", events.docs],
        ["profile", profiles.docs],
        ["attacker", attackers.docs],
      ];
      let newest = lastSeen;
      for (const [name, docs] of batches) {
        for (const doc of docs) {
          const id = doc.id || doc.sessionId || doc.attackerId || null;
          if (id && seen.has(id)) continue;
          if (id) seen.add(id);
          const stamp = doc.timestamp || doc.updatedAt || doc.lastSeen || null;
          if (stamp && stamp > newest) newest = stamp;
          io.emit(name, sanitizeDoc(doc));
        }
      }
      if (newest > lastSeen) lastSeen = newest;
    } catch {
      try { log.warn({ code: "LIVE_POLL" }, "Live feed poll failed"); } catch {}
    }
  }

  function start() {
    if (timer) return;
    timer = setInterval(() => { void pollOnce(); }, pollMs);
    if (timer.unref) timer.unref();
  }

  function close() {
    closed = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { start, close, pollOnce };
}
