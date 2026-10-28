import { validateEvent } from "../../../packages/shared/src/event.js";
import { enrichEvent } from "../../../packages/enrich/src/enrich.js";
import { eventsIndexName } from "../../../packages/search/src/index-name.js";
import { createSessionAggregator } from "./sessions.js";
import { classify } from "../../../packages/mitre/src/classify.js";
import { createDeadLetter } from "./dead-letter.js";

/**
 * Create the processor: parse, validate, enrich, aggregate, index.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {object} [options.geoip]
 * @param {object} [options.indexer]
 * @param {object} [options.deadLetter]
 * @param {Function} [options.loadExisting]
 * @param {Function} [options.now]
 * @returns {{ processBatch: (messages: Array<object>) => Promise<object>, stats: () => object, flush: () => Promise<void>, close: () => Promise<void> }}
 */
export function createProcessor(options) {
  const config = options.config;
  const log = options.logger || { info: () => {}, warn: () => {}, error: () => {} };
  const indexer = options.indexer;
  const deadLetter = options.deadLetter || createDeadLetter({ file: config.PROCESSOR_DEAD_LETTER_FILE, maxBytes: config.PROCESSOR_DEAD_LETTER_MAX_BYTES });
  const aggregator = createSessionAggregator({
    cacheMax: config.PROCESSOR_SESSION_CACHE_MAX,
    idleMs: config.PROCESSOR_SESSION_IDLE_MS,
    loadExisting: options.loadExisting,
  });
  const stats = { consumed: 0, indexed: 0, rejectedByEs: 0, deadLettered: 0, sessionsUpdated: 0, esRetries: 0, sessionsIndexed: 0, mitreClassified: 0, lastError: null };
  let statsTimer = null;

  function deadLetterEntry(message, reason, raw) {
    return {
      receivedAt: new Date().toISOString(),
      topic: message.topic || config.KAFKA_TOPIC,
      partition: message.partition || 0,
      offset: message.offset || "0",
      reason,
      raw: String(raw || "").slice(0, 2048),
    };
  }

  async function processBatch(messages) {
    const docs = [];
    const changedSessions = new Map();
    const resolved = [];
    const validMessages = [];
    for (const message of messages) {
      stats.consumed += 1;
      const raw = message.value ? message.value.toString("utf8") : "";
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch {
        deadLetter.write(deadLetterEntry(message, "invalid_json", raw));
        stats.deadLettered += 1;
        resolved.push(message);
        continue;
      }
      const result = validateEvent(parsed);
      if (!result.ok) {
        deadLetter.write(deadLetterEntry(message, "schema", raw));
        stats.deadLettered += 1;
        resolved.push(message);
        continue;
      }
      const event = result.data;
      validMessages.push(message);
      const enrich = await enrichEvent(event, { geoip: options.geoip });
      const session = await aggregator.apply(event, enrich);
      if (session) changedSessions.set(session.sessionId, session);
      const body = { ...event };
      const mitreFull = classify(event);
      body.mitre = mitreFull.map((item) => ({ techniqueId: item.techniqueId, tactic: item.tactic, confidence: item.confidence }));
      if (mitreFull.length > 0) stats.mitreClassified += 1;
      body.enrich = { ipClass: enrich.ipClass, geo: enrich.geo };
      body.ingestedAt = new Date().toISOString();
      if (enrich.ipClass === "invalid") {
        body.source = { ...event.source, rawIp: event.source.ip };
        delete body.source.ip;
      } else {
        body.source = { ...event.source, ip: enrich.ip };
        if (event.source.ip !== enrich.ip) body.source.rawIp = event.source.ip;
      }
      docs.push({ index: eventsIndexName(config.ES_INDEX_PREFIX, event.timestamp), id: event.id, body });
    }
    for (const session of changedSessions.values()) {
      docs.push({ index: `${config.ES_INDEX_PREFIX}-sessions`, id: session.sessionId, body: session });
    }
    if (docs.length > 0 && indexer) {
      const outcome = await indexer.index(docs);
      stats.esRetries += outcome.retries || 0;
      if (outcome.rejected && outcome.rejected.length > 0) {
        stats.rejectedByEs += outcome.rejected.length;
        for (const failure of outcome.rejected) {
          const err = failure.error || {};
          const reasonText = err.reason || "";
          const withinMatch = reasonText.match(/within \[([^\]]+)\]/);
          const introducedMatch = reasonText.match(/introduction of \[([^\]]+)\]/);
          const field = withinMatch ? withinMatch[1] : (introducedMatch ? introducedMatch[1] : "");
          const reason = err.type ? `es:${err.type}${field ? `:${field}` : ""}` : "es_rejected";
          deadLetter.write({
            receivedAt: new Date().toISOString(),
            topic: config.KAFKA_TOPIC,
            partition: 0,
            offset: "0",
            reason,
            raw: JSON.stringify({ index: failure.doc.index, id: failure.doc.id }).slice(0, 2048),
          });
          stats.deadLettered += 1;
        }
      }
      if (outcome.remaining && outcome.remaining.length > 0) {
        // Indexer was closed mid-retry; those docs were not lost from
        // the caller's view, but offsets must not advance past them.
        // Return them as unresolved by excluding them from resolved.
        stats.lastError = "indexer closed with pending docs";
        return { resolved, docs, remaining: outcome.remaining, stats: { ...stats } };
      }
      stats.indexed += docs.length - (outcome.rejected ? outcome.rejected.length : 0);
      const sessionIndex = `${config.ES_INDEX_PREFIX}-sessions`;
      const sessionDocs = docs.filter((d) => d.index === sessionIndex).length;
      const rejectedSessions = outcome.rejected ? outcome.rejected.filter((f) => f.doc.index === sessionIndex).length : 0;
      stats.sessionsIndexed += sessionDocs - rejectedSessions;
      stats.sessionsUpdated += changedSessions.size;
    }
    resolved.push(...validMessages);
    return { resolved, docs, stats: { ...stats } };
  }

  async function flush() {
    // Sessions are indexed with each batch; nothing else to flush.
  }

  async function close() {
    if (statsTimer) clearInterval(statsTimer);
    if (indexer && typeof indexer.close === "function") await indexer.close();
  }

  return { processBatch, stats: () => ({ ...stats }), flush, close, aggregator };
}
