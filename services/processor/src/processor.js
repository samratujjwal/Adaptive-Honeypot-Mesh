import { validateEvent } from "../../../packages/shared/src/event.js";
import { enrichEvent } from "../../../packages/enrich/src/enrich.js";
import { eventsIndexName } from "../../../packages/search/src/index-name.js";
import { createSessionAggregator } from "./sessions.js";
import { classify } from "../../../packages/mitre/src/classify.js";
import { createDeadLetter } from "./dead-letter.js";
import { classifyProfile } from "../../../packages/profile/src/classify.js";
import { buildAttackerProfile, mergeAttacker, validateAttacker } from "../../../packages/adaptive/src/index.js";

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
  const stats = { consumed: 0, indexed: 0, rejectedByEs: 0, deadLettered: 0, sessionsUpdated: 0, esRetries: 0, sessionsIndexed: 0, mitreClassified: 0, profilesWritten: 0, profileLlmUsed: 0, profileLlmCached: 0, profileLlmFallback: 0, profileErrors: 0, attackersWritten: 0, attackerErrors: 0, lastError: null };
  const attackerProfilesByIp = new Map();
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
      const mitreFullEarly = classify(event);
      const eventWithMitre = { ...event, mitre: mitreFullEarly.map((item) => ({ techniqueId: item.techniqueId, tactic: item.tactic, confidence: item.confidence })) };
      const session = await aggregator.apply(eventWithMitre, enrich);
      if (session) changedSessions.set(session.sessionId, session);
      const body = { ...event };
      const mitreFull = mitreFullEarly;
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
    // Profile writing: best-effort, on close or eviction only, never blocks offsets.
    try {
      const profiled = options._profiledIds || (options._profiledIds = new Set());
      const toProfile = [];
      for (const session of changedSessions.values()) {
        if (session.closed && !profiled.has(session.sessionId)) toProfile.push({ session, signals: aggregator.getSignals ? aggregator.getSignals(session.sessionId) : null });
      }
      if (aggregator.takeEvicted) {
        for (const evicted of aggregator.takeEvicted()) {
          if (!profiled.has(evicted.session.sessionId)) toProfile.push(evicted);
        }
      }
      for (const item of toProfile) {
        try {
          const session = item.session;
          const signals = item.signals || {};
          const input = {
            sessionId: session.sessionId, service: session.service, nodeId: session.nodeId, sourceIp: session.sourceIp,
            firstSeen: session.firstSeen, lastSeen: session.lastSeen, durationMs: session.durationMs, closed: session.closed,
            eventCount: session.eventCount, commandCount: session.commandCount, authAttempts: session.authAttempts, authSuccess: session.authSuccess,
            commands: session.commands, mitreTechniqueIds: signals.mitreTechniqueIds || [], mitreTactics: signals.mitreTactics || [],
            userAgents: signals.userAgents || [], fileTransferOut: Boolean(signals.fileTransferOut), fileTransferOutSensitive: Boolean(signals.fileTransferOutSensitive), transferService: session.service,
            totalTypingMs: signals.totalTypingMs || 0, totalKeystrokes: signals.totalKeystrokes || 0, backspaceCount: signals.backspaceCount || 0,
            httpLoginAttempts: signals.httpLoginAttempts || 0,
          };
          const rulesProfile = classifyProfile(input);
          const rulesIntent = rulesProfile.classification.intent;
          let profile = rulesProfile;
          if (options.enhanceProfile) {
            profile = await options.enhanceProfile(profile, input);
          }
          profiled.add(session.sessionId);
          if (indexer) {
            const outcome = await indexer.index([{ index: `${config.ES_INDEX_PREFIX}-profiles`, id: session.sessionId, body: profile }]);
            if (outcome.remaining && outcome.remaining.length > 0) throw new Error("profile indexer closed");
            if (outcome.rejected && outcome.rejected.length > 0) throw new Error("profile rejected");
            stats.profilesWritten += 1;
            if (profile.llm && profile.llm.used) stats.profileLlmUsed += 1;
            if (profile.llm && profile.llm.cached) stats.profileLlmCached += 1;
            if (profile.llm && profile.llm.fallback) stats.profileLlmFallback += 1;
          } else {
            stats.profilesWritten += 1;
          }
          try {
            const correlationProfile = { ...profile, rulesIntent };
            const ip = profile.sourceIp;
            const existing = attackerProfilesByIp.get(ip) || [];
            if (!existing.some((entry) => entry.sessionId === profile.sessionId)) existing.push(correlationProfile);
            attackerProfilesByIp.set(ip, existing);
            let attacker = buildAttackerProfile(existing);
            if (options.getAttackerFn) {
              try {
                const stored = await options.getAttackerFn(ip);
                if (stored) attacker = mergeAttacker(stored, attacker);
              } catch {
                try { logger.warn({ code: "ATTACKER_READ" }, "Attacker read failed, using in-memory profiles only"); } catch {}
              }
            }
            if (!validateAttacker(attacker)) throw new Error("attacker validation failed");
            if (options.indexAttackerFn) {
              await options.indexAttackerFn(attacker);
            } else if (indexer) {
              const attackerOutcome = await indexer.index([{ index: `${config.ES_INDEX_PREFIX}-attackers`, id: attacker.attackerId, body: attacker }]);
              if (attackerOutcome.remaining && attackerOutcome.remaining.length > 0) throw new Error("attacker indexer closed");
              if (attackerOutcome.rejected && attackerOutcome.rejected.length > 0) throw new Error("attacker rejected");
            }
            stats.attackersWritten += 1;
          } catch {
            stats.attackerErrors += 1;
            try { logger.warn({ code: "ATTACKER_WRITE" }, "Attacker update failed"); } catch {}
          }
        } catch {
          stats.profileErrors += 1;
        }
      }
    } catch {
      stats.profileErrors += 1;
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
