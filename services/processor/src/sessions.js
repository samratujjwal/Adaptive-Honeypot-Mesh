import { createHash } from "node:crypto";

function uniqCapped(list, value, max, maxLen) {
  const text = String(value || "").slice(0, maxLen);
  if (!text) return list;
  if (!list.includes(text)) list.push(text);
  return list.slice(0, max);
}

function newSession(event, enrich) {
  return {
    sessionId: event.sessionId,
    service: event.honeypot.service,
    nodeId: event.honeypot.nodeId,
    sourceIp: enrich ? enrich.ip : (event.source && event.source.ip ? String(event.source.ip) : ""),
    sourceIpClass: enrich ? enrich.ipClass : "invalid",
    geo: enrich ? enrich.geo : null,
    firstSeen: event.timestamp,
    lastSeen: event.timestamp,
    durationMs: 0,
    closed: false,
    closeReason: null,
    eventCount: 0,
    eventTypeCounts: {},
    authAttempts: 0,
    authSuccess: 0,
    usernames: [],
    commandCount: 0,
    commands: [],
    httpRequestCount: 0,
    httpPaths: [],
    ftpCommandCount: 0,
    filesTransferred: [],
    llmResponses: 0,
    honeytokens: [],
    seenEventIds: [],
    updatedAt: event.timestamp,
  };
}

/**
 * Create a session aggregator with an in-memory cache and restart reload.
 *
 * @param {object} options
 * @param {number} [options.cacheMax]
 * @param {number} [options.idleMs]
 * @param {Function} [options.now]
 * @param {Function} [options.loadExisting]
 * @returns {{ apply: (event: object, enrich: object) => Promise<object|null>, get: (id: string) => object|undefined, flush: () => Array<object>, evictIdle: () => void }}
 */
export function createSessionAggregator(options = {}) {
  const cacheMax = options.cacheMax || 10000;
  const idleMs = options.idleMs || 1800000;
  const now = options.now || Date.now;
  const loadExisting = options.loadExisting || (async () => new Map());
  const cache = new Map();
  const lastAccess = new Map();

  function evictIdle() {
    const current = now();
    for (const [id, last] of lastAccess) {
      if (current - last > idleMs) {
        cache.delete(id);
        lastAccess.delete(id);
      }
    }
    while (cache.size > cacheMax) {
      let oldestId = null;
      let oldestTime = Infinity;
      for (const [id, last] of lastAccess) {
        if (last < oldestTime) { oldestTime = last; oldestId = id; }
      }
      if (!oldestId) break;
      cache.delete(oldestId);
      lastAccess.delete(oldestId);
    }
  }

  async function apply(event, enrich) {
    if (!event || !event.sessionId) return null;
    let session = cache.get(event.sessionId);
    if (!session) {
      const existing = await loadExisting([event.sessionId]);
      const loaded = existing && typeof existing.get === "function" ? existing.get(event.sessionId) : null;
      session = loaded ? { ...loaded, seenEventIds: Array.isArray(loaded.seenEventIds) ? [...loaded.seenEventIds] : [] } : newSession(event, enrich);
      cache.set(event.sessionId, session);
    }
    if (session.seenEventIds && session.seenEventIds.includes(event.id)) return null;
    session.seenEventIds = [...(session.seenEventIds || []), event.id].slice(-200);
    session.eventCount += 1;
    session.eventTypeCounts[event.eventType] = (session.eventTypeCounts[event.eventType] || 0) + 1;
    if (event.timestamp < session.firstSeen) session.firstSeen = event.timestamp;
    if (event.timestamp > session.lastSeen) session.lastSeen = event.timestamp;
    session.updatedAt = event.timestamp;
    const payload = event.payload || {};
    if (event.eventType === "auth_attempt") {
      session.authAttempts += 1;
      if (payload.success) session.authSuccess += 1;
      if (payload.username) session.usernames = uniqCapped(session.usernames, payload.username, 20, 200);
    }
    if (event.eventType === "command") {
      session.commandCount += 1;
      if (payload.command) session.commands = uniqCapped(session.commands, payload.command, 50, 200);
    }
    if (event.eventType === "http_request") {
      session.httpRequestCount += 1;
      if (payload.path) session.httpPaths = uniqCapped(session.httpPaths, payload.path, 50, 200);
    }
    if (event.eventType === "ftp_command") {
      session.ftpCommandCount += 1;
    }
    if (event.eventType === "file_transfer") {
      const file = {
        direction: payload.direction || "download",
        path: String(payload.savedAs || payload.url || "").slice(0, 200),
        size: payload.size || 0,
        sha256: payload.sha256 ? String(payload.sha256).slice(0, 64) : "",
      };
      session.filesTransferred = [...session.filesTransferred, file].slice(0, 20);
    }
    if (event.eventType === "llm_response") {
      session.llmResponses += 1;
    }
    if (event.eventType === "honeytoken") {
      const hit = { tokenId: payload.tokenId || "", kind: payload.kind || "", action: payload.action || "" };
      const key = `${hit.tokenId}|${hit.kind}|${hit.action}`;
      const existingKeys = new Set(session.honeytokens.map((h) => `${h.tokenId}|${h.kind}|${h.action}`));
      if (!existingKeys.has(key)) session.honeytokens = [...session.honeytokens, hit].slice(0, 20);
    }
    if (event.eventType === "connection_close") {
      session.closed = true;
      session.closeReason = payload.reason || null;
      session.durationMs = Math.max(0, Date.parse(session.lastSeen) - Date.parse(session.firstSeen));
    }
    lastAccess.set(event.sessionId, now());
    evictIdle();
    return session;
  }

  function get(id) {
    return cache.get(id);
  }

  function flush() {
    return [...cache.values()];
  }

  return { apply, get, flush, evictIdle, cache };
}
