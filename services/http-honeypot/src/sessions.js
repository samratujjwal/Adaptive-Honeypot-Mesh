import { randomUUID } from "node:crypto";

/**
 * Create a per-IP session store. The same session id is returned
 * while requests keep arriving within the window, a new id is
 * issued after the window expires. Max 10000 tracked IPs, oldest
 * evicted first.
 *
 * @param {object} options
 * @param {number} options.windowMs
 * @param {number} [options.maxIps]
 * @param {() => number} [options.now]
 * @returns {{ getSessionId: (ip: string) => string, size: () => number }}
 */
export function createSessionStore({ windowMs, maxIps, now }) {
  const max = typeof maxIps === "number" ? maxIps : 10000;
  const clock = typeof now === "function" ? now : Date.now;
  const store = new Map();

  function getSessionId(ip) {
    const current = clock();
    const existing = store.get(ip);
    if (existing && current - existing.lastSeen <= windowMs) {
      existing.lastSeen = current;
      return existing.sessionId;
    }
    const sessionId = randomUUID();
    if (!existing && store.size >= max) {
      let oldestIp = null;
      let oldestTime = Infinity;
      for (const [key, value] of store.entries()) {
        if (value.lastSeen < oldestTime) {
          oldestTime = value.lastSeen;
          oldestIp = key;
        }
      }
      if (oldestIp !== null) store.delete(oldestIp);
    }
    store.set(ip, { sessionId, lastSeen: current });
    return sessionId;
  }

  return { getSessionId, size: () => store.size };
}

/**
 * Create a token store for login cookies. Max 1000 tokens total,
 * 1 hour TTL, oldest evicted first.
 *
 * @param {object} [options]
 * @param {() => number} [options.now]
 * @returns {{ create: (ip: string, username: string, type: string) => string, validate: (token: string, ip: string, type: string) => string | null, size: () => number }}
 */
export function createTokenStore({ now } = {}) {
  const clock = typeof now === "function" ? now : Date.now;
  const store = new Map();
  const TTL_MS = 3600000;
  const MAX_TOKENS = 1000;

  function create(ip, username, type) {
    const token = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "").slice(0, 16);
    if (store.size >= MAX_TOKENS) {
      let oldestToken = null;
      let oldestTime = Infinity;
      for (const [key, value] of store.entries()) {
        if (value.created < oldestTime) {
          oldestTime = value.created;
          oldestToken = key;
        }
      }
      if (oldestToken !== null) store.delete(oldestToken);
    }
    store.set(token, { ip, username, type, created: clock() });
    return token;
  }

  function validate(token, ip, type) {
    if (!token) return null;
    const entry = store.get(token);
    if (!entry) return null;
    if (entry.type !== type) return null;
    if (entry.ip !== ip) return null;
    if (clock() - entry.created > TTL_MS) {
      store.delete(token);
      return null;
    }
    return entry.username;
  }

  return { create, validate, size: () => store.size };
}
