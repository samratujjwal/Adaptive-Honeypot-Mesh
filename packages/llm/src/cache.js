import { createHash } from "node:crypto";

const TIME_DEPENDENT = new Set(["date", "uptime", "w", "who", "last", "top", "watch", "ping"]);

/**
 * Check whether a command is time-dependent and must never be
 * cached. Matching is on the first word, case-insensitive.
 *
 * @param {string} command
 * @returns {boolean}
 */
export function isTimeDependent(command) {
  const first = String(command || "").trim().split(/\s+/)[0] || "";
  return TIME_DEPENDENT.has(first.toLowerCase());
}

/**
 * Build a cache key from persona, hostname, user, cwd and command.
 * The command is normalized by trimming and collapsing whitespace.
 *
 * @param {object} parts
 * @returns {string} sha256 hex key
 */
export function capNotes(notes) {
  if (!Array.isArray(notes)) return [];
  const capped = notes.map((note) => String(note).trim().slice(0, 120)).filter((note) => note !== "");
  return capped.slice(-10);
}

export function notesDigest(notes) {
  const capped = capNotes(notes);
  return createHash("sha256").update(JSON.stringify(capped), "utf8").digest("hex");
}

export function makeKey(parts) {
  const normalized = String(parts.command || "").trim().replace(/\s+/g, " ");
  let digest = "";
  if (typeof parts.notesDigest === "string") digest = parts.notesDigest;
  else if (Array.isArray(parts.notes)) digest = notesDigest(parts.notes);
  else digest = notesDigest([]);
  const payload = JSON.stringify({
    personaId: parts.personaId,
    hostname: parts.hostname,
    user: parts.user,
    cwd: parts.cwd,
    command: normalized,
    notesDigest: digest,
  });
  return createHash("sha256").update(payload, "utf8").digest("hex");
}

/**
 * Create an LRU-ish cache with TTL. Static and fallback results
 * and time-dependent commands are never stored.
 *
 * @param {object} options
 * @param {number} options.max
 * @param {number} options.ttlMs
 * @param {() => number} [options.now]
 * @returns {{ get: (key: string) => unknown, set: (key: string, value: unknown, opts?: object) => boolean, makeKey: typeof makeKey }}
 */
export function createCache({ max, ttlMs, now }) {
  const clock = typeof now === "function" ? now : Date.now;
  const store = new Map();
  return {
    makeKey,
    get(key) {
      const entry = store.get(key);
      if (!entry) return null;
      if (clock() >= entry.expiresAt) {
        store.delete(key);
        return null;
      }
      store.delete(key);
      store.set(key, entry);
      return entry.value;
    },
    set(key, value, opts = {}) {
      if (opts.fallback === true) return false;
      if (value && typeof value === "object" && value.fallback === true) return false;
      if (value && typeof value === "object" && value.meta && value.meta.fallback === true) return false;
      if (opts.command && isTimeDependent(opts.command)) return false;
      if (value && typeof value === "object" && typeof value.command === "string" && isTimeDependent(value.command)) return false;
      store.delete(key);
      store.set(key, { value, expiresAt: clock() + ttlMs });
      while (store.size > max) {
        const oldest = store.keys().next().value;
        store.delete(oldest);
      }
      return true;
    },
  };
}
