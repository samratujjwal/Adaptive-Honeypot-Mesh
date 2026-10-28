const FORBIDDEN = new Set(["password", "pwd", "token", "tokenValue", "credential", "credentials", "rawQuery", "rawBody", "rawTarget", "summary"]);

/**
 * Recursively remove secret and raw-attacker-data keys from a
 * document before it is sent over HTTP or Socket.IO. Never logs
 * removed values, only counts them if a logger is supplied.
 *
 * @param {unknown} value
 * @param {object} [stats]
 * @returns {unknown}
 */
export function sanitizeDoc(value, stats) {
  if (Array.isArray(value)) return value.map((item) => sanitizeDoc(item, stats));
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN.has(key)) {
      if (stats) stats.removed = (stats.removed || 0) + 1;
      continue;
    }
    out[key] = sanitizeDoc(child, stats);
  }
  return out;
}
