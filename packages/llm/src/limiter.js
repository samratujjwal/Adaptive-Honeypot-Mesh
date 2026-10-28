import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Format a timestamp as a YYYY-MM-DD date in America/Los_Angeles,
 * because Gemini quotas reset at Pacific midnight.
 *
 * @param {number} ms
 * @returns {string} date key
 */
export function pacificDate(ms) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Los_Angeles",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(ms));
}

/**
 * Create a rate limiter with a sliding RPM window, a daily counter
 * persisted to usageFile, and a per-session cap. Never waits.
 *
 * @param {object} options
 * @param {number} options.rpm
 * @param {number} options.dailyLimit
 * @param {number} options.sessionLimit
 * @param {() => number} [options.now]
 * @param {string} [options.usageFile]
 * @param {object} [options.logger]
 * @returns {{ tryAcquire: (sessionId: string) => { ok: boolean, reason: string | null }, release: (sessionId: string) => void }}
 */
export function createLimiter({ rpm, dailyLimit, sessionLimit, now, usageFile, logger }) {
  const clock = typeof now === "function" ? now : Date.now;
  const log = logger || { error: (...args) => console.error(...args) };
  let timestamps = [];
  let dailyDate = pacificDate(clock());
  let dailyCount = 0;
  const sessionCounts = new Map();

  function loadFromFile() {
    if (!usageFile) return;
    try {
      const parsed = JSON.parse(readFileSync(usageFile, "utf8"));
      if (parsed && parsed.date === pacificDate(clock()) && typeof parsed.count === "number") {
        dailyCount = parsed.count;
        dailyDate = parsed.date;
      }
    } catch {
      /* Missing or unreadable file: continue from memory. */
    }
  }

  function saveToFile() {
    if (!usageFile) return;
    try {
      mkdirSync(dirname(usageFile), { recursive: true });
      writeFileSync(usageFile, JSON.stringify({ date: dailyDate, count: dailyCount }) + "\n", "utf8");
    } catch (error) {
      try {
        log.error({ error: error.message }, "LLM usage file write failed");
      } catch {
        /* Logging must never crash the limiter. */
      }
    }
  }

  loadFromFile();

  function tryAcquire(sessionId) {
    const current = clock();
    const today = pacificDate(current);
    if (today !== dailyDate) {
      dailyDate = today;
      dailyCount = 0;
    }
    timestamps = timestamps.filter((time) => current - time < 60000);
    if (timestamps.length >= rpm) return { ok: false, reason: "rpm" };
    if (dailyCount >= dailyLimit) return { ok: false, reason: "daily" };
    const sessionCount = sessionCounts.get(sessionId) || 0;
    if (sessionCount >= sessionLimit) return { ok: false, reason: "session" };
    timestamps.push(current);
    dailyCount += 1;
    sessionCounts.set(sessionId, sessionCount + 1);
    saveToFile();
    return { ok: true, reason: null };
  }

  function release(sessionId) {
    if (timestamps.length > 0) timestamps.pop();
    if (dailyCount > 0) dailyCount -= 1;
    const sessionCount = sessionCounts.get(sessionId) || 0;
    if (sessionCount > 0) sessionCounts.set(sessionId, sessionCount - 1);
  }

  return { tryAcquire, release };
}
