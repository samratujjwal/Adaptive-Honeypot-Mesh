import { appendFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Create a dead letter writer with a byte cap.
 *
 * @param {object} options
 * @param {string} options.file
 * @param {number} [options.maxBytes]
 * @param {Function} [options.now]
 * @returns {{ write: (entry: object) => boolean, count: () => number, bytes: () => number }}
 */
export function createDeadLetter(options) {
  const file = options.file;
  const maxBytes = options.maxBytes || 10485760;
  const now = options.now || (() => new Date().toISOString());
  let count = 0;
  let stopped = false;
  return {
    write(entry) {
      if (stopped) return false;
      try {
        const dir = dirname(file);
        mkdirSync(dir, { recursive: true });
        const currentSize = existsSync(file) ? statSync(file).size : 0;
        if (currentSize >= maxBytes) {
          stopped = true;
          return false;
        }
        const line = `${JSON.stringify(entry)}\n`;
        appendFileSync(file, line, "utf8");
        count += 1;
        if (currentSize + Buffer.byteLength(line, "utf8") >= maxBytes) stopped = true;
        return true;
      } catch {
        return false;
      }
    },
    count() { return count; },
    bytes() {
      try { return existsSync(file) ? statSync(file).size : 0; } catch { return 0; }
    },
  };
}
