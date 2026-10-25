import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { validateEvent } from "./event.js";
import { logger } from "./logger.js";

/**
 * Create a file-backed event sink. Events are validated, then appended
 * as one JSON line each to <dir>/<service>.jsonl. Invalid events and
 * write failures are logged and return false instead of throwing.
 *
 * @param {{ dir: string, service: string }} options
 * @returns {{ emit: (event: unknown) => boolean, close: () => void }}
 */
export function createFileSink({ dir, service, logger: injectedLogger }) {
  const filePath = join(dir, `${service}.jsonl`);
  const log = injectedLogger || logger;
  return {
    emit(event) {
      const result = validateEvent(event);
      if (!result.ok) {
        log.error({ errors: result.errors }, "Invalid event rejected by sink");
        return false;
      }
      try {
        mkdirSync(dir, { recursive: true });
        appendFileSync(filePath, `${JSON.stringify(result.data)}\n`, "utf8");
        return true;
      } catch (error) {
        log.error({ error: error.message }, "Event sink write failed");
        return false;
      }
    },
    close() {},
  };
}
