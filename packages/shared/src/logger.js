import pino from "pino";
import { config } from "./config.js";

const REDACT_PATHS = [
  "apiKey",
  "GEMINI_API_KEY",
  "password",
  "authorization",
  "headers.authorization",
  "*.apiKey",
  "*.GEMINI_API_KEY",
  "*.password",
  "*.authorization",
  "*.headers.authorization",
];

/**
 * Create a pino logger with secret redaction. The same redaction rules
 * apply to the shared default logger and to loggers made for tests.
 *
 * @param {{ level?: string, destination?: NodeJS.WritableStream }} [options]
 * @returns {import("pino").Logger}
 */
export function createLogger(options = {}) {
  const { level = config.LOG_LEVEL, destination } = options;
  if (destination) {
    return pino({ level, redact: { paths: REDACT_PATHS, censor: "[REDACTED]" } }, destination);
  }
  return pino({ level, redact: { paths: REDACT_PATHS, censor: "[REDACTED]" } });
}

export const logger = createLogger();
