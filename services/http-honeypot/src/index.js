import { fileURLToPath } from "node:url";
import { config } from "../../../packages/shared/src/config.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createLlmService } from "../../../packages/llm/src/service.js";
import { createHttpHoneypot } from "./server.js";

/**
 * Start the HTTP honeypot. Runs itself only when executed directly.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} [deps.sink]
 * @param {object} [deps.logger]
 * @param {object} [deps.llmService]
 * @returns {Promise<{ http: object, close: () => Promise<void> }>}
 */
export async function start(deps) {
  const cfg = (deps && deps.config) || config;
  const sink = (deps && deps.sink) || createFileSink({ dir: cfg.EVENT_DIR, service: "http" });
  const log = (deps && deps.logger) || logger;
  const llmService = (deps && deps.llmService) || createLlmService({ config: cfg, logger: log });
  const honeypot = createHttpHoneypot({ config: cfg, sink, llmService });
  await honeypot.listen(cfg.HTTP_PORT, cfg.BIND_HOST);
  const address = honeypot.address();
  try {
    log.info({ address: address.address, port: address.port }, "HTTP honeypot listening");
  } catch {
    /* Ignore. */
  }
  async function close() {
    await honeypot.close();
    try {
      sink.close();
    } catch {
      /* Ignore. */
    }
  }
  return { http: honeypot, close };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  let instance = null;
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    if (instance) await instance.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  start()
    .then((result) => {
      instance = result;
      const address = result.http.address();
      console.log(`HTTP honeypot listening on ${address.address}:${address.port}`);
    })
    .catch((error) => {
      console.error(`HTTP honeypot failed to start: ${error.message}`);
      process.exit(1);
    });
}
