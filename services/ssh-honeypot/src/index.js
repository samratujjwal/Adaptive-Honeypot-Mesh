import { fileURLToPath } from "node:url";
import { config } from "../../../packages/shared/src/config.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createSinkFactory } from "../../../packages/bus/src/sink-factory.js";
import { createKafkaClient } from "../../../packages/bus/src/kafka-client.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createLlmService } from "../../../packages/llm/src/service.js";
import { createSshHoneypot } from "./server.js";

/**
 * Start the SSH honeypot. Runs itself only when executed directly.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} [deps.sink]
 * @param {object} [deps.logger]
 * @param {object} [deps.llmService]
 * @returns {Promise<{ ssh: object, close: () => Promise<void> }>}
 */
export async function start(deps) {
  const cfg = (deps && deps.config) || config;
  let localFactory = null;
  let sink = deps && deps.sink;
  if (!sink && deps && deps.sinkFactory) sink = deps.sinkFactory.create("ssh");
  if (!sink) {
    if (cfg.KAFKA_ENABLED) {
      localFactory = createSinkFactory({ config: cfg, logger: (deps && deps.logger) || logger, kafkaClient: createKafkaClient({ config: cfg, logger: (deps && deps.logger) || logger }) });
      sink = localFactory.create("ssh");
    } else {
      sink = createFileSink({ dir: cfg.EVENT_DIR, service: "ssh" });
    }
  }
  const log = (deps && deps.logger) || logger;
  const llmService = (deps && deps.llmService) || createLlmService({ config: cfg, logger: log });
  const honeypot = createSshHoneypot({ config: cfg, sink, llmService });
  await honeypot.listen(cfg.SSH_PORT, cfg.BIND_HOST);
  const address = honeypot.address();
  try {
    log.info({ address: address.address, port: address.port }, "SSH honeypot listening");
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
    if (localFactory) {
      try { await localFactory.close(); } catch {}
    }
  }
  return { ssh: honeypot, close };
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
      const address = result.ssh.address();
      console.log(`SSH honeypot listening on ${address.address}:${address.port}`);
    })
    .catch((error) => {
      console.error(`SSH honeypot failed to start: ${error.message}`);
      process.exit(1);
    });
}
