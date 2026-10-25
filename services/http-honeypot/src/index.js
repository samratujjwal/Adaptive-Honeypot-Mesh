import { config } from "../../../packages/shared/src/config.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createLlmService } from "../../../packages/llm/src/service.js";
import { createHttpHoneypot } from "./server.js";

async function main() {
  const sink = createFileSink({ dir: config.EVENT_DIR, service: "http" });
  const llmService = createLlmService({ config, logger });
  const honeypot = createHttpHoneypot({ config, sink, llmService });
  try {
    await honeypot.listen(config.HTTP_PORT, config.BIND_HOST);
  } catch (error) {
    console.error(`HTTP honeypot failed to start: ${error.message}`);
    process.exit(1);
  }
  const address = honeypot.address();
  logger.info({ address: address.address, port: address.port }, "HTTP honeypot listening");
  console.log(`HTTP honeypot listening on ${address.address}:${address.port}`);
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await honeypot.close();
    sink.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error(`HTTP honeypot failed to start: ${error.message}`);
  process.exit(1);
});
