import { config } from "../../../packages/shared/src/config.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createSshHoneypot } from "./server.js";

async function main() {
  const sink = createFileSink({ dir: config.EVENT_DIR, service: "ssh" });
  const honeypot = createSshHoneypot({ config, sink });
  try {
    await honeypot.listen(config.SSH_PORT, config.BIND_HOST);
  } catch (error) {
    console.error(`SSH honeypot failed to start: ${error.message}`);
    process.exit(1);
  }
  const address = honeypot.address();
  logger.info({ address: address.address, port: address.port }, "SSH honeypot listening");
  console.log(`SSH honeypot listening on ${address.address}:${address.port}`);
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
  console.error(`SSH honeypot failed to start: ${error.message}`);
  process.exit(1);
});
