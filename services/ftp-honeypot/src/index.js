import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "../../../packages/shared/src/config.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createFtpHoneypot } from "./server.js";

function loadCredentials() {
  const here = dirname(fileURLToPath(import.meta.url));
  const path = join(here, "..", "config", "ftp-credentials.json");
  if (existsSync(path)) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8"));
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/**
 * Start the FTP honeypot. Runs itself only when executed directly.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} [deps.sink]
 * @param {object} [deps.logger]
 * @param {Array<{ username: string, password: string }>} [deps.credentials]
 * @returns {Promise<{ ftp: object, close: () => Promise<void> }>}
 */
export async function start(deps) {
  const cfg = (deps && deps.config) || config;
  const sink = (deps && deps.sink) || createFileSink({ dir: cfg.EVENT_DIR, service: "ftp" });
  const log = (deps && deps.logger) || logger;
  const credentials = (deps && deps.credentials) || loadCredentials();
  const ftp = createFtpHoneypot({ config: cfg, sink, logger: log, credentials });
  await ftp.listen(cfg.FTP_PORT, cfg.BIND_HOST);
  const address = ftp.address();
  try {
    log.info({ address: address.address, port: address.port }, "FTP honeypot listening");
  } catch {
    /* Ignore. */
  }
  async function close() {
    await ftp.close();
    try {
      sink.close();
    } catch {
      /* Ignore. */
    }
  }
  return { ftp, close };
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
      const address = result.ftp.address();
      console.log(`FTP honeypot listening on ${address.address}:${address.port}`);
    })
    .catch((error) => {
      console.error(`FTP honeypot failed to start: ${error.message}`);
      process.exit(1);
    });
}
