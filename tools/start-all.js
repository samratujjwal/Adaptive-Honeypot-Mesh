import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createLlmService } from "../packages/llm/src/service.js";
import { createSinkFactory } from "../packages/bus/src/sink-factory.js";
import { createKafkaClient } from "../packages/bus/src/kafka-client.js";
import { start as startSsh } from "../services/ssh-honeypot/src/index.js";
import { start as startHttp } from "../services/http-honeypot/src/index.js";
import { start as startFtp } from "../services/ftp-honeypot/src/index.js";

/**
 * Start SSH, HTTP and FTP in the same process, sharing one LLM
 * service instance. Runs itself only when executed directly.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {object} [deps.logger]
 * @param {object} [deps.llmService]
 * @returns {Promise<{ services: object, llmService: object, close: () => Promise<void> }>}
 */
export async function startAll(deps) {
  const cfg = (deps && deps.config) || config;
  const log = (deps && deps.logger) || logger;
  const llmService = (deps && deps.llmService) || createLlmService({ config: cfg, logger: log });
  let factory = (deps && deps.sinkFactory) || null;
  let localFactory = false;
  if (!factory) {
    const kafkaClient = (deps && deps.createKafkaClient) ? deps.createKafkaClient({ config: cfg, logger: log }) : (cfg.KAFKA_ENABLED ? createKafkaClient({ config: cfg, logger: log }) : undefined);
    factory = createSinkFactory({ config: cfg, logger: log, kafkaClient });
    localFactory = true;
  }
  try { log.info({ kafka: cfg.KAFKA_ENABLED ? "enabled" : "disabled" }, `Kafka streaming: ${cfg.KAFKA_ENABLED ? "enabled" : "disabled"}`); } catch {}
  const ssh = await startSsh({ config: cfg, logger: log, llmService, sinkFactory: factory });
  const http = await startHttp({ config: cfg, logger: log, llmService, sinkFactory: factory });
  const ftp = await startFtp({ config: cfg, logger: log, sinkFactory: factory });
  const services = { ssh: ssh.ssh, http: http.http, ftp: ftp.ftp };
  async function close() {
    await ftp.close();
    await http.close();
    await ssh.close();
    if (localFactory) {
      try { await factory.close(); } catch {}
    }
  }
  try {
    log.info({ ssh: ssh.ssh.address(), http: http.http.address(), ftp: ftp.ftp.address() }, "All honeypots listening");
  } catch {
    /* Ignore. */
  }
  return { services, llmService, close, sinkFactory: factory };
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
  startAll()
    .then((result) => {
      instance = result;
      console.log(`SSH honeypot listening on ${result.services.ssh.address().address}:${result.services.ssh.address().port}`);
      console.log(`HTTP honeypot listening on ${result.services.http.address().address}:${result.services.http.address().port}`);
      console.log(`FTP honeypot listening on ${result.services.ftp.address().address}:${result.services.ftp.address().port}`);
    })
    .catch((error) => {
      console.error(`Failed to start honeypots: ${error.message}`);
      process.exit(1);
    });
}
