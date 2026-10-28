import { fileURLToPath } from "node:url";
import { config } from "../../../packages/shared/src/config.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createEsClient } from "../../../packages/search/src/es-client.js";
import { createBulkIndexer } from "../../../packages/search/src/bulk-indexer.js";
import { createGeoip } from "../../../packages/enrich/src/geoip.js";
import { createProcessor } from "./processor.js";
import { createConsumer } from "./consumer.js";
import { ensureTemplates } from "../../../packages/search/src/setup.js";
import { waitForStartup, createStartupChecks } from "./startup.js";
import { createKafkaClient } from "../../../packages/bus/src/kafka-client.js";

/**
 * Start the processor. Runs itself only when executed directly.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {object} [deps.logger]
 * @param {object} [deps.es]
 * @param {object} [deps.kafkaClient]
 * @param {object} [deps.geoip]
 * @param {object} [deps.indexer]
 * @returns {Promise<{ processor: object, consumer: object, close: () => Promise<void> }>}
 */
export async function start(deps) {
  const cfg = (deps && deps.config) || config;
  const log = (deps && deps.logger) || logger;
  const es = (deps && deps.es) || createEsClient({ config: cfg, logger: log });
  const indexer = (deps && deps.indexer) || createBulkIndexer({ es, config: cfg, logger: log });
  const geoip = (deps && deps.geoip) || createGeoip({ enabled: cfg.GEOIP_ENABLED });
  const processor = createProcessor({ config: cfg, logger: log, geoip, indexer });
  const kafkaClient = (deps && deps.kafkaClient) || createKafkaClient({ config: cfg, logger: log });
  const waitFn = (deps && deps.waitForStartupFn) || waitForStartup;
  const ensureFn = (deps && deps.ensureTemplatesFn) || ensureTemplates;
  await waitFn({ checks: createStartupChecks({ es, kafkaClient }), logger: log, sleep: deps && deps.sleep });
  await ensureFn(es, { prefix: cfg.ES_INDEX_PREFIX });
  const consumer = createConsumer({ config: cfg, logger: log, kafkaClient, processor });
  let statsTimer = null;
  if (!deps || !deps.noStatsTimer) {
    statsTimer = setInterval(() => {
      try { log.info({ stats: processor.stats() }, "Processor stats"); } catch {}
    }, 30000);
    if (statsTimer.unref) statsTimer.unref();
  }
  async function close() {
    if (statsTimer) clearInterval(statsTimer);
    try { await consumer.stop(); } catch {}
    try { await processor.close(); } catch {}
  }
  return { processor, consumer, close };
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
    .then(async (result) => {
      instance = result;
      await result.consumer.start();
      console.log("Processor running");
    })
    .catch((error) => {
      console.error(`Processor failed to start: ${error.message}`);
      process.exit(1);
    });
}
