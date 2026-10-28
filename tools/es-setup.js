import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createEsClient } from "../packages/search/src/es-client.js";
import { ensureTemplates } from "../packages/search/src/setup.js";

/**
 * Set up Elasticsearch templates. Accepts an injected client.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {object} [deps.es]
 * @returns {Promise<object>}
 */
export async function setupEs(deps) {
  const cfg = (deps && deps.config) || config;
  const es = (deps && deps.es) || createEsClient({ config: cfg, logger });
  return ensureTemplates(es, { prefix: cfg.ES_INDEX_PREFIX });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  setupEs()
    .then((result) => {
      console.log(`Elasticsearch templates ready: events=${result.eventsTemplate}, sessions=${result.sessionsTemplate}, sessionsIndex=${result.sessionsIndex}`);
      process.exit(0);
    })
    .catch(() => {
      console.error(`Cannot reach Elasticsearch at ${config.ELASTICSEARCH_URL}. Is it running? (docker compose up -d elasticsearch)`);
      process.exit(1);
    });
}
