import { Client } from "@elastic/elasticsearch";

/**
 * Create an Elasticsearch client. This is the only file importing
 * @elastic/elasticsearch.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @returns {object}
 */
export function createEsClient({ config, logger }) {
  const log = logger || { info: () => {}, warn: () => {}, error: () => {} };
  return new Client({
    node: config.ELASTICSEARCH_URL,
    requestTimeout: config.PROCESSOR_ES_TIMEOUT_MS,
    maxRetries: 0,
    sniffOnStart: false,
    sniffOnConnectionFault: false,
    log: "error",
  });
}
