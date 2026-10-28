import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createEsClient } from "../packages/search/src/es-client.js";

/**
 * Print Elasticsearch summary counts. Never prints payloads.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {object} [deps.es]
 * @param {Function} [deps.print]
 * @returns {Promise<object>}
 */
export async function summarizeEs(deps) {
  const cfg = (deps && deps.config) || config;
  const print = (deps && deps.print) || console.log;
  const es = (deps && deps.es) || createEsClient({ config: cfg, logger });
  const prefix = cfg.ES_INDEX_PREFIX;
  const eventsIndex = `${prefix}-events-*`;
  const sessionsIndex = `${prefix}-sessions`;
  const byService = await es.search({ index: eventsIndex, size: 0, aggs: { by_service: { terms: { field: "honeypot.service" } }, by_type: { terms: { field: "eventType" } }, by_ip: { terms: { field: "source.ip", size: 5 } }, by_honeytoken: { terms: { field: "payload.action" } }, oldest: { min: { field: "timestamp" } }, newest: { max: { field: "timestamp" } } } });
  const sessionsCount = await es.count({ index: sessionsIndex });
  const eventsCount = await es.count({ index: eventsIndex });
  const body = (response) => (response && response.body ? response.body : response);
  const eventsBody = body(byService);
  const sessionsBody = body(sessionsCount);
  const eventsBodyCount = body(eventsCount);
  const eventsTotal = eventsBodyCount && typeof eventsBodyCount.count === "number" ? eventsBodyCount.count : 0;
  const buckets = (name) => (eventsBody.aggregations && eventsBody.aggregations[name] && eventsBody.aggregations[name].buckets) ? eventsBody.aggregations[name].buckets : [];
  print(`Events by service: ${buckets("by_service").map((b) => `${b.key}=${b.doc_count}`).join(", ")}`);
  print(`Events by type: ${buckets("by_type").map((b) => `${b.key}=${b.doc_count}`).join(", ")}`);
  print(`Sessions: ${sessionsBody.count || 0}`);
  print(`Top source IPs: ${buckets("by_ip").map((b) => `${b.key}=${b.doc_count}`).join(", ")}`);
  print(`Honeytoken events by action: ${buckets("by_honeytoken").map((b) => `${b.key}=${b.doc_count}`).join(", ")}`);
  const oldest = eventsBody.aggregations && eventsBody.aggregations.oldest ? eventsBody.aggregations.oldest.value_as_string || eventsBody.aggregations.oldest.value : "";
  const newest = eventsBody.aggregations && eventsBody.aggregations.newest ? eventsBody.aggregations.newest.value_as_string || eventsBody.aggregations.newest.value : "";
  if (eventsTotal > 0 && (sessionsBody.count || 0) === 0) {
    print("WARNING: events exist but no sessions are indexed.");
  }
  print(`Oldest: ${oldest}`);
  print(`Newest: ${newest}`);
  return { byService: buckets("by_service"), byType: buckets("by_type"), sessions: sessionsBody.count || 0, events: eventsTotal, topIps: buckets("by_ip"), honeytoken: buckets("by_honeytoken"), oldest, newest };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  summarizeEs()
    .then(() => process.exit(0))
    .catch(() => {
      console.error(`Cannot reach Elasticsearch at ${config.ELASTICSEARCH_URL}. Is it running? (docker compose up -d elasticsearch)`);
      process.exit(1);
    });
}
