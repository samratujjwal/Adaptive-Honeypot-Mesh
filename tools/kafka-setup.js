import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createKafkaClient } from "../packages/bus/src/kafka-client.js";

/**
 * Idempotently create the Kafka topic. Accepts an injected client.
 *
 * @param {object} [deps]
 * @param {object} [deps.config]
 * @param {object} [deps.logger]
 * @param {object} [deps.kafkaClient]
 * @returns {Promise<{ created: boolean, partitions: number }>}
 */
export async function setupKafka(deps) {
  const cfg = (deps && deps.config) || config;
  const log = (deps && deps.logger) || logger;
  const client = (deps && deps.kafkaClient) || createKafkaClient({ config: cfg, logger: log });
  const admin = client.admin();
  try {
    if (typeof admin.connect === "function") await admin.connect();
    const topics = await admin.listTopics();
    if (topics.includes(cfg.KAFKA_TOPIC)) {
      const metadata = await admin.fetchTopicMetadata({ topics: [cfg.KAFKA_TOPIC] });
      const count = metadata && metadata.topics && metadata.topics[0] && metadata.topics[0].partitions ? metadata.topics[0].partitions.length : 0;
      return { created: false, partitions: count };
    }
    await admin.createTopics({ topics: [{ topic: cfg.KAFKA_TOPIC, numPartitions: 3, replicationFactor: 1 }] });
    return { created: true, partitions: 3 };
  } finally {
    try { if (typeof admin.disconnect === "function") await admin.disconnect(); } catch {}
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const timeout = setTimeout(() => {
    console.error("Kafka broker unreachable (timeout 5s)");
    process.exit(1);
  }, 5000);
  timeout.unref?.();
  setupKafka()
    .then((result) => {
      clearTimeout(timeout);
      if (result.created) console.log(`Created topic ${config.KAFKA_TOPIC} with ${result.partitions} partitions`);
      else console.log(`Topic ${config.KAFKA_TOPIC} already exists with ${result.partitions} partitions`);
      process.exit(0);
    })
    .catch((error) => {
      clearTimeout(timeout);
      console.error(`Kafka setup failed: ${error.message}`);
      process.exit(1);
    });
}
