import { Kafka, Partitioners } from "kafkajs";

/**
 * Create a thin kafkajs client. This is the only file that imports
 * kafkajs, so every other module can be tested with fakes.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @returns {{ producer: () => object, admin: () => object, consumer: (groupId: string) => object }}
 */
export function createKafkaClient({ config, logger }) {
  const log = logger || { info: () => {}, warn: () => {}, error: () => {} };
  const kafka = new Kafka({
    clientId: `${config.KAFKA_CLIENT_ID_PREFIX}-${config.NODE_ID}`,
    brokers: String(config.KAFKA_BROKERS).split(",").map((item) => item.trim()).filter(Boolean),
    connectionTimeout: 3000,
    requestTimeout: config.KAFKA_SEND_TIMEOUT_MS,
    retry: { initialRetryTime: 100, retries: 3 },
    logCreator: () => ({ namespace, level, label, log: entry }) => {
      const message = entry && entry.message ? entry.message : "";
      const text = `${label} ${message}`.trim();
      if (level === 1) { try { log.error({ namespace }, text); } catch {} }
      else if (level === 2) { try { log.warn({ namespace }, text); } catch {} }
      else { try { log.info({ namespace }, text); } catch {} }
    },
  });
  return {
    producer() {
      return kafka.producer({ createPartitioner: Partitioners.DefaultPartitioner });
    },
    admin() {
      return kafka.admin();
    },
    consumer(groupId) {
      return kafka.consumer({ groupId });
    },
  };
}
