import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createKafkaClient } from "../packages/bus/src/kafka-client.js";

/**
 * Tail the Kafka topic, printing one summary line per message.
 * Never prints payloads or passwords.
 *
 * @param {object} [deps]
 * @param {number} [deps.limit]
 * @param {object} [deps.kafkaClient]
 * @param {object} [deps.config]
 * @param {Function} [deps.print]
 * @returns {Promise<{ count: number }>}
 */
export async function tailKafka(deps) {
  const limit = (deps && deps.limit) || 20;
  const cfg = (deps && deps.config) || config;
  const log = (deps && deps.logger) || logger;
  const print = (deps && deps.print) || console.log;
  const client = (deps && deps.kafkaClient) || createKafkaClient({ config: cfg, logger: log });
  const groupId = `kafka-tail-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
  const consumer = client.consumer(groupId);
  let count = 0;
  let idleTimer = null;
  let done = false;
  const finish = async () => {
    if (done) return;
    done = true;
    if (idleTimer) clearTimeout(idleTimer);
    try { if (typeof consumer.disconnect === "function") await consumer.disconnect(); } catch {}
  };
  try {
    if (typeof consumer.connect === "function") await consumer.connect();
    if (typeof consumer.subscribe === "function") await consumer.subscribe({ topic: cfg.KAFKA_TOPIC, fromBeginning: true });
    await new Promise((resolve) => {
      const resetIdle = () => {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(async () => { await finish(); resolve(); }, 10000);
        idleTimer.unref?.();
      };
      resetIdle();
      const run = consumer.run({
        eachMessage: async ({ message }) => {
          if (done) return;
          try {
            const event = JSON.parse(message.value.toString("utf8"));
            const timestamp = event.timestamp || "";
            const service = event.honeypot && event.honeypot.service ? event.honeypot.service : "";
            const eventType = event.eventType || "";
            const sessionShort = String(event.sessionId || "").slice(0, 8);
            const ip = event.source && event.source.ip ? event.source.ip : "";
            print(`${timestamp} ${service} ${eventType} ${sessionShort} ${ip}`);
          } catch {
            /* Skip unparseable messages without printing them. */
          }
          count += 1;
          if (count >= limit) { await finish(); resolve(); return; }
          resetIdle();
        },
      });
      if (run && typeof run.then === "function") run.catch(() => { finish(); resolve(); });
    });
  } finally {
    await finish();
  }
  return { count };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const limit = Number(process.argv[2]) || 20;
  tailKafka({ limit })
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(`Kafka tail failed: ${error.message}`);
      process.exit(1);
    });
}
