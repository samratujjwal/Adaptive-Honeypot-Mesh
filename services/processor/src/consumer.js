import { createKafkaClient } from "../../../packages/bus/src/kafka-client.js";

/**
 * Create the Kafka consumer for the processor.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {object} [options.kafkaClient]
 * @param {object} options.processor
 * @returns {{ start: () => Promise<void>, stop: () => Promise<void> }}
 */
export function createConsumer(options) {
  const config = options.config;
  const log = options.logger || { info: () => {}, warn: () => {}, error: () => {} };
  const processor = options.processor;
  const client = options.kafkaClient || createKafkaClient({ config, logger: log });
  const consumer = client.consumer(config.PROCESSOR_GROUP_ID);
  let running = false;
  async function start() {
    await consumer.connect();
    await consumer.subscribe({ topic: config.KAFKA_TOPIC, fromBeginning: true });
    running = true;
    await consumer.run({
      autoCommit: false,
      eachBatchAutoResolve: false,
      eachBatch: async ({ batch, resolveOffset, heartbeat, isRunning, isStale }) => {
        const messages = batch.messages.slice(0, config.PROCESSOR_BATCH_MAX);
        const outcome = await processor.processBatch(messages);
        for (const message of outcome.resolved || []) {
          if (isStale()) break;
          resolveOffset(message.offset);
        }
        try { await heartbeat(); } catch {}
        if (!running) return;
      },
    });
  }
  async function stop() {
    running = false;
    try { await consumer.disconnect(); } catch {}
  }
  return { start, stop, consumer };
}
