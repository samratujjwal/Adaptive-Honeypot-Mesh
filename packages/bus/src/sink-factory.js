import { createFileSink } from "../../shared/src/event-sink.js";
import { createKafkaSink } from "./kafka-sink.js";
import { createCompositeSink } from "./composite-sink.js";

/**
 * Create a sink factory. When Kafka is disabled, only file sinks are
 * built. When enabled, one shared Kafka sink is used by all services.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {Function} [options.createFileSink]
 * @param {Function|object} [options.kafkaClient]
 * @param {Function} [options.producerFactory]
 * @returns {{ create: (service: string) => object, stats: () => object, close: () => Promise<void> }}
 */
export function createSinkFactory(options) {
  const config = options.config;
  const log = options.logger;
  const fileSinkFactory = options.createFileSink || createFileSink;
  const fileSinks = [];
  let kafkaSink = null;
  let kafkaProducer = null;
  if (config.KAFKA_ENABLED) {
    if (options.kafkaClient) {
      const client = typeof options.kafkaClient === "function" ? options.kafkaClient() : options.kafkaClient;
      if (client && typeof client.producer === "function") {
        kafkaProducer = client.producer();
      } else if (client && typeof client.send === "function") {
        kafkaProducer = client;
      }
    }
    kafkaSink = createKafkaSink({
      config,
      logger: log,
      producerFactory: options.producerFactory || (() => kafkaProducer),
      producer: kafkaProducer,
    });
  }
  return {
    create(service) {
      const fileSink = fileSinkFactory({ dir: config.EVENT_DIR, service, logger: log });
      fileSinks.push(fileSink);
      if (!kafkaSink) return fileSink;
      const composite = createCompositeSink([fileSink, kafkaSink]);
      return {
        emit(event) { return composite.emit(event); },
        close() {
          try { fileSink.close(); } catch {}
        },
      };
    },
    stats() {
      return kafkaSink ? kafkaSink.stats() : { sent: 0, failed: 0, dropped: 0, rejected: 0, buffered: 0, connected: false, lastError: null };
    },
    async close() {
      if (kafkaSink) {
        try { await kafkaSink.close(); } catch {}
      }
      for (const sink of fileSinks) {
        try { sink.close(); } catch {}
      }
    },
  };
}
