import { validateEvent } from "../../shared/src/event.js";
import { toMessage } from "./message.js";

/**
 * Create a non-blocking Kafka sink. emit() is synchronous and never
 * throws or waits for the broker; a background flush sends batches
 * in order, with backoff on failure.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {Function|object} [options.producerFactory]
 * @param {object} [options.producer]
 * @param {Function} [options.now]
 * @param {Function} [options.setTimer]
 * @param {Function} [options.clearTimer]
 * @returns {{ emit: (event: unknown) => boolean, flush: () => Promise<void>, close: () => Promise<void>, stats: () => object }}
 */
export function createKafkaSink(options) {
  const config = options.config;
  const log = options.logger || { info: () => {}, warn: () => {}, error: () => {} };
  const now = options.now || Date.now;
  const setTimer = options.setTimer || setTimeout;
  const clearTimer = options.clearTimer || clearTimeout;
  const topic = config.KAFKA_TOPIC;
  const bufferMax = config.KAFKA_BUFFER_MAX;
  const batchMax = config.KAFKA_BATCH_MAX;
  const flushMs = config.KAFKA_FLUSH_MS;
  const shutdownMs = config.KAFKA_SHUTDOWN_FLUSH_MS;
  const maxBytes = config.KAFKA_MAX_MESSAGE_BYTES;
  let queue = [];
  let sent = 0;
  let failed = 0;
  let dropped = 0;
  let rejected = 0;
  let connected = false;
  let lastError = null;
  let producer = null;
  let producerCreated = false;
  let flushing = false;
  let closed = false;
  let closing = false;
  let timer = null;
  let backoffMs = 0;
  let lastDropWarnMs = 0;
  let flushWaiters = [];

  function getProducer() {
    if (producerCreated) return producer;
    producerCreated = true;
    try {
      if (options.producer) producer = options.producer;
      else if (typeof options.producerFactory === "function") producer = options.producerFactory();
      else if (options.producerFactory && typeof options.producerFactory.send === "function") producer = options.producerFactory;
      else producer = null;
    } catch (error) {
      lastError = error && error.message ? error.message : "producer creation failed";
      producer = null;
    }
    return producer;
  }

  function scheduleFlush(delayMs) {
    if (closed || closing) return;
    if (timer !== null) return;
    const delay = typeof delayMs === "number" ? delayMs : flushMs;
    try {
      timer = setTimer(() => {
        timer = null;
        void doFlush();
      }, delay);
    } catch {
      timer = null;
    }
  }

  function scheduleBackoff() {
    backoffMs = backoffMs === 0 ? 1000 : Math.min(backoffMs * 2, 30000);
    if (timer !== null) {
      try { clearTimer(timer); } catch {}
      timer = null;
    }
    scheduleFlush(backoffMs);
  }

  async function ensureConnected() {
    const prod = getProducer();
    if (!prod) throw new Error("no producer");
    if (connected) return;
    if (typeof prod.connect === "function") await prod.connect();
    connected = true;
  }

  async function doFlush() {
    if (flushing) return;
    if (queue.length === 0) return;
    flushing = true;
    try {
      while (queue.length > 0) {
        const batch = queue.slice(0, batchMax);
        let messages;
        try {
          messages = batch.map((item) => item.message);
        } catch {
          queue = queue.slice(batch.length);
          continue;
        }
        try {
          await ensureConnected();
          const prod = getProducer();
          if (!prod || typeof prod.send !== "function") throw new Error("no producer send");
          await prod.send({ topic, messages });
          queue = queue.slice(batch.length);
          sent += batch.length;
          backoffMs = 0;
          lastError = null;
        } catch (error) {
          failed += batch.length;
          lastError = error && error.message ? error.message : "send failed";
          try { log.error({ topic, error: lastError, failed: batch.length }, "Kafka send failed"); } catch {}
          scheduleBackoff();
          break;
        }
      }
    } finally {
      flushing = false;
      const waiters = flushWaiters;
      flushWaiters = [];
      for (const resolve of waiters) {
        try { resolve(); } catch {}
      }
    }
  }

  function emit(event) {
    try {
      const result = validateEvent(event);
      if (!result.ok) {
        rejected += 1;
        return false;
      }
      let message;
      try {
        message = toMessage(result.data);
      } catch {
        rejected += 1;
        return false;
      }
      const size = Buffer.byteLength(message.value, "utf8");
      if (size > maxBytes) {
        dropped += 1;
        return false;
      }
      if (queue.length >= bufferMax) {
        dropped += 1;
        const current = now();
        if (current - lastDropWarnMs >= 60000) {
          lastDropWarnMs = current;
          try { log.warn({ dropped }, "Kafka buffer full, dropping events"); } catch {}
        }
        return false;
      }
      queue.push({ message });
      if (queue.length >= batchMax) {
        if (timer !== null) {
          try { clearTimer(timer); } catch {}
          timer = null;
        }
        void doFlush();
      } else {
        scheduleFlush(flushMs);
      }
      return true;
    } catch {
      rejected += 1;
      return false;
    }
  }

  async function flush() {
    if (queue.length === 0) return;
    await new Promise((resolve) => {
      flushWaiters.push(resolve);
      void doFlush();
    });
  }

  async function close() {
    closing = true;
    if (timer !== null) {
      try { clearTimer(timer); } catch {}
      timer = null;
    }
    if (queue.length > 0) {
      const deadline = now() + shutdownMs;
      let timedOut = false;
      const timeoutPromise = new Promise((resolve) => {
        try {
          setTimer(() => { timedOut = true; resolve(); }, shutdownMs);
        } catch {
          resolve();
        }
      });
      const flushPromise = (async () => {
        while (queue.length > 0 && !timedOut) {
          if (now() > deadline) break;
          const before = queue.length;
          await doFlush();
          if (queue.length === before) break;
        }
      })();
      await Promise.race([flushPromise, timeoutPromise]);
    }
    closing = false;
    closed = true;
    try {
      const prod = getProducer();
      if (prod && typeof prod.disconnect === "function") await prod.disconnect();
    } catch {}
    connected = false;
  }

  function stats() {
    return { sent, failed, dropped, rejected, buffered: queue.length, connected, lastError };
  }

  return { emit, flush, close, stats };
}
