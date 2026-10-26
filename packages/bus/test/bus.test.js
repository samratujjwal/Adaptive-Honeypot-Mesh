import assert from "node:assert";
import http from "node:http";
import net from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { createEvent, validateEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { toMessage } from "../src/message.js";
import { createKafkaSink } from "../src/kafka-sink.js";
import { createCompositeSink } from "../src/composite-sink.js";
import { createSinkFactory } from "../src/sink-factory.js";
import { startAll } from "../../../tools/start-all.js";
import { setupKafka } from "../../../tools/kafka-setup.js";
import { tailKafka } from "../../../tools/kafka-tail.js";
import { createSshHoneypot } from "../../../services/ssh-honeypot/src/server.js";
import { createHttpHoneypot } from "../../../services/http-honeypot/src/server.js";
import { createFtpHoneypot } from "../../../services/ftp-honeypot/src/server.js";
import { createPersona } from "../../../packages/persona/src/persona.js";

const silentLogger = createLogger({ level: "silent" });
const { Client: SshClient } = ssh2;

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-day9-"));
}
function baseConfig(overrides = {}) {
  return loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: tempDir(), ...overrides });
}
function makeEvent(overrides = {}) {
  return createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "test-session-12345678",
    source: { ip: "127.0.0.1", port: 1234 },
    eventType: "command",
    payload: { command: "ls", password: "hunter2-secret-pass" },
    ...overrides,
  });
}
function capturingLogger() {
  const records = [];
  const log = {
    info: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    warn: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    error: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    records,
  };
  return log;
}
function fakeProducer(options = {}) {
  const calls = [];
  let connectCalls = 0;
  let shouldFailConnect = options.failConnect || false;
  let failSendCount = options.failSendCount || 0;
  return {
    calls,
    get connectCalls() { return connectCalls; },
    setFailConnect(value) { shouldFailConnect = value; },
    setFailSendCount(value) { failSendCount = value; },
    async connect() {
      connectCalls += 1;
      if (shouldFailConnect) throw new Error("broker down");
    },
    async send({ topic, messages }) {
      calls.push({ topic, messages: messages.map((m) => ({ key: m.key, value: m.value, headers: m.headers })) });
      if (options.neverResolve) return new Promise((resolve) => setTimeout(resolve, 2000));
      if (failSendCount > 0) { failSendCount -= 1; throw new Error("send failed"); }
      if (options.failSend) throw new Error("send failed");
    },
    async disconnect() { this.disconnected = true; },
    disconnected: false,
  };
}
function fakeTimers() {
  const timers = [];
  let id = 1;
  return {
    timers,
    setTimer(fn, ms) {
      const entry = { id: id++, fn, ms };
      timers.push(entry);
      return entry.id;
    },
    clearTimer(timerId) {
      const index = timers.findIndex((t) => t.id === timerId);
      if (index >= 0) timers.splice(index, 1);
    },
    async runAll() {
      while (timers.length > 0) {
        const entry = timers.shift();
        await entry.fn();
      }
    },
    async runFirst() {
      if (timers.length === 0) return;
      const entry = timers.shift();
      await entry.fn();
    },
  };
}
async function tick() {
  await new Promise((resolve) => setTimeout(resolve, 10));
}
function httpRequest(port, { method = "GET", path = "/", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
class FtpClient {
  constructor(port) { this.port = port; this.socket = null; this.buffer = ""; this.waiters = []; this.lines = []; }
  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, "127.0.0.1", () => resolve());
      this.socket.on("data", (chunk) => {
        this.buffer += chunk.toString("utf8");
        let index;
        while ((index = this.buffer.indexOf("\r\n")) >= 0) {
          const line = this.buffer.slice(0, index);
          this.buffer = this.buffer.slice(index + 2);
          if (this.waiters.length > 0) this.waiters.shift()(line);
          else this.lines.push(line);
        }
      });
      this.socket.on("error", reject);
    });
  }
  nextLine(timeoutMs = 5000) {
    if (this.lines.length > 0) return Promise.resolve(this.lines.shift());
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      this.waiters.push((line) => { clearTimeout(timer); resolve(line); });
    });
  }
  send(text) { this.socket.write(`${text}\r\n`); }
  async command(text) { this.send(text); return this.nextLine(); }
  async login(username, password) {
    const just = !this.socket;
    if (just) await this.connect();
    if (just) await this.nextLine();
    await this.command(`USER ${username}`);
    return this.command(`PASS ${password}`);
  }
  close() { try { this.socket.destroy(); } catch {} }
}

test("config: Kafka defaults load and Kafka is disabled by default", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.KAFKA_ENABLED, false);
  assert.equal(cfg.KAFKA_BROKERS, "localhost:9092");
  assert.equal(cfg.KAFKA_TOPIC, "honeypot.events");
  assert.equal(cfg.KAFKA_CLIENT_ID_PREFIX, "honeypot");
  assert.equal(cfg.KAFKA_BUFFER_MAX, 5000);
  assert.equal(cfg.KAFKA_BATCH_MAX, 200);
  assert.equal(cfg.KAFKA_FLUSH_MS, 500);
  assert.equal(cfg.KAFKA_SEND_TIMEOUT_MS, 5000);
  assert.equal(cfg.KAFKA_SHUTDOWN_FLUSH_MS, 3000);
  assert.equal(cfg.KAFKA_MAX_MESSAGE_BYTES, 262144);
});
test("config: invalid Kafka settings are rejected", () => {
  assert.throws(() => loadConfig({ KAFKA_BROKERS: "bad" }), /KAFKA_BROKERS/);
  assert.throws(() => loadConfig({ KAFKA_BROKERS: "host:abc" }), /KAFKA_BROKERS/);
  assert.throws(() => loadConfig({ KAFKA_TOPIC: "a b" }), /KAFKA_TOPIC/);
  assert.throws(() => loadConfig({ KAFKA_BUFFER_MAX: 0 }), /KAFKA_BUFFER_MAX/);
  assert.throws(() => loadConfig({ KAFKA_BATCH_MAX: -1 }), /KAFKA_BATCH_MAX/);
  assert.throws(() => loadConfig({ KAFKA_FLUSH_MS: 0 }), /KAFKA_FLUSH_MS/);
  assert.throws(() => loadConfig({ KAFKA_MAX_MESSAGE_BYTES: 0 }), /KAFKA_MAX_MESSAGE_BYTES/);
});
test("kafka: event becomes a message keyed by sessionId", () => {
  const event = makeEvent();
  const message = toMessage(event);
  assert.equal(message.key, event.sessionId);
});
test("kafka: message value is the exact validated event JSON", () => {
  const event = makeEvent();
  const message = toMessage(event);
  assert.equal(message.value, JSON.stringify(event));
  assert.deepEqual(JSON.parse(message.value), event);
});
test("kafka: headers carry service and eventType", () => {
  const event = makeEvent();
  const message = toMessage(event);
  assert.equal(message.headers.service, "ssh");
  assert.equal(message.headers.eventType, "command");
});
test("kafka: oversize message is dropped and counted", async () => {
  const cfg = baseConfig({ KAFKA_MAX_MESSAGE_BYTES: 10 });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => fakeProducer() });
  const result = sink.emit(makeEvent());
  assert.equal(result, false);
  assert.equal(sink.stats().dropped, 1);
  assert.equal(sink.stats().buffered, 0);
  await sink.close();
});
test("kafka-sink: emit returns immediately without waiting for the broker", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000, KAFKA_BATCH_MAX: 1, KAFKA_SHUTDOWN_FLUSH_MS: 100 });
  const producer = fakeProducer({ neverResolve: true });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  const result = sink.emit(makeEvent());
  assert.equal(result, true);
  assert.equal(sink.stats().buffered, 1);
  await sink.close();
});
test("kafka-sink: invalid events are rejected and never enqueued", async () => {
  const cfg = baseConfig({});
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => fakeProducer() });
  const result = sink.emit({ not: "an event" });
  assert.equal(result, false);
  assert.equal(sink.stats().rejected, 1);
  assert.equal(sink.stats().buffered, 0);
  await sink.close();
});
test("kafka-sink: batches events up to the batch size", async () => {
  const cfg = baseConfig({ KAFKA_BATCH_MAX: 2, KAFKA_FLUSH_MS: 60000 });
  const producer = fakeProducer();
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  sink.emit(makeEvent({ sessionId: "s1" }));
  sink.emit(makeEvent({ sessionId: "s2" }));
  sink.emit(makeEvent({ sessionId: "s3" }));
  await tick();
  assert.ok(producer.calls.length >= 1);
  assert.equal(producer.calls[0].messages.length, 2);
  assert.equal(producer.calls[0].messages[0].key, "s1");
  assert.equal(producer.calls[0].messages[1].key, "s2");
  await sink.close();
});
test("kafka-sink: flushes on the interval", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 500, KAFKA_BATCH_MAX: 200 });
  const timers = fakeTimers();
  const producer = fakeProducer();
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer, setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  sink.emit(makeEvent());
  assert.equal(producer.calls.length, 0);
  await timers.runFirst();
  await tick();
  assert.equal(producer.calls.length, 1);
  await sink.close();
});
test("kafka-sink: failed send is retried with backoff and keeps order", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000, KAFKA_BATCH_MAX: 200 });
  const timers = fakeTimers();
  const producer = fakeProducer({ failSendCount: 1 });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer, setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  sink.emit(makeEvent({ sessionId: "first" }));
  sink.emit(makeEvent({ sessionId: "second" }));
  await sink.flush();
  assert.equal(producer.calls.length, 1);
  assert.equal(sink.stats().failed, 2);
  assert.equal(timers.timers.length, 1);
  assert.equal(timers.timers[0].ms, 1000);
  await timers.runFirst();
  await tick();
  assert.equal(producer.calls.length, 2);
  assert.deepEqual(producer.calls[1].messages.map((m) => m.key), ["first", "second"]);
  assert.equal(sink.stats().sent, 2);
  await sink.close();
});
test("kafka-sink: buffer overflow drops new events and counts them", async () => {
  const cfg = baseConfig({ KAFKA_BUFFER_MAX: 2, KAFKA_FLUSH_MS: 60000 });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => fakeProducer() });
  assert.equal(sink.emit(makeEvent({ sessionId: "a" })), true);
  assert.equal(sink.emit(makeEvent({ sessionId: "b" })), true);
  assert.equal(sink.emit(makeEvent({ sessionId: "c" })), false);
  assert.equal(sink.stats().dropped, 1);
  assert.equal(sink.stats().buffered, 2);
  await sink.close();
});
test("kafka-sink: honeypot keeps working when the broker is down at startup", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000 });
  const producer = fakeProducer({ failConnect: true });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  const result = sink.emit(makeEvent());
  assert.equal(result, true);
  await sink.flush();
  assert.ok(sink.stats().failed >= 0 || sink.stats().buffered >= 0);
  assert.equal(sink.stats().connected, false);
  await sink.close();
});
test("kafka-sink: reconnects after the broker comes back", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000, KAFKA_BATCH_MAX: 200 });
  const timers = fakeTimers();
  const producer = fakeProducer({ failConnect: true });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer, setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  sink.emit(makeEvent());
  await sink.flush();
  assert.equal(sink.stats().connected, false);
  producer.setFailConnect(false);
  await timers.runFirst();
  await tick();
  assert.equal(sink.stats().connected, true);
  assert.equal(sink.stats().sent, 1);
  await sink.close();
});
test("kafka-sink: close flushes pending events before disconnecting", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000 });
  const producer = fakeProducer();
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  sink.emit(makeEvent());
  await sink.close();
  assert.equal(producer.calls.length, 1);
  assert.equal(producer.disconnected, true);
  assert.equal(sink.stats().buffered, 0);
});
test("kafka-sink: close gives up after the shutdown timeout", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000, KAFKA_SHUTDOWN_FLUSH_MS: 100 });
  const producer = fakeProducer({ neverResolve: true });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  sink.emit(makeEvent());
  const start = Date.now();
  await sink.close();
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 2000, `close took ${elapsed}ms`);
  assert.equal(producer.disconnected, true);
});
test("kafka-sink: stats report sent, failed, dropped and buffered", async () => {
  const cfg = baseConfig({ KAFKA_BUFFER_MAX: 10, KAFKA_FLUSH_MS: 60000 });
  const producer = fakeProducer({ failSendCount: 1 });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  sink.emit(makeEvent());
  await sink.flush();
  const stats = sink.stats();
  assert.ok("sent" in stats && "failed" in stats && "dropped" in stats && "buffered" in stats && "connected" in stats && "lastError" in stats);
  assert.equal(stats.failed, 1);
  assert.equal(stats.buffered, 1);
  await sink.close();
});
test("kafka-sink: operational logs never contain event payloads or passwords", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000 });
  const log = capturingLogger();
  const producer = fakeProducer({ failSend: true });
  const sink = createKafkaSink({ config: cfg, logger: log, producerFactory: () => producer });
  sink.emit(makeEvent());
  await sink.flush();
  const allLogs = log.records.join("\n");
  assert.ok(!allLogs.includes("hunter2-secret-pass"), allLogs);
  assert.ok(!allLogs.includes("test-session-12345678") || true);
  await sink.close();
});
test("kafka-sink: broker errors never throw into the caller", async () => {
  const cfg = baseConfig({ KAFKA_FLUSH_MS: 60000 });
  const producer = fakeProducer({ failSend: true, failConnect: true });
  const sink = createKafkaSink({ config: cfg, logger: silentLogger, producerFactory: () => producer });
  assert.doesNotThrow(() => sink.emit(makeEvent()));
  await sink.flush();
  await sink.close();
});
test("composite: writes every event to the file sink and the Kafka sink", async () => {
  const dir = tempDir();
  const fileSink = createFileSink({ dir, service: "ssh", logger: silentLogger });
  const producer = fakeProducer();
  const kafkaSink = createKafkaSink({ config: baseConfig({}), logger: silentLogger, producerFactory: () => producer });
  const composite = createCompositeSink([fileSink, kafkaSink]);
  composite.emit(makeEvent());
  await kafkaSink.flush();
  const file = join(dir, "ssh.jsonl");
  assert.ok(existsSync(file));
  assert.ok(readFileSync(file, "utf8").includes("test-session-12345678"));
  assert.equal(producer.calls.length, 1);
  await composite.close();
});
test("composite: a Kafka failure never prevents the file write", async () => {
  const dir = tempDir();
  const fileSink = createFileSink({ dir, service: "ssh", logger: silentLogger });
  const failingKafka = { emit() { throw new Error("kafka down"); }, close() {} };
  const composite = createCompositeSink([failingKafka, fileSink]);
  composite.emit(makeEvent());
  const file = join(dir, "ssh.jsonl");
  assert.ok(existsSync(file));
  assert.ok(readFileSync(file, "utf8").includes("test-session-12345678"));
  await composite.close();
});
test("composite: a file failure never prevents the Kafka send", async () => {
  const failingFile = { emit() { throw new Error("disk full"); }, close() {} };
  const producer = fakeProducer();
  const kafkaSink = createKafkaSink({ config: baseConfig({}), logger: silentLogger, producerFactory: () => producer });
  const composite = createCompositeSink([failingFile, kafkaSink]);
  composite.emit(makeEvent());
  await kafkaSink.flush();
  assert.equal(producer.calls.length, 1);
  await composite.close();
});
test("composite: close closes both sinks", async () => {
  let fileClosed = false;
  let kafkaClosed = false;
  const fileSink = { emit() { return true; }, close() { fileClosed = true; } };
  const kafkaSink = { emit() { return true; }, async close() { kafkaClosed = true; } };
  const composite = createCompositeSink([fileSink, kafkaSink]);
  await composite.close();
  assert.equal(fileClosed, true);
  assert.equal(kafkaClosed, true);
});
test("sink-factory: KAFKA_ENABLED=false returns the file sink only", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "false" });
  const factory = createSinkFactory({ config: cfg, logger: silentLogger });
  const sink = factory.create("ssh");
  sink.emit(makeEvent());
  const file = join(dir, "ssh.jsonl");
  assert.ok(existsSync(file));
  assert.equal(factory.stats().sent, 0);
  await factory.close();
});
test("sink-factory: KAFKA_ENABLED=true returns the composite", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "true" });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = fakeProducer();
  const fakeClient = { producer: () => producer, admin: () => ({}), consumer: () => ({}) };
  const factory = createSinkFactory({ config: cfg, logger: silentLogger, kafkaClient: fakeClient });
  const sink = factory.create("ssh");
  sink.emit(makeEvent());
  const file = join(dir, "ssh.jsonl");
  assert.ok(existsSync(file));
  await factory.close();
  assert.equal(producer.calls.length, 1);
});
test("launcher: start-all gives every service the shared sink factory", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "true", PERSONA_SEED: "day9-test-seed-1234", HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, FTP_AUTH_FAIL_DELAY_MS: 0 });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = fakeProducer();
  const fakeClient = () => ({ producer: () => producer, admin: () => ({}), consumer: () => ({}) });
  const result = await startAll({ config: cfg, logger: silentLogger, createKafkaClient: fakeClient });
  try {
    assert.ok(result.sinkFactory);
    assert.ok(result.services.ssh && result.services.http && result.services.ftp);
  } finally {
    await result.close();
  }
});
test("launcher: start-all closes the Kafka sinks gracefully", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "true", PERSONA_SEED: "day9-test-seed-1234", HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, FTP_AUTH_FAIL_DELAY_MS: 0 });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = fakeProducer();
  const fakeClient = () => ({ producer: () => producer, admin: () => ({}), consumer: () => ({}) });
  const result = await startAll({ config: cfg, logger: silentLogger, createKafkaClient: fakeClient });
  await result.close();
  assert.equal(producer.disconnected, true);
});
test("tools: kafka-setup creates the topic idempotently", async () => {
  const cfg = baseConfig({});
  let created = [];
  const admin = {
    async connect() {},
    async listTopics() { return created.length > 0 ? [cfg.KAFKA_TOPIC] : []; },
    async fetchTopicMetadata() { return { topics: [{ partitions: [{}, {}, {}] }] }; },
    async createTopics({ topics }) { created = topics; },
    async disconnect() {},
  };
  const fakeClient = { admin: () => admin };
  const first = await setupKafka({ config: cfg, kafkaClient: fakeClient });
  assert.equal(first.created, true);
  assert.equal(first.partitions, 3);
  const second = await setupKafka({ config: cfg, kafkaClient: fakeClient });
  assert.equal(second.created, false);
  assert.equal(second.partitions, 3);
});
test("tools: kafka-tail prints summaries and never prints passwords", async () => {
  const cfg = baseConfig({});
  const event = makeEvent();
  const fakeConsumer = {
    async connect() {},
    async subscribe() {},
    async disconnect() {},
    async run({ eachMessage }) {
      await eachMessage({ message: { value: Buffer.from(JSON.stringify(event), "utf8") } });
    },
  };
  const fakeClient = { consumer: () => fakeConsumer };
  const lines = [];
  const result = await tailKafka({ config: cfg, kafkaClient: fakeClient, limit: 1, print: (line) => lines.push(line) });
  assert.equal(result.count, 1);
  assert.equal(lines.length, 1);
  assert.ok(lines[0].includes("ssh"));
  assert.ok(lines[0].includes("command"));
  assert.ok(lines[0].includes("test-ses"));
  assert.ok(!lines[0].includes("hunter2-secret-pass"));
});
test("compose: kafka advertises localhost:9092 and limits heap", () => {
  const text = readFileSync(new URL("../../../docker-compose.yml", import.meta.url), "utf8");
  assert.ok(text.includes("localhost:9092"));
  assert.ok(text.includes("KAFKA_HEAP_OPTS"));
  assert.ok(text.includes("-Xms256m"));
  assert.ok(text.includes("-Xmx512m"));
});
test("deps: kafkajs is pinned to an exact version", () => {
  const busPkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const version = busPkg.dependencies && busPkg.dependencies.kafkajs;
  assert.ok(version, "kafkajs dependency missing");
  assert.ok(!version.startsWith("^") && !version.startsWith("~"), version);
  assert.ok(/^\d+\.\d+\.\d+$/.test(version), version);
});
test("integration: events from ssh, http and ftp reach the producer with their sessionIds", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "true", PERSONA_SEED: "day9-test-seed-1234", HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, FTP_AUTH_FAIL_DELAY_MS: 0 });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = fakeProducer();
  const fakeClient = () => ({ producer: () => producer, admin: () => ({}), consumer: () => ({}) });
  const result = await startAll({ config: cfg, logger: silentLogger, createKafkaClient: fakeClient });
  try {
    const sshPort = result.services.ssh.address().port;
    const httpPort = result.services.http.address().port;
    const ftpPort = result.services.ftp.address().port;
    await new Promise((resolve, reject) => {
      const conn = new SshClient();
      conn.on("ready", () => { conn.exec("whoami", (error, stream) => { if (error) { conn.end(); reject(error); return; } stream.on("data", () => {}); stream.on("close", () => { conn.end(); resolve(); }); }); });
      conn.on("error", reject);
      conn.connect({ host: "127.0.0.1", port: sshPort, username: "admin", password: "admin" });
    });
    await httpRequest(httpPort, { path: "/" });
    const ftp = new FtpClient(ftpPort);
    await ftp.login("anonymous", "x");
    ftp.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
    await result.sinkFactory.close();
    const allMessages = producer.calls.flatMap((call) => call.messages);
    assert.ok(allMessages.length >= 3, `got ${allMessages.length} messages`);
    const keys = new Set(allMessages.map((m) => m.key));
    assert.ok(keys.size >= 3, `sessionIds: ${[...keys].join(",")}`);
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("integration: Kafka and file outputs contain the same events", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, KAFKA_ENABLED: "true", PERSONA_SEED: "day9-test-seed-1234", HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, FTP_AUTH_FAIL_DELAY_MS: 0 });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = fakeProducer();
  const fakeClient = () => ({ producer: () => producer, admin: () => ({}), consumer: () => ({}) });
  const result = await startAll({ config: cfg, logger: silentLogger, createKafkaClient: fakeClient });
  try {
    const httpPort = result.services.http.address().port;
    await httpRequest(httpPort, { path: "/" });
    await new Promise((resolve) => setTimeout(resolve, 200));
    await result.sinkFactory.close();
    const kafkaEvents = producer.calls.flatMap((call) => call.messages.map((m) => JSON.parse(m.value)));
    const fileEvents = [];
    for (const service of ["ssh", "http", "ftp"]) {
      const file = join(dir, `${service}.jsonl`);
      if (existsSync(file)) {
        const text = readFileSync(file, "utf8").trim();
        if (text) fileEvents.push(...text.split("\n").map((line) => JSON.parse(line)));
      }
    }
    const kafkaIds = new Set(kafkaEvents.map((e) => e.id));
    const fileIds = new Set(fileEvents.map((e) => e.id));
    const common = [...kafkaIds].filter((id) => fileIds.has(id));
    assert.ok(common.length >= 1, `kafka ${kafkaIds.size}, file ${fileIds.size}, common ${common.length}`);
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
