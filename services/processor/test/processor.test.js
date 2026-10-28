import assert from "node:assert";
import http from "node:http";
import net from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { createEvent } from "../../../packages/shared/src/event.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createPersona } from "../../../packages/persona/src/persona.js";
import { formatLastLogin } from "../../../services/ssh-honeypot/src/shell.js";
import { createSshHoneypot } from "../../../services/ssh-honeypot/src/server.js";
import { createHttpHoneypot } from "../../../services/http-honeypot/src/server.js";
import { createFtpHoneypot } from "../../../services/ftp-honeypot/src/server.js";
import { startAll } from "../../../tools/start-all.js";
import { kafkaBrokerErrorLine } from "../../../tools/kafka-setup.js";
import { createSessionAggregator } from "../src/sessions.js";
import { createProcessor } from "../src/processor.js";
import { createBulkIndexer } from "../../../packages/search/src/bulk-indexer.js";
import { setupEs } from "../../../tools/es-setup.js";
import { summarizeEs } from "../../../tools/es-summary.js";
import { createGeoip } from "../../../packages/enrich/src/geoip.js";

const silentLogger = createLogger({ level: "silent" });
const { Client: SshClient } = ssh2;
const SEED = "day10-test-seed-1234";

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-day10-"));
}
function baseConfig(overrides = {}) {
  const dir = tempDir();
  return loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, ...overrides });
}
function makeEvent(overrides = {}) {
  return createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "test-session-12345678",
    source: { ip: "127.0.0.1", port: 1234 },
    eventType: "command",
    payload: { command: "ls -la", cwd: "/home/admin" },
    ...overrides,
  });
}
function capturingLogger() {
  const records = [];
  return {
    records,
    info: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    warn: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    error: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
  };
}
function fakeIndexer() {
  const docs = [];
  return {
    docs,
    async index(input) { docs.push(...input); return { rejected: [], retries: 0, remaining: [] }; },
    async close() {},
  };
}
function fakeEs() {
  const docs = [];
  return {
    docs,
    async bulk({ body }) {
      const items = [];
      for (let i = 0; i < body.length; i += 2) {
        docs.push({ index: body[i].index._index, id: body[i].index._id, body: body[i + 1] });
        items.push({ index: { status: 201 } });
      }
      return { body: { items } };
    },
    indices: {
      async putIndexTemplate() { return {}; },
      async exists() { return false; },
      async create() { return {}; },
    },
    async mget({ body }) {
      return { body: { docs: body.docs.map((d) => ({ _id: d._id, found: false })) } };
    },
    async search() {
      return { body: { aggregations: { by_service: { buckets: [{ key: "ssh", doc_count: 2 }] }, by_type: { buckets: [{ key: "command", doc_count: 2 }] }, by_ip: { buckets: [{ key: "127.0.0.1", doc_count: 2 }] }, by_honeytoken: { buckets: [{ key: "used", doc_count: 1 }] }, oldest: { value_as_string: "2026-10-21T00:00:00Z" }, newest: { value_as_string: "2026-10-21T01:00:00Z" } } } };
    },
    async count() { return { body: { count: 1 } }; },
  };
}
async function startSshTest() {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PERSONA_SEED: SEED, HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000 });
  const sink = createFileSink({ dir, service: "ssh", logger: silentLogger });
  const honeypot = createSshHoneypot({ config: cfg, sink });
  await honeypot.listen(0, "127.0.0.1");
  return { dir, cfg, honeypot, port: honeypot.address().port };
}
async function shellOutput(port, username = "admin", password = "admin") {
  return new Promise((resolve, reject) => {
    const conn = new SshClient();
    conn.on("ready", () => {
      conn.shell((error, stream) => {
        if (error) { conn.end(); reject(error); return; }
        let out = "";
        stream.on("data", (chunk) => { out += chunk.toString("utf8"); });
        setTimeout(() => { try { stream.write("exit\n"); } catch {} setTimeout(() => { conn.end(); resolve(out); }, 200); }, 500);
      });
    });
    conn.on("error", reject);
    conn.connect({ host: "127.0.0.1", port, username, password });
  });
}
function httpRequest(port, { method = "GET", path = "/", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
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

test("tools: kafka tools print one friendly line when the broker is unreachable", () => {
  const cfg = loadConfig({ KAFKA_BROKERS: "localhost:9092" });
  const line = kafkaBrokerErrorLine(cfg);
  assert.equal(line, "Cannot reach Kafka at localhost:9092. Is it running? (docker compose up -d kafka)");
  assert.ok(!line.includes("\n"));
});
test("tools: kafka tools do not print kafkajs error spam", () => {
  const setupText = readFileSync(new URL("../../../tools/kafka-setup.js", import.meta.url), "utf8");
  const tailText = readFileSync(new URL("../../../tools/kafka-tail.js", import.meta.url), "utf8");
  assert.ok(setupText.includes("KAFKA_LOG_LEVEL_NOTHING"));
  assert.ok(tailText.includes("KAFKA_LOG_LEVEL_NOTHING"));
  assert.ok(setupText.includes("kafkaBrokerErrorLine"));
  assert.ok(tailText.includes("kafkaBrokerErrorLine"));
});
test("ssh: Last login uses the classic format in UTC", () => {
  const formatted = formatLastLogin(new Date(Date.UTC(2026, 9, 21, 9, 41, 7)));
  assert.equal(formatted, "Wed Oct 21 09:41:07 2026");
  assert.ok(!formatted.includes("GMT") && !formatted.includes("UTC") && !formatted.includes("IST"));
  assert.ok(/^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{2}:\d{2}:\d{2} \d{4}$/.test(formatted));
});
test("ssh: first Last login shows the persona's previous login", async () => {
  const made = await startSshTest();
  try {
    const persona = createPersona({ seed: SEED, hostname: "srv-web-01" });
    const out = await shellOutput(made.port);
    const expected = formatLastLogin(persona.host.previousLogin.time);
    assert.ok(out.includes(`Last login: ${expected} from ${persona.host.previousLogin.sourceIp}`), out);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: later logins show the previous session time and ip", async () => {
  const made = await startSshTest();
  try {
    const persona = createPersona({ seed: SEED, hostname: "srv-web-01" });
    const first = await shellOutput(made.port);
    const second = await shellOutput(made.port);
    assert.ok(first.includes(persona.host.previousLogin.sourceIp));
    assert.ok(!second.includes(persona.host.previousLogin.sourceIp) || second.includes("127.0.0.1"));
    assert.ok(second.includes("from 127.0.0.1"), second);
    assert.ok(!second.includes(formatLastLogin(persona.host.previousLogin.time)) || second.includes("127.0.0.1"));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("config: processor and Elasticsearch defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.ES_INDEX_PREFIX, "honeypot");
  assert.equal(cfg.PROCESSOR_GROUP_ID, "honeypot-processor");
  assert.equal(cfg.PROCESSOR_BATCH_MAX, 500);
  assert.equal(cfg.PROCESSOR_FLUSH_MS, 1000);
  assert.equal(cfg.PROCESSOR_ES_TIMEOUT_MS, 10000);
  assert.equal(cfg.PROCESSOR_SESSION_CACHE_MAX, 10000);
  assert.equal(cfg.PROCESSOR_SESSION_IDLE_MS, 1800000);
  assert.equal(cfg.PROCESSOR_DEAD_LETTER_FILE, "data/dead-letter.jsonl");
  assert.equal(cfg.PROCESSOR_DEAD_LETTER_MAX_BYTES, 10485760);
  assert.equal(cfg.GEOIP_ENABLED, true);
});
test("config: invalid processor settings are rejected", () => {
  assert.throws(() => loadConfig({ ELASTICSEARCH_URL: "not-a-url" }), /ELASTICSEARCH_URL/);
  assert.throws(() => loadConfig({ PROCESSOR_BATCH_MAX: 0 }), /PROCESSOR_BATCH_MAX/);
  assert.throws(() => loadConfig({ PROCESSOR_FLUSH_MS: 0 }), /PROCESSOR_FLUSH_MS/);
  assert.throws(() => loadConfig({ PROCESSOR_SESSION_CACHE_MAX: 0 }), /PROCESSOR_SESSION_CACHE_MAX/);
  assert.throws(() => loadConfig({ ES_INDEX_PREFIX: "" }), /ES_INDEX_PREFIX/);
});
test("sessions: counters for commands, auth attempts and http requests", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({ eventType: "auth_attempt", payload: { username: "admin", success: true, method: "password" } }), geo);
  await agg.apply(makeEvent({ eventType: "auth_attempt", payload: { username: "root", success: false, method: "password" } }), geo);
  await agg.apply(makeEvent({ eventType: "command", payload: { command: "ls" } }), geo);
  await agg.apply(makeEvent({ eventType: "http_request", payload: { path: "/index.html", method: "GET" } }), geo);
  const session = agg.get("test-session-12345678");
  assert.equal(session.authAttempts, 2);
  assert.equal(session.authSuccess, 1);
  assert.equal(session.commandCount, 1);
  assert.equal(session.httpRequestCount, 1);
  assert.equal(session.eventCount, 4);
});
test("sessions: first seen, last seen and duration are tracked", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({ timestamp: "2026-10-21T00:00:00Z" }), geo);
  await agg.apply(makeEvent({ id: "00000000-0000-4000-8000-000000000002", timestamp: "2026-10-21T00:01:00Z" }), geo);
  const session = agg.get("test-session-12345678");
  assert.equal(session.firstSeen, "2026-10-21T00:00:00Z");
  assert.equal(session.lastSeen, "2026-10-21T00:01:00Z");
  await agg.apply(makeEvent({ id: "00000000-0000-4000-8000-000000000003", timestamp: "2026-10-21T00:02:00Z", eventType: "connection_close", payload: { reason: "client_quit" } }), geo);
  assert.equal(session.durationMs, 120000);
});
test("sessions: connection_close marks the session closed with its reason", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({ eventType: "connection_close", payload: { reason: "idle_timeout" } }), geo);
  const session = agg.get("test-session-12345678");
  assert.equal(session.closed, true);
  assert.equal(session.closeReason, "idle_timeout");
});
test("sessions: unique usernames and commands are capped", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  for (let i = 0; i < 30; i += 1) {
    await agg.apply(makeEvent({ id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, eventType: "auth_attempt", payload: { username: `user${i}`, success: false } }), geo);
    await agg.apply(makeEvent({ id: `00000000-0000-4000-8000-${String(100 + i).padStart(12, "0")}`, eventType: "command", payload: { command: `cmd${i}` } }), geo);
  }
  const session = agg.get("test-session-12345678");
  assert.ok(session.usernames.length <= 20);
  assert.ok(session.commands.length <= 50);
  assert.equal(new Set(session.usernames).size, session.usernames.length);
  assert.equal(new Set(session.commands).size, session.commands.length);
});
test("sessions: honeytoken hits are recorded with the token id only", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({ eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "used", via: "ssh_command" } }), geo);
  const session = agg.get("test-session-12345678");
  assert.equal(session.honeytokens.length, 1);
  assert.equal(session.honeytokens[0].tokenId, "ht-abcdef12");
  assert.ok(!JSON.stringify(session).includes("secret"));
});
test("sessions: duplicate event ids are not counted twice", async () => {
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  const event = makeEvent({});
  await agg.apply(event, geo);
  const result = await agg.apply(event, geo);
  assert.equal(result, null);
  assert.equal(agg.get("test-session-12345678").eventCount, 1);
});
test("sessions: an existing session is loaded from Elasticsearch after a restart", async () => {
  const existing = makeEvent({ eventType: "command", payload: { command: "old" } });
  const loadedDoc = { sessionId: "test-session-12345678", service: "ssh", nodeId: "node-01", sourceIp: "127.0.0.1", sourceIpClass: "loopback", geo: null, firstSeen: "2026-10-21T00:00:00Z", lastSeen: "2026-10-21T00:00:00Z", durationMs: 0, closed: false, closeReason: null, eventCount: 5, eventTypeCounts: { command: 5 }, authAttempts: 0, authSuccess: 0, usernames: [], commandCount: 5, commands: ["old"], httpRequestCount: 0, httpPaths: [], ftpCommandCount: 0, filesTransferred: [], llmResponses: 0, honeytokens: [], seenEventIds: ["old-id"], updatedAt: "2026-10-21T00:00:00Z" };
  const agg = createSessionAggregator({ loadExisting: async (ids) => new Map([[ids[0], loadedDoc]]) });
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({ id: "00000000-0000-4000-8000-000000000010" }), geo);
  const session = agg.get("test-session-12345678");
  assert.equal(session.eventCount, 6);
  assert.equal(session.commandCount, 6);
});
test("sessions: idle sessions are evicted from memory but a later event reloads them", async () => {
  let nowMs = 1000;
  let loads = 0;
  const agg = createSessionAggregator({ idleMs: 1000, now: () => nowMs, loadExisting: async (ids) => { loads += 1; return new Map(); } });
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  await agg.apply(makeEvent({}), geo);
  assert.ok(agg.get("test-session-12345678"));
  nowMs = 10000;
  agg.evictIdle();
  assert.equal(agg.get("test-session-12345678"), undefined);
  const loadsBefore = loads;
  await agg.apply(makeEvent({ id: "00000000-0000-4000-8000-000000000011" }), geo);
  assert.ok(loads > loadsBefore);
});
test("processor: a valid message is enriched and indexed", async () => {
  const cfg = baseConfig({});
  const indexer = fakeIndexer();
  const geoip = createGeoip({ enabled: true, lookupImpl: async () => ({ country: "US", region: "CA", city: "X", ll: [1, 2], timezone: "America/Los_Angeles" }) });
  const processor = createProcessor({ config: cfg, logger: silentLogger, geoip, indexer });
  const event = makeEvent({ source: { ip: "8.8.8.8", port: 1234 } });
  const outcome = await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  assert.equal(outcome.resolved.length, 1);
  const eventDoc = indexer.docs.find((d) => d.index.startsWith("honeypot-events-"));
  assert.ok(eventDoc);
  assert.equal(eventDoc.body.enrich.ipClass, "public");
  assert.equal(eventDoc.body.enrich.geo.country, "US");
  assert.ok(eventDoc.body.ingestedAt);
  await processor.close();
});
test("processor: invalid JSON goes to the dead letter file", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PROCESSOR_DEAD_LETTER_FILE: join(dir, "dead.jsonl") });
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const outcome = await processor.processBatch([{ value: Buffer.from("not json", "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  assert.equal(outcome.resolved.length, 1);
  assert.equal(processor.stats().deadLettered, 1);
  const text = readFileSync(join(dir, "dead.jsonl"), "utf8");
  assert.ok(text.includes("invalid_json"));
  await processor.close();
});
test("processor: a schema-invalid event goes to the dead letter file", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PROCESSOR_DEAD_LETTER_FILE: join(dir, "dead.jsonl") });
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const outcome = await processor.processBatch([{ value: Buffer.from(JSON.stringify({ bad: true }), "utf8"), offset: "1", topic: "honeypot.events", partition: 0 }]);
  assert.equal(outcome.resolved.length, 1);
  assert.equal(processor.stats().deadLettered, 1);
  const text = readFileSync(join(dir, "dead.jsonl"), "utf8");
  assert.ok(text.includes("schema"));
  await processor.close();
});
test("processor: the dead letter file stops growing at the byte cap", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PROCESSOR_DEAD_LETTER_FILE: join(dir, "dead.jsonl"), PROCESSOR_DEAD_LETTER_MAX_BYTES: 100 });
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  for (let i = 0; i < 20; i += 1) {
    await processor.processBatch([{ value: Buffer.from("bad json", "utf8"), offset: String(i), topic: "honeypot.events", partition: 0 }]);
  }
  const size = readFileSync(join(dir, "dead.jsonl"), "utf8").length;
  assert.ok(size <= 300, `size ${size}`);
  await processor.close();
});
test("processor: offsets resolve only after a successful bulk write", async () => {
  const cfg = baseConfig({});
  let bulkCalls = 0;
  const es = {
    async bulk({ body }) {
      bulkCalls += 1;
      return { body: { items: [{ index: { status: 201 } }] } };
    },
  };
  const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: async () => {} });
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({});
  const outcome = await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "5", topic: "honeypot.events", partition: 0 }]);
  assert.equal(bulkCalls, 1);
  assert.equal(outcome.resolved.length, 1);
  assert.equal(outcome.resolved[0].offset, "5");
  await processor.close();
});
test("processor: an Elasticsearch outage pauses consumption without losing messages", async () => {
  const cfg = baseConfig({});
  const es = {
    async bulk() { throw new Error("connection refused"); },
  };
  const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) });
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({});
  const promise = processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "7", topic: "honeypot.events", partition: 0 }]);
  await new Promise((resolve) => setTimeout(resolve, 100));
  await indexer.close();
  const outcome = await promise;
  assert.equal(outcome.resolved.length, 0);
  assert.ok(outcome.remaining && outcome.remaining.length > 0);
  await processor.close();
});
test("processor: events of one session are applied in order", async () => {
  const cfg = baseConfig({});
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const e1 = makeEvent({ id: "00000000-0000-4000-8000-000000000021", timestamp: "2026-10-21T00:00:00Z", eventType: "connection_open", payload: {} });
  const e2 = makeEvent({ id: "00000000-0000-4000-8000-000000000022", timestamp: "2026-10-21T00:01:00Z", eventType: "command", payload: { command: "ls" } });
  const e3 = makeEvent({ id: "00000000-0000-4000-8000-000000000023", timestamp: "2026-10-21T00:02:00Z", eventType: "connection_close", payload: { reason: "client_quit" } });
  await processor.processBatch([
    { value: Buffer.from(JSON.stringify(e1), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 },
    { value: Buffer.from(JSON.stringify(e2), "utf8"), offset: "1", topic: "honeypot.events", partition: 0 },
    { value: Buffer.from(JSON.stringify(e3), "utf8"), offset: "2", topic: "honeypot.events", partition: 0 },
  ]);
  const sessionDoc = indexer.docs.find((d) => d.index === "honeypot-sessions");
  assert.ok(sessionDoc);
  assert.equal(sessionDoc.body.eventCount, 3);
  assert.equal(sessionDoc.body.closed, true);
  await processor.close();
});
test("processor: graceful shutdown flushes and disconnects", async () => {
  const cfg = baseConfig({});
  const indexer = fakeIndexer();
  let closed = false;
  indexer.close = async () => { closed = true; };
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({});
  await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  await processor.close();
  assert.equal(closed, true);
  assert.ok(indexer.docs.length >= 1);
});
test("processor: stats are logged without payloads", async () => {
  const cfg = baseConfig({});
  const log = capturingLogger();
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: log, indexer });
  const event = makeEvent({ payload: { command: "cat /etc/passwd", password: "hunter2-secret" } });
  await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  const stats = processor.stats();
  assert.ok(stats.consumed >= 1);
  assert.ok(!JSON.stringify(stats).includes("hunter2-secret"));
  await processor.close();
});
test("tools: es-setup creates templates idempotently", async () => {
  const cfg = baseConfig({});
  const es = fakeEs();
  let templateCalls = 0;
  es.indices.putIndexTemplate = async () => { templateCalls += 1; return {}; };
  const first = await setupEs({ config: cfg, es });
  const second = await setupEs({ config: cfg, es });
  assert.equal(first.eventsTemplate, true);
  assert.equal(second.eventsTemplate, true);
  assert.equal(templateCalls, 4);
});
test("tools: es-summary prints counts and never prints passwords or commands", async () => {
  const cfg = baseConfig({});
  const es = fakeEs();
  const lines = [];
  const result = await summarizeEs({ config: cfg, es, print: (line) => lines.push(line) });
  assert.equal(result.sessions, 1);
  const all = lines.join("\n");
  assert.ok(all.includes("ssh"));
  assert.ok(all.includes("command"));
  assert.ok(!all.includes("hunter2"));
  assert.ok(!all.includes("cat /etc/passwd"));
});
test("compose: kafka, elasticsearch and grafana ports are bound to 127.0.0.1", () => {
  const text = readFileSync(new URL("../../../docker-compose.yml", import.meta.url), "utf8");
  assert.ok(text.includes("127.0.0.1:9092:9092"));
  assert.ok(text.includes("127.0.0.1:9200:9200"));
  assert.ok(text.includes("127.0.0.1:3000:3000"));
});
test("compose: elasticsearch heap is limited and security is marked dev-only", () => {
  const text = readFileSync(new URL("../../../docker-compose.yml", import.meta.url), "utf8");
  assert.ok(text.includes("-Xms512m"));
  assert.ok(text.includes("-Xmx512m"));
  assert.ok(text.includes("DEV ONLY"));
  assert.ok(text.includes('xpack.security.enabled: "false"'));
  assert.ok(text.includes("ingest.geoip.downloader.enabled"));
});
test("integration: ssh, http and ftp events flow through the processor into the fake Elasticsearch", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PERSONA_SEED: SEED, HONEYPOT_HOSTNAME: "srv-web-01", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, FTP_AUTH_FAIL_DELAY_MS: 0, KAFKA_ENABLED: "true" });
  cfg.SSH_PORT = 0; cfg.HTTP_PORT = 0; cfg.FTP_PORT = 0;
  const producer = { calls: [], async connect() {}, async send({ messages }) { this.calls.push(...messages); }, async disconnect() {} };
  const fakeKafkaClient = () => ({ producer: () => producer, admin: () => ({}), consumer: () => ({}) });
  const result = await startAll({ config: cfg, logger: silentLogger, createKafkaClient: fakeKafkaClient });
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
    await new Promise((resolve) => setTimeout(resolve, 300));
    await result.sinkFactory.close();
    assert.ok(producer.calls.length >= 3, `producer calls ${producer.calls.length}`);
    const es = fakeEs();
    const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: async () => {} });
    const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
    const messages = producer.calls.map((m, i) => ({ value: Buffer.from(m.value, "utf8"), offset: String(i), topic: "honeypot.events", partition: 0 }));
    const outcome = await processor.processBatch(messages);
    assert.ok(outcome.resolved.length >= 3);
    assert.ok(es.docs.length >= 3);
    const services = new Set(es.docs.filter((d) => d.body.honeypot).map((d) => d.body.honeypot.service));
    assert.ok(services.has("ssh") && services.has("http") && services.has("ftp"), [...services].join(","));
    await processor.close();
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("integration: a honeytoken event is indexed and counted in its session", async () => {
  const cfg = baseConfig({});
  const es = fakeEs();
  const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: async () => {} });
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({ eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "used", via: "ssh_command" } });
  await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  const eventDoc = es.docs.find((d) => d.body.eventType === "honeytoken");
  assert.ok(eventDoc);
  const sessionDoc = es.docs.find((d) => d.index === "honeypot-sessions");
  assert.ok(sessionDoc);
  assert.equal(sessionDoc.body.honeytokens[0].tokenId, "ht-abcdef12");
  assert.ok(!JSON.stringify(sessionDoc.body).includes("secret"));
  await processor.close();
});

test("processor: an ssh event sequence produces an indexed session document (fake ES that validates every bulk item against the real mapping)", async () => {
  const { buildTemplates } = await import("../../../packages/search/src/templates.js");
  const { validateDocument } = await import("../../../packages/search/src/validate.js");
  const { eventsTemplate, sessionsTemplate } = buildTemplates("honeypot");
  const cfg = baseConfig({});
  const validated = [];
  const es = {
    async bulk({ body }) {
      const items = [];
      for (let i = 0; i < body.length; i += 2) {
        const action = body[i].index;
        const doc = body[i + 1];
        const mapping = action._index === "honeypot-sessions" ? sessionsTemplate.template.mappings : eventsTemplate.template.mappings;
        const result = validateDocument(doc, mapping);
        validated.push({ index: action._index, ok: result.ok, errors: result.errors });
        if (!result.ok) items.push({ index: { status: 400, error: { type: "strict_dynamic_mapping_exception", reason: result.errors.join("; ") } } });
        else items.push({ index: { status: 201 } });
      }
      return { body: { items } };
    },
  };
  const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: async () => {} });
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const base = { honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "sess-ssh-1", source: { ip: "127.0.0.1", port: 1234 } };
  const events = [
    makeEvent({ ...base, eventType: "connection_open", payload: {} }),
    makeEvent({ ...base, eventType: "auth_attempt", payload: { username: "admin", success: true } }),
    makeEvent({ ...base, eventType: "command", payload: { command: "ls" } }),
    makeEvent({ ...base, eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "used", via: "ssh_command" } }),
    makeEvent({ ...base, eventType: "connection_close", payload: { reason: "client_quit" } }),
  ];
  const outcome = await processor.processBatch(events.map((e, i) => ({ value: Buffer.from(JSON.stringify(e), "utf8"), offset: String(i), topic: "honeypot.events", partition: 0 })));
  assert.ok(validated.some((v) => v.index === "honeypot-sessions" && v.ok), JSON.stringify(validated));
  assert.equal(outcome.resolved.length, 5);
  assert.ok(processor.stats().sessionsIndexed >= 1);
  await processor.close();
});

test("processor: Elasticsearch rejection reasons are kept in the dead letter reason", async () => {
  const dir = tempDir();
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: dir, PROCESSOR_DEAD_LETTER_FILE: join(dir, "dead.jsonl") });
  const es = {
    async bulk({ body }) {
      const items = [];
      for (let i = 0; i < body.length; i += 2) {
        if (body[i].index._index === "honeypot-sessions") items.push({ index: { status: 400, error: { type: "strict_dynamic_mapping_exception", reason: "mapping set to strict, dynamic introduction of [connection_open] within [eventTypeCounts] is not allowed" } } });
        else items.push({ index: { status: 201 } });
      }
      return { body: { items } };
    },
  };
  const indexer = createBulkIndexer({ es, config: cfg, logger: silentLogger, sleep: async () => {} });
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({ eventType: "command", payload: { command: "ls" } });
  await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  assert.ok(processor.stats().rejectedByEs >= 1);
  const text = readFileSync(join(dir, "dead.jsonl"), "utf8");
  assert.ok(text.includes("es:strict_dynamic_mapping_exception:eventTypeCounts"), text);
  await processor.close();
});

test("processor: stats count sessionsIndexed", async () => {
  const cfg = baseConfig({});
  const indexer = fakeIndexer();
  const processor = createProcessor({ config: cfg, logger: silentLogger, indexer });
  const event = makeEvent({ eventType: "command", payload: { command: "ls" } });
  await processor.processBatch([{ value: Buffer.from(JSON.stringify(event), "utf8"), offset: "0", topic: "honeypot.events", partition: 0 }]);
  assert.equal(processor.stats().sessionsIndexed, 1);
  await processor.close();
});

test("tools: es-summary warns when events exist but sessions do not", async () => {
  const cfg = baseConfig({});
  const es = {
    async search() {
      return { body: { aggregations: { by_service: { buckets: [{ key: "ssh", doc_count: 2 }] }, by_type: { buckets: [{ key: "command", doc_count: 2 }] }, by_ip: { buckets: [{ key: "127.0.0.1", doc_count: 2 }] }, by_honeytoken: { buckets: [] }, oldest: { value_as_string: "2026-10-21T00:00:00Z" }, newest: { value_as_string: "2026-10-21T01:00:00Z" } } } };
    },
    async count({ index }) {
      if (String(index).includes("sessions")) return { body: { count: 0 } };
      return { body: { count: 25 } };
    },
  };
  const lines = [];
  await summarizeEs({ config: cfg, es, print: (line) => lines.push(line) });
  assert.ok(lines.some((line) => line === "WARNING: events exist but no sessions are indexed."), lines.join("\n"));
});

test("ssh: Last login day of month is space padded like Linux", () => {
  const formatted = formatLastLogin(new Date(Date.UTC(2024, 8, 2, 9, 6, 4)));
  assert.equal(formatted, "Mon Sep  2 09:06:04 2024");
  assert.ok(!formatted.includes("Sep 02"));
});
