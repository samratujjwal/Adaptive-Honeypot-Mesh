import assert from "node:assert";
import test from "node:test";
import { readFileSync } from "node:fs";
import { buildTemplates } from "../src/templates.js";
import { eventsIndexName } from "../src/index-name.js";
import { createBulkIndexer } from "../src/bulk-indexer.js";
import { createLogger } from "../../../packages/shared/src/logger.js";

const silentLogger = createLogger({ level: "silent" });

function capturingLogger() {
  const records = [];
  return {
    records,
    info: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    warn: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
    error: (obj, msg) => records.push(JSON.stringify(obj) + " " + String(msg || "")),
  };
}

test("search: events template maps source.ip as ip and geo.location as geo_point", () => {
  const { eventsTemplate } = buildTemplates("honeypot");
  assert.deepEqual(eventsTemplate.index_patterns, ["honeypot-events-*"]);
  assert.equal(eventsTemplate.template.mappings.properties.source.properties.ip.type, "ip");
  assert.equal(eventsTemplate.template.mappings.properties.enrich.properties.geo.properties.location.type, "geo_point");
});
test("search: payload is flattened and the top-level mapping is strict", () => {
  const { eventsTemplate } = buildTemplates("honeypot");
  assert.equal(eventsTemplate.template.mappings.dynamic, "strict");
  assert.equal(eventsTemplate.template.mappings.properties.payload.type, "flattened");
  assert.equal(eventsTemplate.template.mappings.properties.payload.ignore_above, 1024);
  assert.equal(eventsTemplate.template.settings.number_of_shards, 1);
  assert.equal(eventsTemplate.template.settings.number_of_replicas, 0);
  assert.equal(eventsTemplate.template.settings["index.mapping.total_fields.limit"], 200);
});
test("search: index name uses the UTC date of the event timestamp", () => {
  assert.equal(eventsIndexName("honeypot", "2026-10-21T09:41:07Z"), "honeypot-events-2026.10.21");
  assert.equal(eventsIndexName("honeypot", "2026-01-02T00:30:00Z"), "honeypot-events-2026.01.02");
});
test("search: sessions template maps timestamps and counters", () => {
  const { sessionsTemplate } = buildTemplates("honeypot");
  assert.deepEqual(sessionsTemplate.index_patterns, ["honeypot-sessions"]);
  assert.equal(sessionsTemplate.template.mappings.dynamic, "strict");
  assert.equal(sessionsTemplate.template.mappings.properties.firstSeen.type, "date");
  assert.equal(sessionsTemplate.template.mappings.properties.lastSeen.type, "date");
  assert.equal(sessionsTemplate.template.mappings.properties.eventCount.type, "integer");
  assert.equal(sessionsTemplate.template.mappings.properties.authAttempts.type, "integer");
  assert.equal(sessionsTemplate.template.mappings.properties.commandCount.type, "integer");
});
test("indexer: uses the event id as the document id", async () => {
  const calls = [];
  const es = { async bulk({ body }) { calls.push(body); return { body: { items: [{ index: { status: 201 } }] } }; } };
  const indexer = createBulkIndexer({ es, config: { PROCESSOR_ES_TIMEOUT_MS: 10000 }, logger: silentLogger, sleep: async () => {} });
  await indexer.index([{ index: "honeypot-events-2026.10.21", id: "event-id-123", body: { id: "event-id-123" } }]);
  assert.equal(calls[0][0].index._id, "event-id-123");
  assert.equal(calls[0][0].index._index, "honeypot-events-2026.10.21");
  await indexer.close();
});
test("indexer: bulk partial failures retry only the failed items", async () => {
  const calls = [];
  let attempt = 0;
  const es = {
    async bulk({ body }) {
      attempt += 1;
      calls.push(body);
      if (attempt === 1) {
        return { body: { items: [{ index: { status: 201 } }, { index: { status: 429, error: { type: "es_rejected", reason: "busy" } } }] } };
      }
      return { body: { items: [{ index: { status: 201 } }] } };
    },
  };
  const indexer = createBulkIndexer({ es, config: {}, logger: silentLogger, sleep: async () => {} });
  const outcome = await indexer.index([
    { index: "idx", id: "a", body: { id: "a" } },
    { index: "idx", id: "b", body: { id: "b" } },
  ]);
  assert.equal(outcome.rejected.length, 0);
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0].index._id, "b");
  await indexer.close();
});
test("indexer: retries with backoff when Elasticsearch is down and never loses events", async () => {
  let attempts = 0;
  const es = {
    async bulk() {
      attempts += 1;
      if (attempts < 3) throw new Error("connection refused");
      return { body: { items: [{ index: { status: 201 } }] } };
    },
  };
  const sleeps = [];
  const indexer = createBulkIndexer({ es, config: {}, logger: silentLogger, sleep: async (ms) => { sleeps.push(ms); } });
  const outcome = await indexer.index([{ index: "idx", id: "a", body: { id: "a" } }]);
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps.slice(0, 2), [1000, 2000]);
  assert.equal(outcome.remaining.length, 0);
  await indexer.close();
});
test("indexer: permanently rejected documents are returned and not retried", async () => {
  const calls = [];
  const es = {
    async bulk({ body }) {
      calls.push(body);
      return { body: { items: [{ index: { status: 400, error: { type: "mapper_parsing_exception", reason: "bad mapping" } } }] } };
    },
  };
  const indexer = createBulkIndexer({ es, config: {}, logger: silentLogger, sleep: async () => {} });
  const outcome = await indexer.index([{ index: "idx", id: "bad", body: { id: "bad" } }]);
  assert.equal(calls.length, 1);
  assert.equal(outcome.rejected.length, 1);
  assert.equal(outcome.rejected[0].doc.id, "bad");
  await indexer.close();
});
test("indexer: Elasticsearch errors never log document bodies", async () => {
  const log = capturingLogger();
  const es = {
    async bulk() {
      return { body: { items: [{ index: { status: 400, error: { type: "mapper_parsing_exception", reason: "bad mapping" } } }] } };
    },
  };
  const indexer = createBulkIndexer({ es, config: {}, logger: log, sleep: async () => {} });
  await indexer.index([{ index: "idx", id: "doc1", body: { id: "doc1", payload: { password: "secret-pass-123", command: "rm -rf /" } } }]);
  const all = log.records.join("\n");
  assert.ok(!all.includes("secret-pass-123"), all);
  assert.ok(!all.includes("rm -rf /"), all);
  assert.ok(all.includes("doc1"));
  await indexer.close();
});
test("deps: elasticsearch client and geoip package are pinned to exact versions", () => {
  const searchPkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const enrichPkg = JSON.parse(readFileSync(new URL("../../enrich/package.json", import.meta.url), "utf8"));
  const esVersion = searchPkg.dependencies["@elastic/elasticsearch"];
  const geoVersion = enrichPkg.dependencies["geoip-lite"] || enrichPkg.dependencies["fast-geoip"];
  assert.ok(esVersion && !esVersion.startsWith("^") && !esVersion.startsWith("~") && /^\d+\.\d+\.\d+$/.test(esVersion), esVersion);
  assert.ok(geoVersion && !geoVersion.startsWith("^") && !geoVersion.startsWith("~") && /^\d+\.\d+\.\d+$/.test(geoVersion), geoVersion);
});

test("search: every event document field exists in the strict events mapping", async () => {
  const { buildTemplates } = await import("../src/templates.js");
  const { validateDocument } = await import("../src/validate.js");
  const { createEvent } = await import("../../../packages/shared/src/event.js");
  const { eventsTemplate } = buildTemplates("honeypot");
  const event = createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "test-session-12345678",
    source: { ip: "8.8.8.8", port: 1234 },
    eventType: "command",
    payload: { command: "ls", nested: { a: 1 } },
  });
  const doc = { ...event, enrich: { ipClass: "public", geo: { country: "US", countryName: "United States", region: "CA", city: "X", location: { lat: 37.7, lon: -97.8 }, timezone: "America/Chicago" } }, ingestedAt: "2026-10-26T10:00:00Z" };
  const result = validateDocument(doc, eventsTemplate.template.mappings);
  assert.deepEqual(result.errors, [], result.errors.join("; "));
  assert.equal(result.ok, true);
});

test("search: every session document field exists in the strict sessions mapping", async () => {
  const { buildTemplates } = await import("../src/templates.js");
  const { validateDocument } = await import("../src/validate.js");
  const { createSessionAggregator } = await import("../../../services/processor/src/sessions.js");
  const { createEvent } = await import("../../../packages/shared/src/event.js");
  const { sessionsTemplate } = buildTemplates("honeypot");
  const agg = createSessionAggregator({});
  const geo = { ipClass: "loopback", geo: null, ip: "127.0.0.1" };
  const base = { honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "sess-ssh-1", source: { ip: "127.0.0.1", port: 1234 } };
  await agg.apply(createEvent({ ...base, eventType: "connection_open", payload: {} }), geo);
  await agg.apply(createEvent({ ...base, eventType: "auth_attempt", payload: { username: "admin", success: true } }), geo);
  await agg.apply(createEvent({ ...base, eventType: "command", payload: { command: "ls" } }), geo);
  await agg.apply(createEvent({ ...base, eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "used", via: "ssh_command" } }), geo);
  await agg.apply(createEvent({ ...base, eventType: "file_transfer", payload: { direction: "download", savedAs: "/tmp/x.txt", size: 123, sha256: "a".repeat(64) } }), geo);
  const session = agg.get("sess-ssh-1");
  const result = validateDocument(session, sessionsTemplate.template.mappings);
  assert.deepEqual(result.errors, [], result.errors.join("; "));
  assert.equal(result.ok, true);
});
