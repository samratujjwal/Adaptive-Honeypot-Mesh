import test from "node:test";
import assert from "node:assert/strict";
import { waitForStartup } from "../src/startup.js";
import { start } from "../src/index.js";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { createProcessor } from "../src/processor.js";

const silent = { info: () => {}, warn: () => {}, error: () => {} };

test("startup: fake Kafka/ES that fail twice then succeed -> processor startup helper succeeds after waiting", async () => {
  let attempts = 0;
  const logs = [];
  const logger = { info: () => {}, warn: (obj, msg) => logs.push(msg), error: () => {} };
  await waitForStartup({
    checks: [{ name: "elasticsearch", check: async () => { attempts += 1; if (attempts < 3) { const e = new Error("refused"); e.code = "ECONNREFUSED"; throw e; } } }],
    logger,
    sleep: async () => {},
  });
  assert.equal(attempts, 3);
  assert.ok(logs.some((line) => line.includes("elasticsearch") && line.includes("ECONNREFUSED")));
});

test("startup: fake ES that always fails -> helper reports the service and error code, no event body in the log", async () => {
  const logs = [];
  const logger = { info: () => {}, warn: (obj, msg) => logs.push(msg), error: () => {} };
  await assert.rejects(() => waitForStartup({
    checks: [{ name: "elasticsearch", check: async () => { const e = new Error("refused"); e.code = "ECONNREFUSED"; throw e; } }],
    logger,
    sleep: async () => {},
    budgetMs: 100,
  }), /elasticsearch.*ECONNREFUSED/);
  assert.ok(!logs.join(" ").includes("password"));
});

test("startup: ensureTemplates is called exactly once before consuming (fake ES)", async () => {
  const cfg = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: "/tmp", PROCESSOR_DEAD_LETTER_FILE: "/tmp/dead.jsonl" });
  let ensureCalls = 0;
  const fakeEs = { info: async () => ({}), indices: { putIndexTemplate: async () => ({}), exists: async () => true, create: async () => ({}) } };
  const fakeKafkaClient = { admin: () => ({ connect: async () => {}, listTopics: async () => [], disconnect: async () => {} }), consumer: () => ({ connect: async () => {}, subscribe: async () => {}, run: async () => {}, disconnect: async () => {} }) };
  const fakeIndexer = { index: async () => ({ retries: 0, rejected: [], remaining: [] }), close: async () => {} };
  const result = await start({
    config: cfg,
    logger: silent,
    es: fakeEs,
    kafkaClient: fakeKafkaClient,
    indexer: fakeIndexer,
    geoip: { lookup: async () => null },
    noStatsTimer: true,
    waitForStartupFn: async () => {},
    ensureTemplatesFn: async () => { ensureCalls += 1; },
  });
  assert.equal(ensureCalls, 1);
  await result.close();
});
