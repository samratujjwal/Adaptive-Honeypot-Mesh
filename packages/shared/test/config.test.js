import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";

test("config: defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.NODE_ENV, "development");
  assert.equal(cfg.LOG_LEVEL, "info");
  assert.equal(cfg.SSH_PORT, 2222);
  assert.equal(cfg.HTTP_PORT, 8080);
  assert.equal(cfg.FTP_PORT, 2121);
  assert.equal(cfg.BIND_HOST, "127.0.0.1");
  assert.equal(cfg.LLM_MODE, "mock");
  assert.equal(cfg.GEMINI_MODEL, "gemini-2.5-flash");
  assert.equal(cfg.KAFKA_BROKERS, "localhost:9092");
  assert.equal(cfg.ELASTICSEARCH_URL, "http://localhost:9200");
  assert.equal(cfg.NODE_ID, "node-01");
});

test("config: invalid port fails and names the field", () => {
  assert.throws(() => loadConfig({ SSH_PORT: "99999" }), /SSH_PORT/);
});

test("config: real mode without a key fails and names the field", () => {
  assert.throws(() => loadConfig({ LLM_MODE: "real" }), /GEMINI_API_KEY/);
  assert.throws(() => loadConfig({ LLM_MODE: "real", GEMINI_API_KEY: "" }), /GEMINI_API_KEY/);
});

test("config: mock mode without a key passes", () => {
  const cfg = loadConfig({ LLM_MODE: "mock" });
  assert.equal(cfg.LLM_MODE, "mock");
  assert.equal(cfg.GEMINI_API_KEY, undefined);
});

test("config: invalid LLM_MODE fails", () => {
  assert.throws(() => loadConfig({ LLM_MODE: "bogus" }), /LLM_MODE/);
});
