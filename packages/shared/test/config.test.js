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
  assert.equal(cfg.GEMINI_MODEL, "gemini-2.5-flash-lite");
  assert.equal(cfg.GEMINI_FALLBACK_MODEL, "gemini-2.5-flash");
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

test("config: fallback model defaults to gemini-2.5-flash", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.GEMINI_FALLBACK_MODEL, "gemini-2.5-flash");
});

test("config: SSH defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.SSH_IDLE_TIMEOUT_MS, 120000);
  assert.equal(cfg.SSH_MAX_SESSION_MS, 600000);
  assert.equal(cfg.SSH_MAX_CONNECTIONS, 50);
  assert.equal(cfg.SSH_MAX_CONNECTIONS_PER_IP, 5);
  assert.equal(cfg.SSH_MAX_AUTH_ATTEMPTS, 6);
  assert.equal(cfg.SSH_IDENT, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
  assert.equal(cfg.HONEYPOT_HOSTNAME, "srv-web-01");
  assert.equal(cfg.ALLOW_PUBLIC_BIND, false);
  assert.equal(cfg.EVENT_DIR, "data/events");
  assert.equal(cfg.SSH_HOST_KEY_PATH, "data/ssh/host_ed25519");
});

test("config: public bind without ALLOW_PUBLIC_BIND fails", () => {
  assert.throws(() => loadConfig({ BIND_HOST: "0.0.0.0" }), /BIND_HOST/);
  assert.throws(() => loadConfig({ BIND_HOST: "::" }), /BIND_HOST/);
});

test("config: public bind with ALLOW_PUBLIC_BIND passes", () => {
  const cfg = loadConfig({ BIND_HOST: "0.0.0.0", ALLOW_PUBLIC_BIND: "true" });
  assert.equal(cfg.BIND_HOST, "0.0.0.0");
  assert.equal(cfg.ALLOW_PUBLIC_BIND, true);
});

test("config: explicit model and fallback model are respected", () => {
  const cfg = loadConfig({
    GEMINI_MODEL: "gemini-2.5-flash",
    GEMINI_FALLBACK_MODEL: "gemini-2.5-flash-lite",
  });
  assert.equal(cfg.GEMINI_MODEL, "gemini-2.5-flash");
  assert.equal(cfg.GEMINI_FALLBACK_MODEL, "gemini-2.5-flash-lite");
});

test("config: LLM defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.LLM_TIMEOUT_MS, 8000);
  assert.equal(cfg.LLM_RPM, 8);
  assert.equal(cfg.LLM_DAILY_LIMIT, 400);
  assert.equal(cfg.LLM_SESSION_LIMIT, 40);
  assert.equal(cfg.LLM_CACHE_MAX, 500);
  assert.equal(cfg.LLM_CACHE_TTL_MS, 3600000);
  assert.equal(cfg.LLM_MAX_OUTPUT_CHARS, 4000);
  assert.equal(cfg.LLM_TEMPERATURE, 0.4);
  assert.equal(cfg.GEMINI_THINKING_BUDGET, 0);
  assert.equal(cfg.LLM_USAGE_FILE, "data/llm-usage.json");
});

test("config: invalid LLM limits are rejected", () => {
  assert.throws(() => loadConfig({ LLM_TIMEOUT_MS: 0 }), /LLM_TIMEOUT_MS/);
  assert.throws(() => loadConfig({ LLM_RPM: -1 }), /LLM_RPM/);
  assert.throws(() => loadConfig({ LLM_DAILY_LIMIT: 0 }), /LLM_DAILY_LIMIT/);
  assert.throws(() => loadConfig({ LLM_SESSION_LIMIT: 0 }), /LLM_SESSION_LIMIT/);
  assert.throws(() => loadConfig({ LLM_CACHE_MAX: 0 }), /LLM_CACHE_MAX/);
  assert.throws(() => loadConfig({ LLM_TEMPERATURE: 2 }), /LLM_TEMPERATURE/);
  assert.throws(() => loadConfig({ GEMINI_THINKING_BUDGET: -1 }), /GEMINI_THINKING_BUDGET/);
});
