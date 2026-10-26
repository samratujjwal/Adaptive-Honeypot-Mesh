import assert from "node:assert";
import http from "node:http";
import net from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { validateEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { createHttpHoneypot } from "../src/server.js";
import { wpCookieNameForTest } from "../src/router.js";

const silentLogger = createLogger({ level: "silent" });

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-http-"));
}

function makeServer(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const config = loadConfig({
    BIND_HOST: "127.0.0.1",
    HTTP_PORT: 8080,
    NODE_ID: "node-01",
    EVENT_DIR: eventsDir,
    LLM_MODE: overrides.llmMode || "mock",
    GEMINI_API_KEY: overrides.llmMode === "real" ? "FAKE-KEY-123" : undefined,
    ...(overrides.configOverrides || {}),
  });
  const sink = createFileSink({ dir: eventsDir, service: "http", logger: silentLogger });
  const logger = overrides.logger || silentLogger;
  const honeypot = createHttpHoneypot({ config, sink, llmService: overrides.llmService || null, logger, now: overrides.now });
  return { dir, eventsDir, config, sink, honeypot };
}

async function startServer(overrides = {}) {
  const made = makeServer(overrides);
  await made.honeypot.listen(0, "127.0.0.1");
  const port = made.honeypot.address().port;
  return { ...made, port };
}

function readEvents(eventsDir) {
  const file = join(eventsDir, "http.jsonl");
  if (!existsSync(file)) return [];
  const text = readFileSync(file, "utf8").trim();
  if (!text) return [];
  return text.split("\n").map((line) => JSON.parse(line));
}

async function waitForEvents(eventsDir, predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const events = readEvents(eventsDir);
    const found = events.filter(predicate);
    if (found.length > 0) return found;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for events in ${eventsDir}: ${JSON.stringify(readEvents(eventsDir))}`);
}

function httpRequest(port, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      method: options.method || "GET",
      path: options.path || "/",
      headers: options.headers || {},
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    req.on("error", (error) => reject(error));
    if (options.body) req.write(options.body);
    req.end();
  });
}

function makeFakeHttpLlm(options = {}) {
  const calls = [];
  const llm = {
    calls,
    async respondHttp({ request, ctx }) {
      calls.push({ request, ctx });
      if (options.shouldFail) return { ok: false };
      if (options.delayMs) await new Promise((resolve) => setTimeout(resolve, options.delayMs));
      if (options.invalid) return { ok: true, status: 999, contentType: "text/html", body: "bad", meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0 } };
      const body = options.body !== undefined ? options.body : "<html><body>llm-page</body></html>";
      return {
        ok: true,
        status: options.status !== undefined ? options.status : 200,
        contentType: options.contentType || "text/html; charset=UTF-8",
        body,
        meta: { source: options.source || "llm", model: "fake", cached: Boolean(options.cached), fallback: false, latencyMs: 0 },
      };
    },
  };
  return llm;
}

test("config: HTTP defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.HTTP_PORT, 8080);
  assert.equal(cfg.HTTP_SERVER_HEADER, "nginx/1.18.0 (Ubuntu)");
  assert.equal(cfg.HTTP_MAX_BODY_BYTES, 65536);
  assert.equal(cfg.HTTP_MAX_CONNECTIONS, 200);
  assert.equal(cfg.HTTP_MAX_CONNECTIONS_PER_IP, 20);
  assert.equal(cfg.HTTP_MAX_REQ_PER_MIN_PER_IP, 300);
  assert.equal(cfg.HTTP_REQUEST_TIMEOUT_MS, 10000);
  assert.equal(cfg.HTTP_LLM_ENABLED, true);
  assert.equal(cfg.HTTP_LLM_DEADLINE_MS, 5000);
  assert.equal(cfg.HTTP_SESSION_WINDOW_MS, 1800000);
});

test("config: invalid HTTP limits are rejected", () => {
  assert.throws(() => loadConfig({ HTTP_MAX_BODY_BYTES: 0 }), /HTTP_MAX_BODY_BYTES/);
  assert.throws(() => loadConfig({ HTTP_MAX_CONNECTIONS: 0 }), /HTTP_MAX_CONNECTIONS/);
  assert.throws(() => loadConfig({ HTTP_MAX_CONNECTIONS_PER_IP: 0 }), /HTTP_MAX_CONNECTIONS_PER_IP/);
  assert.throws(() => loadConfig({ HTTP_MAX_REQ_PER_MIN_PER_IP: 0 }), /HTTP_MAX_REQ_PER_MIN_PER_IP/);
  assert.throws(() => loadConfig({ HTTP_REQUEST_TIMEOUT_MS: 0 }), /HTTP_REQUEST_TIMEOUT_MS/);
  assert.throws(() => loadConfig({ HTTP_LLM_DEADLINE_MS: 0 }), /HTTP_LLM_DEADLINE_MS/);
  assert.throws(() => loadConfig({ HTTP_SESSION_WINDOW_MS: 0 }), /HTTP_SESSION_WINDOW_MS/);
});

test("http: refuses to bind to 0.0.0.0 without ALLOW_PUBLIC_BIND", async () => {
  assert.throws(() => loadConfig({ BIND_HOST: "0.0.0.0" }), /BIND_HOST/);
  const made = makeServer({});
  const badConfig = { ...made.config, BIND_HOST: "0.0.0.0", ALLOW_PUBLIC_BIND: false };
  const bad = createHttpHoneypot({ config: badConfig, sink: made.sink, logger: silentLogger });
  await assert.rejects(() => bad.listen(0, "0.0.0.0"), /ALLOW_PUBLIC_BIND/);
  await bad.close();
  await made.honeypot.close();
  rmSync(made.dir, { recursive: true, force: true });
});

test("http: responses carry the configured Server header and no X-Powered-By", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/" });
    assert.equal(res.headers.server, "nginx/1.18.0 (Ubuntu)");
    assert.equal(res.headers["x-powered-by"], undefined);
    assert.ok(res.headers.date);
    assert.ok(res.headers["content-type"]);
    assert.ok(res.headers["content-length"]);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: GET / returns the fake site page", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("Silverline Services"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: unknown path returns an nginx-style 404 when the LLM is off", async () => {
  const made = await startServer({ configOverrides: { HTTP_LLM_ENABLED: "false" } });
  try {
    const res = await httpRequest(made.port, { path: "/nope-unknown-xyz" });
    assert.equal(res.status, 404);
    assert.ok(res.body.includes("404 Not Found"));
    assert.ok(res.body.includes("nginx/1.18.0 (Ubuntu)"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: HEAD returns headers without a body", async () => {
  const made = await startServer({});
  try {
    const getRes = await httpRequest(made.port, { path: "/" });
    const headRes = await httpRequest(made.port, { method: "HEAD", path: "/" });
    assert.equal(headRes.status, 200);
    assert.equal(headRes.body, "");
    assert.equal(headRes.headers["content-length"], getRes.headers["content-length"]);
    assert.equal(headRes.headers["content-type"], getRes.headers["content-type"]);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: unsupported methods return 405 and OPTIONS returns Allow", async () => {
  const made = await startServer({});
  try {
    const putRes = await httpRequest(made.port, { method: "PUT", path: "/" });
    assert.equal(putRes.status, 405);
    assert.ok(putRes.headers.allow.includes("GET"));
    const optRes = await httpRequest(made.port, { method: "OPTIONS", path: "/" });
    assert.equal(optRes.status, 200);
    assert.equal(optRes.headers.allow, "GET, HEAD, POST, OPTIONS");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: wp-login page is served", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/wp-login.php" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("Log In") || res.body.includes("log"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: wrong wp-login credentials show the WordPress error and are logged", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=victim&pwd=wrongpass123" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("<strong>Error:</strong>"));
    assert.ok(res.body.includes("victim"));
    assert.ok(res.body.includes("is incorrect"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.method === "POST");
    assert.equal(events[0].payload.credentials.username, "victim");
    assert.equal(events[0].payload.credentials.password, "wrongpass123");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: weak wp-login credentials set a cookie and redirect to the dashboard", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=admin&pwd=admin123" });
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, "/wp-admin/");
    assert.ok(res.headers["set-cookie"] && res.headers["set-cookie"][0].includes("wordpress_logged_in_"));
    assert.ok(res.headers["set-cookie"][0].includes("HttpOnly"));
    const cookie = res.headers["set-cookie"][0].split(";")[0];
    const dash = await httpRequest(made.port, { path: "/wp-admin/", headers: { cookie } });
    assert.equal(dash.status, 200);
    assert.ok(dash.body.includes("Dashboard"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: wp-admin without a session redirects to the login", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/wp-admin/" });
    assert.equal(res.status, 302);
    assert.ok(res.headers.location.includes("/wp-login.php"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: wp-admin with the issued session shows the dashboard", async () => {
  const made = await startServer({});
  try {
    const login = await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=admin&pwd=admin" });
    const cookie = login.headers["set-cookie"][0].split(";")[0];
    const dash = await httpRequest(made.port, { path: "/wp-admin/", headers: { cookie } });
    assert.equal(dash.status, 200);
    assert.ok(dash.body.includes("Dashboard"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: phpmyadmin login failure shows the MySQL access denied error", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { method: "POST", path: "/phpmyadmin/", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "pma_username=root&pma_password=bad" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("#1045 - Access denied for user 'root'@'localhost' (using password: YES)"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: generic admin login logs credentials", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { method: "POST", path: "/admin/login", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "username=attacker1&password=hunter2" });
    assert.equal(res.status, 200);
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.path === "/admin/login");
    assert.equal(events[0].payload.credentials.username, "attacker1");
    assert.equal(events[0].payload.credentials.password, "hunter2");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: .env serves a fictional file and is logged as sensitive", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/.env" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("DB_DATABASE"));
    assert.ok(!res.body.includes("AKIA"));
    assert.ok(!res.body.includes("sk_live"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.path === "/.env");
    assert.equal(events[0].payload.matchedRoute, "sensitive_env");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: .git/config is served as a fictional file", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/.git/config" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("git.") && res.body.includes("/project.git"));
    const other = await httpRequest(made.port, { path: "/.git/objects/abc" });
    assert.equal(other.status, 404);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: robots.txt lists fake disallowed paths", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/robots.txt" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("/admin"));
    assert.ok(res.body.includes("/backup"));
    assert.ok(res.body.includes("/wp-admin"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: static asset stubs return correct content types", async () => {
  const made = await startServer({});
  try {
    const css = await httpRequest(made.port, { path: "/wp-includes/style.css" });
    assert.equal(css.status, 200);
    assert.ok(css.headers["content-type"].includes("text/css"));
    const js = await httpRequest(made.port, { path: "/wp-includes/script.js" });
    assert.ok(js.headers["content-type"].includes("javascript"));
    const png = await httpRequest(made.port, { path: "/static/logo.png" });
    assert.ok(png.headers["content-type"].includes("image/png"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("app: server-status returns 403", async () => {
  const made = await startServer({});
  try {
    const res = await httpRequest(made.port, { path: "/server-status" });
    assert.equal(res.status, 403);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: unknown interesting path is answered by the LLM service", async () => {
  const llm = makeFakeHttpLlm({ body: "<html><body>llm-api-page</body></html>" });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    const res = await httpRequest(made.port, { path: "/api/users" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("llm-api-page"));
    assert.equal(llm.calls.length, 1);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: boring scanner paths never reach the LLM", async () => {
  const llm = makeFakeHttpLlm({});
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    for (const path of ["/shell.php", "/cgi-bin/test", "/wp-content/uploads/evil.php", "/random123.php"]) {
      const res = await httpRequest(made.port, { path });
      assert.equal(res.status, 404);
    }
    assert.equal(llm.calls.length, 0);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: slow LLM falls back to 404 at the deadline", async () => {
  const llm = makeFakeHttpLlm({ delayMs: 500, body: "slow-should-not-appear" });
  const made = await startServer({ llmMode: "real", llmService: llm, configOverrides: { HTTP_LLM_DEADLINE_MS: 50 } });
  try {
    const res = await httpRequest(made.port, { path: "/api/slow" });
    assert.equal(res.status, 404);
    assert.ok(!res.body.includes("slow-should-not-appear"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: invalid model output falls back to 404", async () => {
  const llm = makeFakeHttpLlm({ shouldFail: true });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    const res = await httpRequest(made.port, { path: "/api/bad" });
    assert.equal(res.status, 404);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: model status and content type are allowlisted", async () => {
  const { parseHttpOutput } = await import("../../../packages/llm/src/http-output.js");
  assert.equal(parseHttpOutput(JSON.stringify({ status: 999, contentType: "text/html; charset=UTF-8", body: "bad" })).ok, false);
  assert.equal(parseHttpOutput(JSON.stringify({ status: 200, contentType: "text/html", body: "bad" })).ok, false);
  assert.equal(parseHttpOutput(JSON.stringify({ status: 200, contentType: "text/html; charset=UTF-8", body: "ok" })).ok, true);
  const llm = makeFakeHttpLlm({ invalid: true });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    const res = await httpRequest(made.port, { path: "/api/allow" });
    assert.equal(res.status, 404);
    assert.ok(!res.body.includes("bad"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: oversize model body is truncated", async () => {
  const bigBody = "x".repeat(40000);
  const llm = makeFakeHttpLlm({ body: bigBody });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    const res = await httpRequest(made.port, { path: "/api/big" });
    assert.equal(res.status, 200);
    assert.ok(Buffer.byteLength(res.body, "utf8") <= 32768);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: GET responses are cached and POST is not", async () => {
  let getCalls = 0;
  let postCalls = 0;
  const llm = {
    calls: [],
    async respondHttp({ request }) {
      this.calls.push(request);
      if (request.method === "GET") getCalls += 1;
      else postCalls += 1;
      return { ok: true, status: 200, contentType: "text/html; charset=UTF-8", body: "cached-page", meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0 } };
    },
  };
  // Use the real service cache via a wrapper: the server calls respondHttp, so to test caching we use the real service with a fake fetch
  const { createLlmService } = await import("../../../packages/llm/src/service.js");
  let fetchCalls = 0;
  const fetchImpl = async (url, init) => {
    fetchCalls += 1;
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ status: 200, contentType: "text/html; charset=UTF-8", body: "real-cached-page" }) }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
      }),
    };
  };
  const realConfig = loadConfig({ LLM_MODE: "real", GEMINI_API_KEY: "FAKE-KEY-123", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash", HTTP_LLM_ENABLED: "true" });
  const realService = createLlmService({ config: realConfig, logger: silentLogger, fetchImpl });
  const made = await startServer({ llmMode: "real", llmService: realService });
  try {
    const first = await httpRequest(made.port, { path: "/api/cachetest" });
    assert.ok(first.body.includes("real-cached-page"));
    const second = await httpRequest(made.port, { path: "/api/cachetest" });
    assert.ok(second.body.includes("real-cached-page"));
    assert.equal(fetchCalls, 1);
    const post1 = await httpRequest(made.port, { method: "POST", path: "/api/cachetest", headers: { "content-type": "text/plain" }, body: "hi" });
    assert.ok(post1.body.includes("real-cached-page"));
    const post2 = await httpRequest(made.port, { method: "POST", path: "/api/cachetest", headers: { "content-type": "text/plain" }, body: "hi" });
    assert.ok(post2.body.includes("real-cached-page"));
    assert.equal(fetchCalls, 3);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: request details are passed as an untrusted JSON string", async () => {
  let recordedUser = null;
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    recordedUser = body.contents[0].parts[0].text;
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ status: 200, contentType: "text/html; charset=UTF-8", body: "json-page" }) }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
      }),
    };
  };
  const { createLlmService } = await import("../../../packages/llm/src/service.js");
  const realConfig = loadConfig({ LLM_MODE: "real", GEMINI_API_KEY: "FAKE-KEY-123", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" });
  const realService = createLlmService({ config: realConfig, logger: silentLogger, fetchImpl });
  const made = await startServer({ llmMode: "real", llmService: realService });
  try {
    await httpRequest(made.port, { path: "/api/jsoncheck?x=1" });
    assert.ok(recordedUser);
    const parsed = JSON.parse(recordedUser);
    assert.equal(parsed.method, "GET");
    assert.equal(parsed.path, "/api/jsoncheck");
    assert.equal(parsed.query, "x=1");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http-llm: LLM disabled by config never calls the service", async () => {
  const llm = makeFakeHttpLlm({});
  const made = await startServer({ llmMode: "real", llmService: llm, configOverrides: { HTTP_LLM_ENABLED: "false" } });
  try {
    const res = await httpRequest(made.port, { path: "/api/disabled" });
    assert.equal(res.status, 404);
    assert.equal(llm.calls.length, 0);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("gemini: accepts a custom response schema", async () => {
  const { createGeminiClient, HTTP_RESPONSE_SCHEMA } = await import("../../../packages/llm/src/gemini.js");
  let recordedBody = null;
  const fetchImpl = async (url, init) => {
    recordedBody = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ status: 200, contentType: "text/html; charset=UTF-8", body: "hi" }) }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 },
      }),
    };
  };
  const client = createGeminiClient({ apiKey: "FAKE-KEY", fetchImpl, timeoutMs: 5000, temperature: 0.4, thinkingBudget: 0, logger: silentLogger, now: () => 1000000 });
  const result = await client.generate({ model: "gemini-2.5-flash-lite", system: "s", user: "u", schema: HTTP_RESPONSE_SCHEMA });
  assert.equal(result.ok, true);
  assert.deepEqual(recordedBody.generationConfig.responseSchema, HTTP_RESPONSE_SCHEMA);
});

test("http: path traversal never reads host files", async () => {
  const made = await startServer({});
  try {
    const paths = ["/../../Windows/win.ini", "/%2e%2e/%2e%2e/Windows/win.ini", "/..%5c..%5cWindows%5cwin.ini"];
    for (const path of paths) {
      const res = await new Promise((resolve) => {
        const req = http.request({ host: "127.0.0.1", port: made.port, method: "GET", path }, (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
        });
        req.on("error", () => resolve({ status: 0, body: "" }));
        req.end();
      });
      assert.ok(res.status === 404 || res.status === 400 || res.status === 0);
      assert.ok(!res.body.includes("[fonts]") && !res.body.includes("win.ini"));
    }
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: oversize body is rejected with 413 and flagged", async () => {
  const made = await startServer({ configOverrides: { HTTP_MAX_BODY_BYTES: 100 } });
  try {
    const res = await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "x=".padEnd(200, "a") });
    assert.equal(res.status, 413);
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.responseStatus === 413);
    assert.equal(events[0].payload.bodyTruncated, true);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: header overflow is rejected", async () => {
  const made = await startServer({});
  try {
    const result = await new Promise((resolve) => {
      const req = http.request({ host: "127.0.0.1", port: made.port, method: "GET", path: "/", headers: { "x-big": "a".repeat(20000) } }, (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode }));
      });
      req.on("error", () => resolve({ status: 0 }));
      req.end();
    });
    assert.ok(result.status === 431 || result.status === 400 || result.status === 0);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: per-IP connection limit is enforced", async () => {
  const made = await startServer({ configOverrides: { HTTP_MAX_CONNECTIONS_PER_IP: 2 } });
  try {
    const sockets = [];
    for (let i = 0; i < 2; i += 1) {
      const socket = net.connect(made.port, "127.0.0.1");
      sockets.push(socket);
      await new Promise((resolve) => socket.on("connect", resolve));
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
    let thirdClosed = false;
    const third = net.connect(made.port, "127.0.0.1");
    third.on("close", () => {
      thirdClosed = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.equal(thirdClosed, true);
    for (const socket of sockets) socket.destroy();
    third.destroy();
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: request rate limit drops excess requests", async () => {
  const made = await startServer({ configOverrides: { HTTP_MAX_REQ_PER_MIN_PER_IP: 2 } });
  try {
    await httpRequest(made.port, { path: "/" });
    await httpRequest(made.port, { path: "/" });
    const third = await new Promise((resolve) => {
      const req = http.request({ host: "127.0.0.1", port: made.port, method: "GET", path: "/" }, (res) => {
        res.on("data", () => {});
        res.on("end", () => resolve({ status: res.statusCode }));
      });
      req.on("error", () => resolve({ status: 0 }));
      req.end();
    });
    assert.equal(third.status, 0);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir);
    assert.equal(events.filter((event) => event.eventType === "http_request").length, 2);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: slow request is closed by the timeout", async () => {
  const made = await startServer({ configOverrides: { HTTP_REQUEST_TIMEOUT_MS: 200 } });
  try {
    const closed = await new Promise((resolve) => {
      let done = false;
      const finish = (value) => {
        if (!done) {
          done = true;
          resolve(value);
        }
      };
      const socket = net.connect(made.port, "127.0.0.1", () => {
        socket.write("POST /wp-login.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n");
      });
      socket.on("data", (data) => {
        if (data.toString().includes("408")) finish(true);
      });
      socket.on("close", () => finish(true));
      setTimeout(() => finish(false), 5000);
    });
    assert.equal(closed, true);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: router and handlers import no " + "child" + "_process, network or fs modules", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = [
    join(here, "..", "src", "router.js"),
    join(here, "..", "src", "sessions.js"),
    join(here, "..", "src", "events.js"),
  ];
  const banned = ["node:fs", "node:net", "node:http", "node:https", "node:dns", "node:dgram", "node:tls", "node:" + "child" + "_process"];
  const uniqueBanned = [...new Set(banned)];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const bannedModule of uniqueBanned) {
      assert.ok(!text.includes(bannedModule), `${file} imports ${bannedModule}`);
    }
  }
  const serverText = readFileSync(join(here, "..", "src", "server.js"), "utf8");
  for (const bannedModule of ["node:fs", "node:net", "node:https", "node:dns", "node:dgram", "node:tls", "node:" + "child" + "_process"]) {
    assert.ok(!serverText.includes(bannedModule), `server.js imports ${bannedModule}`);
  }
  assert.ok(serverText.includes("node:http"), "server.js must use node:http to listen");
});

test("http: request event has method, path, headers, ip and matchedRoute", async () => {
  const made = await startServer({});
  try {
    await httpRequest(made.port, { path: "/wp-login.php", headers: { "user-agent": "TestAgent/1.0" } });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.path === "/wp-login.php");
    assert.equal(events[0].payload.method, "GET");
    assert.equal(events[0].payload.headers["user-agent"], "TestAgent/1.0");
    assert.equal(events[0].source.ip, "127.0.0.1");
    assert.equal(events[0].payload.matchedRoute, "wp_login");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: credentials are parsed from login forms into the event", async () => {
  const made = await startServer({});
  try {
    await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=alice&pwd=wonderland" });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.credentials);
    assert.equal(events[0].payload.credentials.username, "alice");
    assert.equal(events[0].payload.credentials.password, "wonderland");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: body preview is truncated and flagged", async () => {
  const made = await startServer({ configOverrides: { HTTP_MAX_BODY_BYTES: 100 } });
  try {
    await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "x=".padEnd(200, "b") });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.responseStatus === 413);
    assert.equal(events[0].payload.bodyTruncated, true);
    assert.ok(events[0].payload.bodyBytes > 100);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: only allowlisted headers are stored and values are capped", async () => {
  const made = await startServer({});
  try {
    await httpRequest(made.port, { path: "/", headers: { "user-agent": "UA", "x-secret": "should-not-appear", "x-long": "z".repeat(600) } });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "http_request" && event.payload.path === "/");
    assert.equal(events[0].payload.headers["user-agent"], "UA");
    assert.equal(events[0].payload.headers["x-secret"], undefined);
    // x-long is not allowlisted, so it should not appear at all
    assert.equal(events[0].payload.headers["x-long"], undefined);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: session id is stable per IP inside the window and changes after it", async () => {
  let nowMs = 1000000;
  const nowFn = () => nowMs;
  const made = await startServer({ now: nowFn, configOverrides: { HTTP_SESSION_WINDOW_MS: 60000 } });
  try {
    await httpRequest(made.port, { path: "/" });
    await httpRequest(made.port, { path: "/" });
    let events = readEvents(made.eventsDir);
    const firstId = events[0].sessionId;
    const secondId = events[1].sessionId;
    assert.equal(firstId, secondId);
    nowMs += 60001;
    await httpRequest(made.port, { path: "/" });
    events = readEvents(made.eventsDir);
    assert.notEqual(events[2].sessionId, firstId);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: llm_response event carries llm meta", async () => {
  const llm = makeFakeHttpLlm({ body: "llm-meta-page" });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    await httpRequest(made.port, { path: "/api/meta" });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "llm_response");
    assert.equal(events[0].payload.command, "GET /api/meta");
    assert.equal(events[0].payload.exitCode, 200);
    assert.ok(events[0].payload.outputPreview.includes("llm-meta-page"));
    assert.equal(events[0].llm.used, true);
    assert.equal(events[0].llm.model, "fake");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: all emitted events pass validateEvent", async () => {
  const llm = makeFakeHttpLlm({ body: "validate-page" });
  const made = await startServer({ llmMode: "real", llmService: llm });
  try {
    await httpRequest(made.port, { path: "/" });
    await httpRequest(made.port, { path: "/api/validate" });
    await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=bob&pwd=secret" });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir);
    assert.ok(events.length > 0);
    for (const event of events) {
      const checked = validateEvent(event);
      assert.equal(checked.ok, true, JSON.stringify(checked.errors));
    }
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("http: attacker credentials never appear in operational logs", async () => {
  const logs = [];
  const recordingLogger = {
    info: (fields, message) => logs.push(JSON.stringify({ fields, message })),
    warn: (fields, message) => logs.push(JSON.stringify({ fields, message })),
    error: (fields, message) => logs.push(JSON.stringify({ fields, message })),
  };
  const made = await startServer({ logger: recordingLogger });
  try {
    await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "log=victimuser&pwd=supersecret123" });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const allLogs = logs.join("\n");
    assert.ok(!allLogs.includes("supersecret123"));
    assert.ok(!allLogs.includes("victimuser"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});
