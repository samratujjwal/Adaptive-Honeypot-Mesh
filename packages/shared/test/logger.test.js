import test from "node:test";
import assert from "node:assert/strict";
import { Writable } from "node:stream";
import { createLogger } from "../src/logger.js";

function captureLogger() {
  let captured = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      captured += chunk.toString();
      callback();
    },
  });
  const testLogger = createLogger({ level: "info", destination: stream });
  return {
    testLogger,
    output: () => captured,
  };
}

test("logger: secret fields are redacted in output", async () => {
  const { testLogger, output } = captureLogger();
  testLogger.info(
    {
      apiKey: "secret-api-key-123",
      GEMINI_API_KEY: "secret-gemini-456",
      password: "secret-password-789",
      authorization: "Bearer secret-token-012",
      headers: { authorization: "Bearer secret-header-345" },
    },
    "login attempt",
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  const text = output();
  assert.ok(text.includes("[REDACTED]"));
  assert.ok(!text.includes("secret-api-key-123"));
  assert.ok(!text.includes("secret-gemini-456"));
  assert.ok(!text.includes("secret-password-789"));
  assert.ok(!text.includes("secret-token-012"));
  assert.ok(!text.includes("secret-header-345"));
});

test("logger: non-secret fields are preserved", async () => {
  const { testLogger, output } = captureLogger();
  testLogger.info({ user: "alice", eventType: "command" }, "command seen");
  await new Promise((resolve) => setTimeout(resolve, 100));
  const text = output();
  assert.ok(text.includes("alice"));
  assert.ok(text.includes("command"));
});
