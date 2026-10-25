import test from "node:test";
import assert from "node:assert/strict";
import { createEvent, validateEvent } from "../src/event.js";

function validEvent() {
  return {
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "session-1",
    source: { ip: "1.2.3.4", port: 5555 },
    eventType: "command",
    payload: { cmd: "ls" },
  };
}

test("event: valid event passes", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    llm: { used: true, cached: false, fallback: false, latencyMs: 42, model: "gemini-2.5-flash" },
    mitre: [{ techniqueId: "T1078", tactic: "initial-access", confidence: 0.8 }],
  });
  assert.equal(result.ok, true);
  assert.equal(result.data.sessionId, "session-1");
});

test("event: missing sessionId fails", () => {
  const event = validEvent();
  delete event.sessionId;
  const result = validateEvent({
    ...event,
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.path === "sessionId"));
});

test("event: bad eventType fails", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    eventType: "teleport",
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.path === "eventType"));
});

test("event: createEvent adds uuid and ISO timestamp", () => {
  const created = createEvent(validEvent());
  assert.match(created.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.equal(Number.isNaN(Date.parse(created.timestamp)), false);
  assert.equal(created.timestamp, new Date(created.timestamp).toISOString());
  assert.equal(validateEvent(created).ok, true);
});

test("event: 1MB payload is rejected", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    payload: { data: "x".repeat(1024 * 1024) },
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.path === "payload"));
});

test("event: payload under the limit is accepted", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    payload: { data: "x".repeat(1000) },
  });
  assert.equal(result.ok, true);
});

test("event: overlong sessionId is rejected", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    sessionId: "s".repeat(129),
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.path === "sessionId"));
});

test("event: unknown service fails", () => {
  const result = validateEvent({
    ...validEvent(),
    id: "123e4567-e89b-42d3-a456-426614174000",
    timestamp: "2026-10-25T00:00:00.000Z",
    honeypot: { service: "smtp", nodeId: "node-01" },
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.path === "honeypot.service"));
});
