import assert from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createEvent, validateEvent } from "../src/event.js";
import { createFileSink } from "../src/event-sink.js";

function validEvent() {
  return createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "123e4567-e89b-42d3-a456-426614174000",
    source: { ip: "127.0.0.1", port: 12345 },
    eventType: "auth_attempt",
    payload: { method: "password", username: "root", password: "123456", success: true },
  });
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-sink-"));
}

test("sink: writes one valid JSON line per event", () => {
  const dir = tempDir();
  try {
    const sink = createFileSink({ dir, service: "ssh" });
    assert.equal(sink.emit(validEvent()), true);
    assert.equal(sink.emit(validEvent()), true);
    const lines = readFileSync(join(dir, "ssh.jsonl"), "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
    for (const line of lines) {
      const parsed = JSON.parse(line);
      assert.equal(validateEvent(parsed).ok, true);
      assert.equal(parsed.eventType, "auth_attempt");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sink: rejects an invalid event without writing it", () => {
  const dir = tempDir();
  try {
    const sink = createFileSink({ dir, service: "ssh" });
    assert.equal(sink.emit({ notAnEvent: true }), false);
    assert.equal(existsSync(join(dir, "ssh.jsonl")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sink: survives a write error without throwing", () => {
  const dir = tempDir();
  try {
    const blocker = join(dir, "blocked");
    writeFileSync(blocker, "not a directory");
    const sink = createFileSink({ dir: blocker, service: "ssh" });
    assert.doesNotThrow(() => sink.emit(validEvent()));
    assert.equal(sink.emit(validEvent()), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
