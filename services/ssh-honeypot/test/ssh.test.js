import assert from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { validateEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { generateEd25519HostKey } from "../src/hostkey.js";
import { createSshHoneypot } from "../src/server.js";

const { Client } = ssh2;

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-ssh-"));
}

function makeServer(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const hostKeyPath = overrides.SSH_HOST_KEY_PATH || join(dir, "ssh", "host_ed25519");
  const config = loadConfig({
    BIND_HOST: "127.0.0.1",
    SSH_IDLE_TIMEOUT_MS: 10000,
    SSH_MAX_SESSION_MS: 60000,
    SSH_MAX_CONNECTIONS: 50,
    SSH_MAX_CONNECTIONS_PER_IP: 50,
    SSH_MAX_AUTH_ATTEMPTS: 6,
    NODE_ID: "node-01",
    EVENT_DIR: eventsDir,
    SSH_HOST_KEY_PATH: hostKeyPath,
    ...overrides,
  });
  const sink = createFileSink({ dir: eventsDir, service: "ssh" });
  const honeypot = createSshHoneypot({ config, sink, hostKeyPath });
  return { dir, eventsDir, hostKeyPath, config, sink, honeypot };
}

async function startServer(overrides = {}) {
  const made = makeServer(overrides);
  await made.honeypot.listen(0, "127.0.0.1");
  const port = made.honeypot.address().port;
  return { ...made, port };
}

function readEvents(eventsDir) {
  const file = join(eventsDir, "ssh.jsonl");
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

function connectClient(port, options) {
  const client = new Client();
  let readyResolve;
  let closeResolve;
  let errorValue = null;
  const readyPromise = new Promise((resolve) => {
    readyResolve = resolve;
  });
  const closePromise = new Promise((resolve) => {
    closeResolve = resolve;
  });
  client.on("ready", () => readyResolve(true));
  client.on("error", (error) => {
    errorValue = error;
  });
  client.on("close", () => closeResolve(true));
  client.connect({ host: "127.0.0.1", port, readyTimeout: 5000, ...options });
  return {
    client,
    readyPromise,
    closePromise,
    get error() {
      return errorValue;
    },
    async waitReadyOrClose(timeoutMs = 5000) {
      const result = await Promise.race([
        readyPromise.then(() => "ready"),
        closePromise.then(() => "close"),
        new Promise((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
      ]);
      return result;
    },
  };
}

function openShell(client) {
  return new Promise((resolve, reject) => {
    client.shell({ term: "xterm", rows: 24, cols: 80 }, (error, stream) => {
      if (error) reject(error);
      else resolve(stream);
    });
  });
}

function waitForOutput(stream, needle, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => {
      stream.removeListener("data", onData);
      reject(new Error(`Timed out waiting for output ${JSON.stringify(needle)}; got ${JSON.stringify(buffer)}`));
    }, timeoutMs);
    const onData = (data) => {
      buffer += data.toString();
      if (buffer.includes(needle)) {
        clearTimeout(timer);
        stream.removeListener("data", onData);
        resolve(buffer);
      }
    };
    stream.on("data", onData);
  });
}

test("ssh: refuses to bind to 0.0.0.0 without ALLOW_PUBLIC_BIND", async () => {
  assert.throws(() => loadConfig({ BIND_HOST: "0.0.0.0" }), /BIND_HOST/);
  const made = makeServer();
  try {
    const badConfig = { ...made.config, BIND_HOST: "0.0.0.0", ALLOW_PUBLIC_BIND: false };
    const bad = createSshHoneypot({ config: badConfig, sink: made.sink, hostKeyPath: made.hostKeyPath });
    await assert.rejects(() => bad.listen(0, "0.0.0.0"), /ALLOW_PUBLIC_BIND/);
    await bad.close();
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: host key persists across restarts", async () => {
  const dir = tempDir();
  try {
    const hostKeyPath = join(dir, "ssh", "host_ed25519");
    const first = makeServer({ SSH_HOST_KEY_PATH: hostKeyPath });
    await first.honeypot.listen(0, "127.0.0.1");
    const firstKey = readFileSync(hostKeyPath, "utf8");
    await first.honeypot.close();
    const second = makeServer({ SSH_HOST_KEY_PATH: hostKeyPath });
    await second.honeypot.listen(0, "127.0.0.1");
    const secondKey = readFileSync(hostKeyPath, "utf8");
    await second.honeypot.close();
    assert.equal(secondKey, firstKey);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ssh: accepts a weak credential from the allowlist", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: rejects a credential not in the allowlist", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "not-in-allowlist-xyz" });
    const outcome = await conn.waitReadyOrClose();
    assert.notEqual(outcome, "ready");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt" && event.payload.username === "root" && event.payload.password === "not-in-allowlist-xyz");
    assert.equal(events[0].payload.success, false);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: disconnects after max auth attempts", async () => {
  const made = await startServer({ SSH_MAX_AUTH_ATTEMPTS: 3 });
  try {
    let attempt = 0;
    const conn = connectClient(made.port, {
      username: "root",
      authHandler: () => {
        attempt += 1;
        if (attempt > 10) return false;
        return { type: "password", username: "root", password: `wrong-${attempt}` };
      },
    });
    const outcome = await conn.waitReadyOrClose(5000);
    assert.notEqual(outcome, "ready");
    const closes = await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_close" && event.payload.reason === "auth_limit");
    assert.equal(closes[0].payload.reason, "auth_limit");
    const attempts = readEvents(made.eventsDir).filter((event) => event.eventType === "auth_attempt" && event.payload.method === "password");
    assert.ok(attempts.length >= 2, `expected at least 2 password attempts, got ${attempts.length}`);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: every auth attempt is logged with username and password", async () => {
  const made = await startServer();
  try {
    const good = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await good.waitReadyOrClose(), "ready");
    good.client.end();
    await good.closePromise;
    const bad = connectClient(made.port, { username: "admin", password: "wrong-admin-xyz" });
    await bad.waitReadyOrClose();
    const goodEvents = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt" && event.payload.username === "root" && event.payload.password === "123456" && event.payload.success === true);
    assert.equal(goodEvents.length >= 1, true);
    const badEvents = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt" && event.payload.username === "admin" && event.payload.password === "wrong-admin-xyz" && event.payload.success === false);
    assert.equal(badEvents.length >= 1, true);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: publickey attempt is logged and rejected", async () => {
  const made = await startServer();
  try {
    const generated = generateEd25519HostKey();
    const conn = connectClient(made.port, { username: "root", privateKey: generated.privateKey });
    const outcome = await conn.waitReadyOrClose();
    assert.notEqual(outcome, "ready");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt" && event.payload.method === "publickey");
    assert.equal(events[0].payload.success, false);
    assert.ok(typeof events[0].payload.keyFingerprint === "string" && events[0].payload.keyFingerprint.startsWith("SHA256:"));
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: shell shows prompt after login", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    const output = await waitForOutput(stream, "root@srv-web-01:~# ");
    assert.ok(output.includes("Last login:"));
    stream.end();
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: unknown command returns command not found and is logged", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("foobar123\r");
    await waitForOutput(stream, "bash: foobar123: command not found");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.command === "foobar123");
    assert.equal(events[0].payload.source, "shell");
    stream.end();
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: command event has command text, sessionId and source ip", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("whoami\r");
    await waitForOutput(stream, "bash: whoami: command not found");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.command === "whoami");
    assert.equal(events[0].payload.command, "whoami");
    assert.ok(typeof events[0].sessionId === "string" && events[0].sessionId.length > 0);
    assert.equal(events[0].source.ip, "127.0.0.1");
    assert.equal(validateEvent(events[0]).ok, true);
    stream.end();
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: backspace editing logs the corrected command", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("ls");
    stream.write("\x7f\x7f");
    stream.write("pwd\r");
    await waitForOutput(stream, "bash: pwd: command not found");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.command === "pwd");
    assert.equal(events[0].payload.command, "pwd");
    assert.equal(events[0].payload.usedBackspace, true);
    stream.end();
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: exit closes the session and logs connection_close", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("exit\r");
    await conn.closePromise;
    const closes = await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_close" && event.payload.reason === "client_exit");
    assert.equal(closes[0].payload.reason, "client_exit");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: exec request is logged and never executed", async () => {
  const made = await startServer();
  try {
    const marker = join(made.dir, "marker.txt");
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const result = await new Promise((resolve, reject) => {
      conn.client.exec(`echo test-marker > "${marker}"`, (error, stream) => {
        if (error) {
          reject(error);
          return;
        }
        let output = "";
        let code = null;
        stream.on("data", (data) => {
          output += data.toString();
        });
        stream.on("exit", (exitCode) => {
          code = exitCode;
        });
        stream.on("close", () => resolve({ output, code }));
      });
    });
    assert.ok(result.output.includes("bash: echo: command not found"));
    assert.equal(result.code, 127);
    assert.equal(existsSync(marker), false);
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.source === "exec");
    assert.ok(events[0].payload.command.includes("echo"));
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: idle timeout closes the session", async () => {
  const made = await startServer({ SSH_IDLE_TIMEOUT_MS: 200 });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    await conn.closePromise;
    const closes = await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_close" && event.payload.reason === "idle_timeout");
    assert.equal(closes[0].payload.reason, "idle_timeout");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: per-IP connection limit is enforced", async () => {
  const made = await startServer({ SSH_MAX_CONNECTIONS_PER_IP: 2 });
  try {
    const first = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await first.waitReadyOrClose(), "ready");
    const second = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await second.waitReadyOrClose(), "ready");
    const third = connectClient(made.port, { username: "root", password: "123456" });
    const outcome = await third.waitReadyOrClose(5000);
    assert.notEqual(outcome, "ready");
    first.client.end();
    second.client.end();
    await Promise.all([first.closePromise, second.closePromise]);
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: oversize input line is truncated and flagged", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("x".repeat(5000));
    stream.write("\r");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.truncated === true);
    assert.equal(events[0].payload.command.length, 4096);
    assert.equal(events[0].payload.truncated, true);
    stream.end();
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: all emitted events pass validateEvent", async () => {
  const made = await startServer();
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const stream = await openShell(conn.client);
    await waitForOutput(stream, "root@srv-web-01:~# ");
    stream.write("whoami\r");
    await waitForOutput(stream, "bash: whoami: command not found");
    stream.write("exit\r");
    await conn.closePromise;
    await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_close");
    const events = readEvents(made.eventsDir);
    assert.ok(events.length >= 4, `expected at least 4 events, got ${events.length}`);
    for (const event of events) {
      assert.equal(validateEvent(event).ok, true, `event failed validation: ${JSON.stringify(event)}`);
    }
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: banner matches configured ident", async () => {
  const made = await startServer();
  try {
    const banner = await new Promise((resolve, reject) => {
      const socket = net.connect(made.port, "127.0.0.1", () => {});
      let buffer = "";
      socket.on("data", (data) => {
        buffer += data.toString();
        if (buffer.includes("\n")) {
          socket.destroy();
          resolve(buffer.split("\n")[0].trim());
        }
      });
      socket.on("error", reject);
    });
    assert.equal(banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});
