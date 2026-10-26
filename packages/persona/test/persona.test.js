import assert from "node:assert";
import net from "node:net";
import http from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { validateEvent, createEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { createPersona, personaToFacts } from "../src/persona.js";
import { createHoneytokens } from "../src/honeytokens.js";
import { createSshHoneypot } from "../../../services/ssh-honeypot/src/server.js";
import { createHttpHoneypot } from "../../../services/http-honeypot/src/server.js";
import { createFtpHoneypot } from "../../../services/ftp-honeypot/src/server.js";
import { createVfs } from "../../../packages/vfs/src/vfs.js";
import { buildSeed } from "../../../services/ssh-honeypot/src/seed/ubuntu-2204.js";
import { createCommandEngine } from "../../../services/ssh-honeypot/src/commands.js";
import { uidForUser } from "../../../services/ssh-honeypot/src/seed/ubuntu-2204.js";

const silentLogger = createLogger({ level: "silent" });
const { Client: SshClient } = ssh2;
const SEED = "day8-test-seed-1234";

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-day8-"));
}
function makePersona(seed = SEED, hostname) {
  return createPersona({ seed, hostname: hostname || "srv-web-01" });
}
function makeTokens(persona, enabled = true) {
  return createHoneytokens(persona, { enabled });
}
function readEvents(dir, service) {
  const file = join(dir, `${service}.jsonl`);
  if (!existsSync(file)) return [];
  const text = readFileSync(file, "utf8").trim();
  if (!text) return [];
  return text.split("\n").map((line) => JSON.parse(line));
}
async function waitForEvents(dir, service, predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const events = readEvents(dir, service);
    const found = events.filter(predicate);
    if (found.length > 0) return found;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${service} events: ${JSON.stringify(readEvents(dir, service))}`);
}
function httpRequest(port, { method = "GET", path = "/", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), raw: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
class FtpClient {
  constructor(port) { this.port = port; this.socket = null; this.buffer = ""; this.waiters = []; this.lines = []; }
  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, "127.0.0.1", () => resolve());
      this.socket.on("data", (chunk) => {
        this.buffer += chunk.toString("utf8");
        let index;
        while ((index = this.buffer.indexOf("\r\n")) >= 0) {
          const line = this.buffer.slice(0, index);
          this.buffer = this.buffer.slice(index + 2);
          if (this.waiters.length > 0) this.waiters.shift()(line);
          else this.lines.push(line);
        }
      });
      this.socket.on("error", reject);
    });
  }
  nextLine(timeoutMs = 5000) {
    if (this.lines.length > 0) return Promise.resolve(this.lines.shift());
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      this.waiters.push((line) => { clearTimeout(timer); resolve(line); });
    });
  }
  send(text) { this.socket.write(`${text}\r\n`); }
  async command(text) { this.send(text); return this.nextLine(); }
  async login(username, password) {
    const just = !this.socket;
    if (just) await this.connect();
    if (just) await this.nextLine();
    await this.command(`USER ${username}`);
    return this.command(`PASS ${password}`);
  }
  async pasv() {
    const reply = await this.command("PASV");
    const m = reply.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
    if (!m) throw new Error(`Bad PASV: ${reply}`);
    return Number(m[5]) * 256 + Number(m[6]);
  }
  async dataCommand(commandText, dataPort, sendData) {
    const dataSocketPromise = new Promise((resolve, reject) => {
      const s = net.connect(dataPort, "127.0.0.1", () => resolve(s));
      s.on("error", reject);
    }).catch(() => null);
    this.send(commandText);
    const first = await this.nextLine();
    const dataSocket = await dataSocketPromise;
    if (first && (first.startsWith("550") || first.startsWith("425") || first.startsWith("553"))) {
      try { if (dataSocket) dataSocket.destroy(); } catch {}
      return { first, last: first, data: Buffer.alloc(0) };
    }
    if (!dataSocket) return { first, last: first, data: Buffer.alloc(0) };
    if (sendData) { dataSocket.write(sendData); dataSocket.end(); }
    const chunks = [];
    if (!sendData) {
      await new Promise((resolve) => {
        dataSocket.on("data", (c) => chunks.push(c));
        dataSocket.on("end", resolve);
        dataSocket.on("close", resolve);
        setTimeout(resolve, 3000);
      });
    } else {
      await new Promise((resolve) => { dataSocket.on("close", resolve); setTimeout(resolve, 3000); });
    }
    const last = await this.nextLine();
    return { first, last, data: Buffer.concat(chunks) };
  }
  close() { try { this.socket.destroy(); } catch {} }
}
async function startSsh(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const hostKeyPath = join(dir, "ssh", "host_ed25519");
  const config = loadConfig({ BIND_HOST: "127.0.0.1", SSH_IDLE_TIMEOUT_MS: 10000, SSH_MAX_SESSION_MS: 60000, NODE_ID: "node-01", EVENT_DIR: eventsDir, SSH_HOST_KEY_PATH: hostKeyPath, PERSONA_SEED: SEED, HONEYPOT_HOSTNAME: "srv-web-01", ...overrides.configOverrides });
  const sink = createFileSink({ dir: eventsDir, service: "ssh", logger: silentLogger });
  const honeypot = createSshHoneypot({ config, sink, hostKeyPath, logger: silentLogger, llmService: null });
  await honeypot.listen(0, "127.0.0.1");
  return { dir, eventsDir, config, honeypot, port: honeypot.address().port };
}
async function startHttp(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const config = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: eventsDir, PERSONA_SEED: SEED, HONEYPOT_HOSTNAME: "srv-web-01", ...overrides.configOverrides });
  const sink = createFileSink({ dir: eventsDir, service: "http", logger: silentLogger });
  const honeypot = createHttpHoneypot({ config, sink, logger: silentLogger });
  await honeypot.listen(0, "127.0.0.1");
  return { dir, eventsDir, config, honeypot, port: honeypot.address().port };
}
async function startFtp(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const config = loadConfig({ BIND_HOST: "127.0.0.1", NODE_ID: "node-01", EVENT_DIR: eventsDir, FTP_AUTH_FAIL_DELAY_MS: 0, PERSONA_SEED: SEED, HONEYPOT_HOSTNAME: "srv-web-01", ...overrides.configOverrides });
  const sink = createFileSink({ dir: eventsDir, service: "ftp", logger: silentLogger });
  const honeypot = createFtpHoneypot({ config, sink, logger: silentLogger });
  await honeypot.listen(0, "127.0.0.1");
  return { dir, eventsDir, config, honeypot, port: honeypot.address().port };
}
function sshExec(port, username, password, command) {
  return new Promise((resolve, reject) => {
    const conn = new SshClient();
    conn.on("ready", () => {
      conn.exec(command, (error, stream) => {
        if (error) { conn.end(); reject(error); return; }
        let out = "";
        stream.on("data", (data) => { out += data.toString("utf8"); });
        stream.on("close", () => { conn.end(); resolve(out); });
      });
    });
    conn.on("error", reject);
    conn.connect({ host: "127.0.0.1", port, username, password });
  });
}

test("config: persona and honeytoken defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.PERSONA_SEED, "change-me-default-seed");
  assert.equal(cfg.HONEYTOKENS_ENABLED, true);
  assert.equal(cfg.HONEYPOT_DOMAIN, undefined);
});
test("config: invalid persona settings are rejected", () => {
  assert.throws(() => loadConfig({ PERSONA_SEED: "short" }), /PERSONA_SEED/);
  assert.throws(() => loadConfig({ PERSONA_SEED: "x".repeat(65) }), /PERSONA_SEED/);
});
test("persona: same seed gives identical persona", () => {
  const a = makePersona();
  const b = makePersona();
  assert.deepEqual(a, b);
});
test("persona: different seeds give different ips, users and pids", () => {
  const a = makePersona("seed-one-12345");
  const b = makePersona("seed-two-67890");
  assert.notEqual(a.host.privateIp, b.host.privateIp);
  assert.notDeepEqual(a.staff, b.staff);
  assert.notDeepEqual(a.processes, b.processes);
});
test("persona: explicit hostname config wins over the derived value", () => {
  const explicit = createPersona({ seed: SEED, hostname: "my-host-01" });
  assert.equal(explicit.host.hostname, "my-host-01");
  const derived = createPersona({ seed: SEED });
  assert.notEqual(derived.host.hostname, "my-host-01");
});
test("persona: process table and listening ports agree", () => {
  const persona = makePersona();
  const byPid = new Map(persona.processes.map((proc) => [proc.pid, proc]));
  for (const entry of persona.listening) {
    assert.ok(byPid.has(entry.pid), `listening pid ${entry.pid} not in processes`);
    assert.ok(byPid.get(entry.pid).command.includes(entry.program) || entry.program === "postgres" || entry.program === "vsftpd" || entry.program === "nginx" || entry.program === "sshd");
  }
  const ports = persona.listening.map((entry) => entry.port).sort((x, y) => x - y);
  assert.deepEqual(ports, [21, 22, 80, 443, 5432]);
});
test("persona: ips are private RFC1918 addresses", () => {
  const persona = makePersona();
  const ip = persona.host.privateIp;
  const parts = ip.split(".").map(Number);
  const isPrivate = parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
  assert.ok(isPrivate, ip);
});
test("persona: users have consistent uid, home and shell", () => {
  const persona = makePersona();
  const uids = new Set();
  for (const user of persona.users) {
    assert.ok(!uids.has(user.uid), `duplicate uid ${user.uid}`);
    uids.add(user.uid);
    assert.ok(user.home.startsWith("/"));
    assert.ok(user.shell.length > 0);
    if (user.username === "root") assert.equal(user.uid, 0);
  }
});
test("persona: served content never contains tell-tale words", async () => {
  const persona = makePersona();
  const tokens = makeTokens(persona);
  const tell = /fictional|fake|dummy|lorem|placeholder|demonstration/i;
  const httpMade = await startHttp({});
  try {
    const home = await httpRequest(httpMade.port, { path: "/" });
    assert.ok(!tell.test(home.body), home.body);
    const login = await httpRequest(httpMade.port, { path: "/wp-login.php" });
    assert.ok(!tell.test(login.body));
    const pma = await httpRequest(httpMade.port, { path: "/phpmyadmin/" });
    assert.ok(!tell.test(pma.body));
    const env = await httpRequest(httpMade.port, { path: "/.env" });
    assert.ok(!tell.test(env.body));
  } finally { await httpMade.honeypot.close(); rmSync(httpMade.dir, { recursive: true, force: true }); }
  const vfs = createVfs(buildSeed({ persona, honeytokens: tokens }));
  for (const path of ["/etc/passwd", "/etc/hostname", "/etc/os-release", "/var/www/html/wp-config.php", "/home/deploy/notes.txt"]) {
    const content = vfs.readFile(path);
    assert.ok(content, path);
    assert.ok(!tell.test(content.toString("utf8")), path);
  }
  const facts = personaToFacts(persona);
  assert.ok(facts.processes.length > 0);
  const engine = createCommandEngine({ vfs: createVfs(buildSeed({ persona, honeytokens: tokens })), user: { name: "root", uid: 0 }, hostname: persona.host.hostname, persona, config: { SSH_LLM_DEADLINE_MS: 8000, SSH_MAX_FILE_BYTES: 65536, SSH_MAX_NODES: 2000, HONEYPOT_STATIC_FIRST: true }, sessionId: "t1", sourceIp: "10.0.0.5" });
  const ps = await engine.run("ps aux");
  assert.ok(!tell.test(ps.output));
  const wget = await engine.run("wget http://example.com/x.sh");
  assert.ok(!tell.test(wget.output));
});
test("persona: served content never references example.com or example.org", async () => {
  const httpMade = await startHttp({});
  try {
    const home = await httpRequest(httpMade.port, { path: "/" });
    assert.ok(!home.body.includes("example.com") && !home.body.includes("example.org"));
    const env = await httpRequest(httpMade.port, { path: "/.env" });
    assert.ok(!env.body.includes("example.com") && !env.body.includes("example.org"));
  } finally { await httpMade.honeypot.close(); rmSync(httpMade.dir, { recursive: true, force: true }); }
});
test("honeytokens: same seed gives the same tokens", () => {
  const a = makeTokens(makePersona());
  const b = makeTokens(makePersona());
  assert.deepEqual(a.tokens, b.tokens);
});
test("honeytokens: values look like real credentials and avoid vendor patterns", () => {
  const tokens = makeTokens(makePersona());
  for (const token of tokens.tokens) {
    assert.ok(!token.value.includes("fake") && !token.value.includes("test") && !token.value.includes("demo") && !token.value.includes("example") && !token.value.includes("password") && !token.value.includes("secret"));
    assert.ok(!token.value.includes("AKIA") && !token.value.includes("sk_live_") && !token.value.includes("ghp_") && !token.value.includes("AIza") && !token.value.includes("xox"));
    if (token.kind !== "api_key") {
      assert.ok(/[A-Z]/.test(token.value) && /[a-z]/.test(token.value) && /[0-9]/.test(token.value) && /[#@!%&]/.test(token.value));
      assert.ok(token.value.length >= 12 && token.value.length <= 16);
    } else {
      assert.ok(token.value.includes("_live_"));
      assert.ok(token.value.split("_live_")[1].length === 32);
    }
  }
});
test("honeytokens: ids and values are unique", () => {
  const tokens = makeTokens(makePersona());
  assert.equal(new Set(tokens.tokens.map((t) => t.id)).size, tokens.tokens.length);
  assert.equal(new Set(tokens.tokens.map((t) => t.value)).size, tokens.tokens.length);
});
test("honeytokens: every token is planted in at least two services", () => {
  const tokens = makeTokens(makePersona());
  function serviceOf(path) {
    if (path.startsWith("/home/") || path.startsWith("/var/www/")) return "ssh";
    if (path.startsWith("/backup/")) return "ftp";
    return "http";
  }
  for (const token of tokens.tokens) {
    const services = new Set(token.plantedIn.map(serviceOf));
    assert.ok(services.size >= 2, `${token.kind}: ${token.plantedIn.join(",")}`);
  }
});
test("honeytokens: planted files contain the token value", () => {
  const persona = makePersona();
  const tokens = makeTokens(persona);
  const vfs = createVfs(buildSeed({ persona, honeytokens: tokens }));
  assert.ok(vfs.readFile("/var/www/html/wp-config.php").toString("utf8").includes(tokens.tokens.find((t) => t.kind === "db_password").value));
  assert.ok(vfs.readFile("/home/deploy/notes.txt").toString("utf8").includes(tokens.tokens.find((t) => t.kind === "ssh_password").value));
});
test("honeytokens: lookup finds a token inside a longer or url-encoded string", () => {
  const tokens = makeTokens(makePersona());
  const db = tokens.tokens.find((t) => t.kind === "db_password");
  assert.ok(tokens.lookup(`prefix ${db.value} suffix`).some((t) => t.id === db.id));
  assert.ok(tokens.lookup(encodeURIComponent(`x=${db.value}`)).some((t) => t.id === db.id));
  assert.equal(tokens.lookup("no token here").length, 0);
});
test("honeytokens: disabled by config plants and detects nothing", () => {
  const persona = makePersona();
  const tokens = makeTokens(persona, false);
  assert.equal(tokens.tokens.length, 0);
  assert.equal(tokens.lookup("anything").length, 0);
  assert.deepEqual(tokens.plantedIn("ssh_password"), []);
});
test("event: honeytoken event type is valid and other types still validate", () => {
  const event = createEvent({ honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "s1", source: { ip: "127.0.0.1", port: 1234 }, eventType: "honeytoken", payload: { tokenId: "ht-12345678", kind: "ssh_password", action: "used", via: "ssh_command" } });
  assert.equal(validateEvent(event).ok, true);
  const other = createEvent({ honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "s1", source: { ip: "127.0.0.1", port: 1234 }, eventType: "command", payload: { command: "ls" } });
  assert.equal(validateEvent(other).ok, true);
});
test("event: honeytoken payload requires tokenId, kind, action and via", () => {
  const base = { honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "s1", source: { ip: "127.0.0.1", port: 1234 }, eventType: "honeytoken" };
  assert.equal(validateEvent({ ...base, payload: { kind: "ssh_password", action: "used", via: "ssh_command" } }).ok, false);
  assert.equal(validateEvent({ ...base, payload: { tokenId: "ht-1", action: "used", via: "ssh_command" } }).ok, false);
  assert.equal(validateEvent({ ...base, payload: { tokenId: "ht-1", kind: "ssh_password", action: "viewed", via: "bad_via" } }).ok, false);
});
test("ssh: token account logs in with its token password", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const deploy = makeTokens(persona).tokens.find((t) => t.kind === "ssh_password");
    const out = await sshExec(made.port, "deploy", deploy.value, "whoami");
    assert.ok(out.includes("deploy"));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: token password for another username is rejected but logged as used", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const deploy = makeTokens(persona).tokens.find((t) => t.kind === "ssh_password");
    let failed = false;
    try { await sshExec(made.port, "admin", deploy.value, "whoami"); } catch { failed = true; }
    assert.ok(failed);
    const events = await waitForEvents(made.eventsDir, "ssh", (e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.via === "ssh_auth");
    assert.ok(events.some((e) => e.payload.tokenId === deploy.id));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: reading a planted file emits a viewed event once per session", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const deploy = makeTokens(persona).tokens.find((t) => t.kind === "ssh_password");
    await sshExec(made.port, "admin", "admin", "cat /home/deploy/notes.txt");
    await sshExec(made.port, "admin", "admin", "cat /home/deploy/notes.txt");
    const events = await waitForEvents(made.eventsDir, "ssh", (e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === deploy.id);
    assert.ok(events.length >= 1);
    const sessionIds = new Set(events.map((e) => e.sessionId));
    assert.ok(sessionIds.size >= 1);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: token value typed in a command emits a used event", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    await new Promise((resolve, reject) => {
      const conn = new SshClient();
      conn.on("ready", () => {
        conn.shell((error, stream) => {
          if (error) { conn.end(); reject(error); return; }
          stream.write(`echo ${db.value}\n`);
          setTimeout(() => { stream.write("exit\n"); conn.end(); resolve(); }, 800);
        });
      });
      conn.on("error", reject);
      conn.connect({ host: "127.0.0.1", port: made.port, username: "admin", password: "admin" });
    });
    const events = await waitForEvents(made.eventsDir, "ssh", (e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.via === "ssh_command" && e.payload.tokenId === db.id);
    assert.ok(events.length >= 1);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: passwd, hosts, hostname and os-release come from the persona", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const passwd = await sshExec(made.port, "admin", "admin", "cat /etc/passwd");
    assert.ok(passwd.includes("root:x:0:0"));
    assert.ok(passwd.includes(persona.staff[0].username));
    const hostname = await sshExec(made.port, "admin", "admin", "cat /etc/hostname");
    assert.ok(hostname.includes(persona.host.hostname));
    const hosts = await sshExec(made.port, "admin", "admin", "cat /etc/hosts");
    assert.ok(hosts.includes(persona.host.hostname));
    const osr = await sshExec(made.port, "admin", "admin", "cat /etc/os-release");
    assert.ok(osr.includes("Ubuntu 22.04.3 LTS"));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ssh: ps and netstat include vsftpd and match the persona", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const ps = await sshExec(made.port, "admin", "admin", "ps aux");
    assert.ok(ps.includes("vsftpd"));
    assert.ok(ps.includes("21") || ps.includes("vsftpd"));
    const netstat = await sshExec(made.port, "admin", "admin", "netstat -tulpn");
    assert.ok(netstat.includes("21"));
    assert.ok(netstat.includes("vsftpd"));
    const vsftpdProc = persona.processes.find((p) => p.command.includes("vsftpd"));
    assert.ok(ps.includes(String(vsftpdProc.pid)));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: homepage is persona-branded and has WordPress markup", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const res = await httpRequest(made.port, { path: "/" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes(persona.company.name));
    assert.ok(res.body.includes('<meta name="generator" content="WordPress 6.4.3" />'));
    assert.ok(res.body.includes(`/wp-content/themes/${persona.web.theme}/style.css`));
    assert.ok(res.body.includes("/wp-includes/"));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: .env and wp-config.php.bak contain tokens and emit viewed events", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const env = await httpRequest(made.port, { path: "/.env" });
    assert.equal(env.status, 200);
    assert.ok(env.body.includes(db.value));
    const bak = await httpRequest(made.port, { path: "/wp-config.php.bak" });
    assert.equal(bak.status, 200);
    assert.ok(bak.body.includes(db.value));
    const events = await waitForEvents(made.eventsDir, "http", (e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === db.id);
    assert.ok(events.length >= 1);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: wp-login accepts the token account", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const wp = makeTokens(persona).tokens.find((t) => t.kind === "wp_password");
    const res = await httpRequest(made.port, { method: "POST", path: "/wp-login.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `log=webmaster&pwd=${encodeURIComponent(wp.value)}` });
    assert.equal(res.status, 302);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: token value in a query, body or header emits a used event", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    await httpRequest(made.port, { path: `/?q=${encodeURIComponent(db.value)}` });
    const events = await waitForEvents(made.eventsDir, "http", (e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.tokenId === db.id);
    assert.ok(events.length >= 1);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: nginx error pages are 162 byte CRLF pages with text/html", async () => {
  const made = await startHttp({});
  try {
    const res = await httpRequest(made.port, { path: "/nope-unknown-xyz-123" });
    assert.equal(res.status, 404);
    assert.equal(res.raw.length, 162);
    assert.ok(res.raw.toString("utf8").includes("\r\n"));
    assert.ok(res.headers["content-type"] === "text/html");
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: no Keep-Alive header is sent", async () => {
  const made = await startHttp({});
  try {
    const res = await httpRequest(made.port, { path: "/" });
    assert.ok(!("keep-alive" in res.headers), JSON.stringify(res.headers));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: parser errors get an nginx-style 400 with a Server header", async () => {
  const made = await startHttp({});
  try {
    const result = await new Promise((resolve) => {
      const socket = net.connect(made.port, "127.0.0.1", () => {
        socket.write("BAD REQUEST LINE\r\n\r\n");
      });
      let data = "";
      socket.on("data", (chunk) => { data += chunk.toString("utf8"); });
      socket.on("close", () => resolve(data));
      setTimeout(() => { try { socket.destroy(); } catch {} resolve(data); }, 3000);
    });
    assert.ok(result.includes("400 Bad Request"));
    assert.ok(result.includes("Server: nginx/1.18.0 (Ubuntu)"));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("http: static pages have Last-Modified and ETag", async () => {
  const made = await startHttp({});
  try {
    const res = await httpRequest(made.port, { path: "/" });
    assert.ok(res.headers["last-modified"]);
    assert.ok(res.headers["etag"]);
    const persona = makePersona();
    assert.ok(res.headers["last-modified"].includes(new Date(persona.host.bootTime).toUTCString().slice(5, 16)) || res.headers["last-modified"] === new Date(persona.host.bootTime).toUTCString());
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ftp: token account logs in", async () => {
  const made = await startFtp({});
  try {
    const persona = makePersona();
    const backup = makeTokens(persona).tokens.find((t) => t.kind === "ftp_password");
    const client = new FtpClient(made.port);
    const reply = await client.login("backup", backup.value);
    assert.ok(reply.startsWith("230"));
    client.close();
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ftp: config.bak contains tokens and RETR emits a viewed event", async () => {
  const made = await startFtp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    const result = await client.dataCommand("RETR /backup/config.bak", dataPort, null);
    assert.ok(result.data.toString("utf8").includes(db.value));
    const events = await waitForEvents(made.eventsDir, "ftp", (e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === db.id);
    assert.ok(events.length >= 1);
    client.close();
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ftp: token value in a command argument emits a used event", async () => {
  const made = await startFtp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    await client.command(`CWD ${db.value}`);
    const events = await waitForEvents(made.eventsDir, "ftp", (e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.tokenId === db.id);
    assert.ok(events.length >= 1);
    client.close();
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("ftp: listing, sizes and dates come from the persona", async () => {
  const made = await startFtp({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    const result = await client.dataCommand("LIST /backup", dataPort, null);
    assert.ok(result.data.toString("utf8").includes("config.bak"));
    assert.ok(result.data.toString("utf8").includes("Mar 05 10:21"));
    client.close();
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});
test("transfer: downloaded files get minimal content by extension", async () => {
  const engine = createCommandEngine({ vfs: createVfs(buildSeed("srv-web-01")), user: { name: "root", uid: 0 }, hostname: "srv-web-01", config: { SSH_LLM_DEADLINE_MS: 8000, SSH_MAX_FILE_BYTES: 65536, SSH_MAX_NODES: 2000, HONEYPOT_STATIC_FIRST: true }, sessionId: "t1", sourceIp: "10.0.0.5" });
  await engine.run("wget http://example.com/a.sh");
  assert.equal((await engine.run("cat /root/a.sh")).output, "#!/bin/sh\n");
  await engine.run("wget http://example.com/b.py");
  assert.equal((await engine.run("cat /root/b.py")).output, "#!/usr/bin/env python3\n");
  await engine.run("wget http://example.com/c.php");
  assert.equal((await engine.run("cat /root/c.php")).output, "<?php\n");
  await engine.run("wget http://example.com/d.html");
  assert.equal((await engine.run("cat /root/d.html")).output, "<html></html>\n");
  await engine.run("wget http://example.com/e.txt");
  assert.equal((await engine.run("cat /root/e.txt")).output, "");
});
test("integration: token seen over ftp and used over ssh gives events with the same tokenId", async () => {
  const ftpMade = await startFtp({});
  const sshMade = await startSsh({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const client = new FtpClient(ftpMade.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    await client.dataCommand("RETR /backup/config.bak", dataPort, null);
    client.close();
    await sshExec(sshMade.port, "admin", "admin", `echo ${db.value}`);
    const ftpEvents = await waitForEvents(ftpMade.eventsDir, "ftp", (e) => e.eventType === "honeytoken" && e.payload.tokenId === db.id);
    const sshEvents = await waitForEvents(sshMade.eventsDir, "ssh", (e) => e.eventType === "honeytoken" && e.payload.tokenId === db.id);
    assert.ok(ftpEvents.length >= 1 && sshEvents.length >= 1);
    assert.equal(ftpEvents[0].payload.tokenId, sshEvents[0].payload.tokenId);
  } finally { await ftpMade.honeypot.close(); await sshMade.honeypot.close(); rmSync(ftpMade.dir, { recursive: true, force: true }); rmSync(sshMade.dir, { recursive: true, force: true }); }
});
test("integration: all three services report the same hostname, domain and versions", async () => {
  const sshMade = await startSsh({});
  const httpMade = await startHttp({});
  const ftpMade = await startFtp({});
  try {
    const persona = makePersona();
    const hostname = await sshExec(sshMade.port, "admin", "admin", "cat /etc/hostname");
    assert.ok(hostname.includes(persona.host.hostname));
    const home = await httpRequest(httpMade.port, { path: "/" });
    assert.ok(home.body.includes(persona.company.name));
    const client = new FtpClient(ftpMade.port);
    await client.connect();
    const banner = await client.nextLine();
    assert.ok(banner.includes("vsFTPd 3.0.5"));
    client.close();
    assert.equal(persona.versions.vsftpd, "3.0.5");
    assert.equal(persona.versions.nginx, "nginx/1.18.0 (Ubuntu)");
  } finally { await sshMade.honeypot.close(); await httpMade.honeypot.close(); await ftpMade.honeypot.close(); rmSync(sshMade.dir, { recursive: true, force: true }); rmSync(httpMade.dir, { recursive: true, force: true }); rmSync(ftpMade.dir, { recursive: true, force: true }); }
});

test("http: GET of a planted file emits viewed and no used event", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const res = await httpRequest(made.port, { path: "/.env" });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes(db.value));
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir, "http");
    const viewed = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === db.id);
    const used = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.tokenId === db.id);
    assert.ok(viewed.length >= 1);
    assert.equal(used.length, 0);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});

test("ssh: cat of a planted file emits viewed and no used event", async () => {
  const made = await startSsh({});
  try {
    const persona = makePersona();
    const deploy = makeTokens(persona).tokens.find((t) => t.kind === "ssh_password");
    const out = await sshExec(made.port, "admin", "admin", "cat /home/deploy/notes.txt");
    assert.ok(out.includes(deploy.value));
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir, "ssh");
    const viewed = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === deploy.id);
    const used = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.tokenId === deploy.id);
    assert.ok(viewed.length >= 1);
    assert.equal(used.length, 0);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});

test("ftp: RETR of a planted file emits viewed and no used event", async () => {
  const made = await startFtp({});
  try {
    const persona = makePersona();
    const db = makeTokens(persona).tokens.find((t) => t.kind === "db_password");
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    const result = await client.dataCommand("RETR /backup/config.bak", dataPort, null);
    assert.ok(result.data.toString("utf8").includes(db.value));
    client.close();
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir, "ftp");
    const viewed = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "viewed" && e.payload.tokenId === db.id);
    const used = events.filter((e) => e.eventType === "honeytoken" && e.payload.action === "used" && e.payload.tokenId === db.id);
    assert.ok(viewed.length >= 1);
    assert.equal(used.length, 0);
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});

test("http: ETag is hex mtime and hex size like nginx", async () => {
  const made = await startHttp({});
  try {
    const persona = makePersona();
    const res = await httpRequest(made.port, { path: "/" });
    assert.equal(res.status, 200);
    const etag = res.headers["etag"];
    assert.ok(etag, "ETag present");
    const expectedMtime = Math.floor(Date.parse(persona.host.bootTime) / 1000).toString(16);
    const expectedSize = Buffer.byteLength(res.body, "utf8").toString(16);
    assert.equal(etag, `"${expectedMtime}-${expectedSize}"`);
    assert.ok(/^"[0-9a-f]+-[0-9a-f]+"$/.test(etag));
  } finally { await made.honeypot.close(); rmSync(made.dir, { recursive: true, force: true }); }
});

test("persona: database and user names contain no hyphens", async () => {
  const persona = makePersona();
  assert.ok(!persona.web.dbName.includes("-"), persona.web.dbName);
  assert.ok(!persona.web.dbUser.includes("-"), persona.web.dbUser);
  assert.ok(persona.web.dbName.includes("_"));
  const sshMade = await startSsh({});
  try {
    const wpConfig = await sshExec(sshMade.port, "admin", "admin", "cat /var/www/html/wp-config.php");
    assert.ok(wpConfig.includes(persona.web.dbName));
    assert.ok(!wpConfig.includes("silverline-services_wp"));
  } finally { await sshMade.honeypot.close(); rmSync(sshMade.dir, { recursive: true, force: true }); }
  const httpMade = await startHttp({});
  try {
    const env = await httpRequest(httpMade.port, { path: "/.env" });
    assert.ok(env.body.includes(persona.web.dbName));
    assert.ok(env.body.includes(persona.web.dbUser));
  } finally { await httpMade.honeypot.close(); rmSync(httpMade.dir, { recursive: true, force: true }); }
});
