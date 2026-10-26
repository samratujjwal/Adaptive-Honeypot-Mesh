import assert from "node:assert";
import net from "node:net";
import http from "node:http";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { validateEvent } from "../../../packages/shared/src/event.js";
import { createFileSink } from "../../../packages/shared/src/event-sink.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { createFtpHoneypot, isAllowedDataPeer } from "../src/server.js";
import { createVfs } from "../../../packages/vfs/src/vfs.js";
import { buildFtpSeed } from "../src/ftp-seed.js";

const silentLogger = createLogger({ level: "silent" });

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-ftp-"));
}

function makeServer(overrides = {}) {
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const config = loadConfig({
    BIND_HOST: "127.0.0.1",
    FTP_PORT: 2121,
    NODE_ID: "node-01",
    EVENT_DIR: eventsDir,
    FTP_AUTH_FAIL_DELAY_MS: 0,
    ...(overrides.configOverrides || {}),
  });
  const sink = createFileSink({ dir: eventsDir, service: "ftp", logger: silentLogger });
  const logger = overrides.logger || silentLogger;
  const ftp = createFtpHoneypot({ config, sink, logger });
  return { dir, eventsDir, config, sink, ftp };
}

async function startServer(overrides = {}) {
  const made = makeServer(overrides);
  await made.ftp.listen(0, "127.0.0.1");
  const port = made.ftp.address().port;
  return { ...made, port };
}

function readEvents(eventsDir) {
  const file = join(eventsDir, "ftp.jsonl");
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
  throw new Error(`Timed out waiting for events: ${JSON.stringify(readEvents(eventsDir))}`);
}

class FtpClient {
  constructor(port) {
    this.port = port;
    this.socket = null;
    this.buffer = "";
    this.waiters = [];
    this.lines = [];
    this.closed = false;
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, "127.0.0.1", () => {
        resolve();
      });
      this.socket.on("data", (chunk) => {
        this.buffer += chunk.toString("utf8");
        let index;
        while ((index = this.buffer.indexOf("\r\n")) >= 0) {
          const line = this.buffer.slice(0, index);
          this.buffer = this.buffer.slice(index + 2);
          if (this.waiters.length > 0) {
            const waiter = this.waiters.shift();
            waiter(line);
          } else {
            this.lines.push(line);
          }
        }
      });
      this.socket.on("close", () => {
        this.closed = true;
        while (this.waiters.length > 0) {
          const waiter = this.waiters.shift();
          waiter(null);
        }
      });
      this.socket.on("error", (error) => {
        reject(error);
      });
    });
  }

  nextLine(timeoutMs = 5000) {
    if (this.lines.length > 0) return Promise.resolve(this.lines.shift());
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(resolve);
        if (index >= 0) this.waiters.splice(index, 1);
        resolve(null);
      }, timeoutMs);
      this.waiters.push((line) => {
        clearTimeout(timer);
        resolve(line);
      });
    });
  }

  async readMultiline() {
    const lines = [];
    while (true) {
      const line = await this.nextLine();
      if (line === null) break;
      lines.push(line);
      if (!line.startsWith("211-") && !line.startsWith("211 ")) {
        if (lines.length === 1 && !line.startsWith("211-")) break;
        if (line.startsWith("211 End")) break;
      }
      if (lines.length > 20) break;
    }
    return lines;
  }

  send(text) {
    this.socket.write(`${text}\r\n`);
  }

  async command(text) {
    this.send(text);
    const line = await this.nextLine();
    return line;
  }

  async login(username, password) {
    const justConnected = !this.socket;
    if (justConnected) await this.connect();
    if (justConnected) await this.nextLine();
    await this.command(`USER ${username}`);
    const reply = await this.command(`PASS ${password}`);
    return reply;
  }

  async pasv() {
    const reply = await this.command("PASV");
    const match = reply.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
    if (!match) throw new Error(`Bad PASV reply: ${reply}`);
    const port = Number(match[5]) * 256 + Number(match[6]);
    return port;
  }

  async epsv() {
    const reply = await this.command("EPSV");
    const match = reply.match(/\(\|\|\|(\d+)\|\)/);
    if (!match) throw new Error(`Bad EPSV reply: ${reply}`);
    return Number(match[1]);
  }

  dataConnect(port) {
    return new Promise((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => resolve(socket));
      socket.on("error", reject);
    });
  }

  async dataCommand(commandText, dataPort, sendData) {
    const dataSocketPromise = this.dataConnect(dataPort).catch(() => null);
    this.send(commandText);
    const first = await this.nextLine();
    const dataSocket = await dataSocketPromise;
    if (first && (first.startsWith("550") || first.startsWith("425") || first.startsWith("553"))) {
      try { if (dataSocket) dataSocket.destroy(); } catch {}
      return { first, last: first, data: Buffer.alloc(0) };
    }
    if (!dataSocket) {
      return { first, last: first, data: Buffer.alloc(0) };
    }
    if (sendData) {
      dataSocket.write(sendData);
      dataSocket.end();
    }
    const chunks = [];
    if (!sendData) {
      await new Promise((resolve) => {
        dataSocket.on("data", (chunk) => chunks.push(chunk));
        dataSocket.on("end", resolve);
        dataSocket.on("close", resolve);
        setTimeout(resolve, 3000);
      });
    } else {
      await new Promise((resolve) => {
        dataSocket.on("close", resolve);
        setTimeout(resolve, 3000);
      });
    }
    const last = await this.nextLine();
    return { first, last, data: Buffer.concat(chunks) };
  }

  close() {
    try {
      this.socket.destroy();
    } catch {
      /* Ignore. */
    }
  }
}

test("config: FTP defaults load", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.FTP_PORT, 2121);
  assert.equal(cfg.FTP_BANNER, "(vsFTPd 3.0.5)");
  assert.equal(cfg.FTP_MAX_CONNECTIONS, 50);
  assert.equal(cfg.FTP_MAX_CONNECTIONS_PER_IP, 5);
  assert.equal(cfg.FTP_MAX_AUTH_ATTEMPTS, 5);
  assert.equal(cfg.FTP_AUTH_FAIL_DELAY_MS, 1000);
  assert.equal(cfg.FTP_IDLE_TIMEOUT_MS, 60000);
  assert.equal(cfg.FTP_MAX_SESSION_MS, 600000);
  assert.equal(cfg.FTP_MAX_LINE, 512);
  assert.equal(cfg.FTP_MAX_CMDS_PER_MIN, 120);
  assert.equal(cfg.FTP_PASV_MIN_PORT, 40000);
  assert.equal(cfg.FTP_PASV_MAX_PORT, 40100);
  assert.equal(cfg.FTP_PASV_ADDRESS, "127.0.0.1");
  assert.equal(cfg.FTP_DATA_TIMEOUT_MS, 10000);
  assert.equal(cfg.FTP_MAX_UPLOAD_BYTES, 1048576);
  assert.equal(cfg.FTP_MAX_SESSION_BYTES, 2097152);
  assert.equal(cfg.FTP_MAX_NODES, 500);
});

test("config: invalid FTP limits are rejected", () => {
  assert.throws(() => loadConfig({ FTP_MAX_CONNECTIONS: 0 }), /FTP_MAX_CONNECTIONS/);
  assert.throws(() => loadConfig({ FTP_MAX_AUTH_ATTEMPTS: 0 }), /FTP_MAX_AUTH_ATTEMPTS/);
  assert.throws(() => loadConfig({ FTP_MAX_LINE: 0 }), /FTP_MAX_LINE/);
  assert.throws(() => loadConfig({ FTP_PASV_MIN_PORT: 40101, FTP_PASV_MAX_PORT: 40100 }), /FTP_PASV_MIN_PORT/);
  assert.throws(() => loadConfig({ FTP_PASV_ADDRESS: "not-an-ip" }), /FTP_PASV_ADDRESS/);
  assert.throws(() => loadConfig({ FTP_MAX_UPLOAD_BYTES: 0 }), /FTP_MAX_UPLOAD_BYTES/);
});

test("ftp: refuses to bind to 0.0.0.0 without ALLOW_PUBLIC_BIND", async () => {
  assert.throws(() => loadConfig({ BIND_HOST: "0.0.0.0" }), /BIND_HOST/);
  const made = makeServer({});
  const badConfig = { ...made.config, BIND_HOST: "0.0.0.0", ALLOW_PUBLIC_BIND: false };
  const bad = createFtpHoneypot({ config: badConfig, sink: made.sink, logger: silentLogger });
  await assert.rejects(() => bad.listen(0, "0.0.0.0"), /ALLOW_PUBLIC_BIND/);
  await bad.close();
  await made.ftp.close();
  rmSync(made.dir, { recursive: true, force: true });
});

test("ftp: banner matches the configured vsftpd banner", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    const banner = await client.nextLine();
    assert.equal(banner, "220 (vsFTPd 3.0.5)");
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: commands before login are refused with 530", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    await client.nextLine();
    const pwd = await client.command("PWD");
    assert.ok(pwd.startsWith("530"));
    const auth = await client.command("AUTH TLS");
    assert.ok(auth.startsWith("530"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: anonymous login is accepted with any password", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    const reply = await client.login("anonymous", "anything@example.com");
    assert.ok(reply.startsWith("230"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: weak credential from the allowlist logs in", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    const reply = await client.login("admin", "admin123");
    assert.ok(reply.startsWith("230"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: wrong credential gets 530 and is logged", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    const reply = await client.login("admin", "wrongpass");
    assert.ok(reply.startsWith("530"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt");
    assert.equal(events[0].payload.username, "admin");
    assert.equal(events[0].payload.password, "wrongpass");
    assert.equal(events[0].payload.success, false);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: disconnects after max auth attempts", async () => {
  const made = await startServer({ configOverrides: { FTP_MAX_AUTH_ATTEMPTS: 3 } });
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    await client.nextLine();
    await client.command("USER admin");
    let last = null;
    for (let i = 0; i < 3; i += 1) {
      last = await client.command("PASS wrong");
      if (i < 2) assert.ok(last.startsWith("530"));
    }
    assert.ok(last.startsWith("421"));
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(client.closed, true);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: SYST, FEAT, PWD, TYPE and NOOP answer like vsftpd", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    await client.nextLine();
    const syst = await client.command("SYST");
    assert.equal(syst, "215 UNIX Type: L8");
    const featLines = [];
    client.send("FEAT");
    let line;
    while (true) {
      line = await client.nextLine();
      featLines.push(line);
      if (line === "211 End") break;
    }
    assert.equal(featLines[0], "211-Features:");
    assert.ok(featLines.includes(" PASV"));
    await client.login("anonymous", "x");
    const pwd = await client.command("PWD");
    assert.ok(pwd.startsWith('257 "/"'));
    const typeA = await client.command("TYPE A");
    assert.equal(typeA, "200 Switching to ASCII mode.");
    const typeI = await client.command("TYPE I");
    assert.equal(typeI, "200 Switching to Binary mode.");
    const noop = await client.command("NOOP");
    assert.equal(noop, "200 NOOP ok.");
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: CWD and CDUP stay inside the fake tree", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const cwd1 = await client.command("CWD /backup");
    assert.ok(cwd1.startsWith("250"));
    const pwd1 = await client.command("PWD");
    assert.ok(pwd1.includes("/backup"));
    const cdup = await client.command("CDUP");
    assert.ok(cdup.startsWith("250"));
    const pwd2 = await client.command("PWD");
    assert.ok(pwd2.includes('"/"') || pwd2.includes("/pub") === false);
    const bad = await client.command("CWD /nonexistent");
    assert.ok(bad.startsWith("550"));
    await client.command("CWD /");
    await client.command("CDUP");
    const pwdRoot = await client.command("PWD");
    assert.ok(pwdRoot.includes('"/"'));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: PASV and LIST return a vsftpd-style listing", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    const result = await client.dataCommand("LIST", dataPort, null);
    assert.ok(result.first.startsWith("150"));
    assert.ok(result.last.startsWith("226"));
    assert.ok(result.data.toString("utf8").includes("pub"));
    assert.ok(result.data.toString("utf8").includes("incoming"));
    assert.ok(result.data.toString("utf8").includes("backup"));
    assert.ok(result.data.toString("utf8").includes("Mar 05 10:21"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: EPSV works for data connections", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.epsv();
    const result = await client.dataCommand("LIST /pub", dataPort, null);
    assert.ok(result.first.startsWith("150"));
    assert.ok(result.data.toString("utf8").includes("readme.txt"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: NLST returns names only", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    const result = await client.dataCommand("NLST /pub", dataPort, null);
    assert.ok(result.data.toString("utf8").includes("readme.txt"));
    assert.ok(!result.data.toString("utf8").includes("drwxr"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: RETR sends a seeded fake file", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const sizeReply = await client.command("SIZE /pub/readme.txt");
    const size = Number(sizeReply.split(" ")[1]);
    assert.ok(size > 0);
    const listPort = await client.pasv();
    const listResult = await client.dataCommand("LIST /pub", listPort, null);
    assert.ok(listResult.data.toString("utf8").includes(String(size)));
    const dataPort = await client.pasv();
    const result = await client.dataCommand("RETR /pub/readme.txt", dataPort, null);
    assert.ok(result.first.startsWith("150"));
    assert.equal(result.data.length, size);
    assert.ok(result.last.startsWith("226"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: RETR of a missing file returns 550", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    await client.pasv();
    const reply = await client.command("RETR /pub/nope.txt");
    assert.ok(reply.startsWith("550"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: STOR accepts an upload and logs its hash, size and preview", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("CWD /incoming");
    const dataPort = await client.pasv();
    const content = Buffer.from("hello-upload-content\n", "utf8");
    const result = await client.dataCommand("STOR hello.txt", dataPort, content);
    assert.ok(result.first.startsWith("150"));
    assert.ok(result.last.startsWith("226"));
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "file_transfer" && event.payload.direction === "upload");
    assert.equal(events[0].payload.path, "/incoming/hello.txt");
    assert.equal(events[0].payload.size, content.length);
    assert.ok(events[0].payload.sha256.length === 64);
    assert.ok(events[0].payload.previewText.includes("hello-upload"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: uploaded bytes are never written to the host disk", async () => {
  const watchDir = tempDir();
  const cwdBefore = readdirSync(process.cwd());
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("CWD /incoming");
    const dataPort = await client.pasv();
    const content = Buffer.from("disk-watch-content-xyz\n", "utf8");
    await client.dataCommand("STOR watch.txt", dataPort, content);
    client.close();
    await new Promise((resolve) => setTimeout(resolve, 300));
    const watchAfter = readdirSync(watchDir);
    assert.deepEqual(watchAfter, []);
    const cwdAfter = readdirSync(process.cwd());
    assert.deepEqual(cwdAfter, cwdBefore);
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
    rmSync(watchDir, { recursive: true, force: true });
  }
});

test("ftp: upload beyond the size limit is rejected", async () => {
  const made = await startServer({ configOverrides: { FTP_MAX_UPLOAD_BYTES: 10 } });
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("CWD /incoming");
    const dataPort = await client.pasv();
    const content = Buffer.from("this-is-way-too-long-for-the-limit\n", "utf8");
    const result = await client.dataCommand("STOR big.txt", dataPort, content);
    assert.ok(result.last.startsWith("552"));
    const listPort = await client.pasv();
    const listResult = await client.dataCommand("LIST /incoming", listPort, null);
    assert.ok(!listResult.data.toString("utf8").includes("big.txt"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: uploaded file is listed and downloadable in the same session", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("CWD /incoming");
    const storPort = await client.pasv();
    const content = Buffer.from("roundtrip-content\n", "utf8");
    await client.dataCommand("STOR round.txt", storPort, content);
    const listPort = await client.pasv();
    const listResult = await client.dataCommand("LIST", listPort, null);
    assert.ok(listResult.data.toString("utf8").includes("round.txt"));
    const retrPort = await client.pasv();
    const retrResult = await client.dataCommand("RETR round.txt", retrPort, null);
    assert.deepEqual(retrResult.data, content);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: changes never leak between sessions", async () => {
  const made = await startServer({});
  try {
    const client1 = new FtpClient(made.port);
    await client1.login("admin", "admin");
    await client1.command("CWD /incoming");
    const storPort = await client1.pasv();
    await client1.dataCommand("STOR leak.txt", storPort, Buffer.from("leak\n", "utf8"));
    client1.close();
    const client2 = new FtpClient(made.port);
    await client2.login("admin", "admin");
    await client2.command("CWD /incoming");
    const listPort = await client2.pasv();
    const listResult = await client2.dataCommand("LIST", listPort, null);
    assert.ok(!listResult.data.toString("utf8").includes("leak.txt"));
    client2.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: MKD, RMD, DELE, RNFR and RNTO work in the fake tree", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    const mkd = await client.command("MKD /incoming/newdir");
    assert.ok(mkd.startsWith("257"));
    const storPort = await client.pasv();
    await client.dataCommand("STOR /incoming/newdir/file.txt", storPort, Buffer.from("x\n", "utf8"));
    const rmdFail = await client.command("RMD /incoming/newdir");
    assert.ok(rmdFail.startsWith("550"));
    const rnfr = await client.command("RNFR /incoming/newdir/file.txt");
    assert.ok(rnfr.startsWith("350"));
    const rnto = await client.command("RNTO /incoming/newdir/renamed.txt");
    assert.ok(rnto.startsWith("250"));
    const dele = await client.command("DELE /incoming/newdir/renamed.txt");
    assert.ok(dele.startsWith("250"));
    const rmd = await client.command("RMD /incoming/newdir");
    assert.ok(rmd.startsWith("250"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: PORT and EPRT are refused (no bounce attacks)", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    const portReply = await client.command("PORT 127,0,0,1,15,200");
    assert.ok(portReply.startsWith("500"));
    assert.ok(portReply.includes("Illegal PORT"));
    const eprtReply = await client.command("EPRT |1|127.0.0.1|12345|");
    assert.ok(eprtReply.startsWith("500"));
    assert.ok(eprtReply.includes("Illegal EPRT"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: data peer check rejects a different IP", () => {
  assert.equal(isAllowedDataPeer("127.0.0.1", "127.0.0.1"), true);
  assert.equal(isAllowedDataPeer("127.0.0.1", "192.168.1.5"), false);
  assert.equal(isAllowedDataPeer("127.0.0.1", "::ffff:127.0.0.1"), true);
  assert.equal(isAllowedDataPeer("::ffff:127.0.0.1", "127.0.0.1"), true);
});

test("ftp: unknown commands get 500", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    const reply = await client.command("FOOBAR xyz");
    assert.ok(reply.startsWith("500"));
    const site = await client.command("SITE CHMOD 777 /pub");
    assert.ok(site.startsWith("500"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: overlong command line is rejected", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    const reply = await client.command(`NOOP ${"a".repeat(600)}`);
    assert.ok(reply.startsWith("500"));
    assert.ok(reply.includes("too long"));
    const noop = await client.command("NOOP");
    assert.ok(noop.startsWith("200"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: idle timeout closes the control connection", async () => {
  const made = await startServer({ configOverrides: { FTP_IDLE_TIMEOUT_MS: 200 } });
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal(client.closed, true);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: per-IP connection limit is enforced", async () => {
  const made = await startServer({ configOverrides: { FTP_MAX_CONNECTIONS_PER_IP: 2 } });
  try {
    const c1 = new FtpClient(made.port);
    await c1.connect();
    await c1.nextLine();
    const c2 = new FtpClient(made.port);
    await c2.connect();
    await c2.nextLine();
    const c3 = new FtpClient(made.port);
    await c3.connect();
    const reply = await c3.nextLine();
    assert.ok(reply && reply.startsWith("421"));
    await new Promise((resolve) => setTimeout(resolve, 200));
    c1.close();
    c2.close();
    c3.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: passive listeners are closed after use and on disconnect", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    await client.dataCommand("LIST", dataPort, null);
    const secondConnect = await new Promise((resolve) => {
      const socket = net.connect(dataPort, "127.0.0.1");
      socket.on("connect", () => {
        socket.destroy();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
      setTimeout(() => resolve(false), 1000);
    });
    assert.equal(secondConnect, false);
    client.close();
    await new Promise((resolve) => setTimeout(resolve, 300));
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: path traversal never reads host files", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    const dataPort1 = await client.pasv();
    const result1 = await client.dataCommand("RETR ../../Windows/win.ini", dataPort1, null);
    // RETR without a successful data transfer: first reply is 550, no data
    assert.ok(result1.first.startsWith("550") || result1.last.startsWith("550") || result1.data.length === 0);
    assert.ok(!result1.data.toString("utf8").includes("[fonts]"));
    const cwdReply = await client.command("CWD ../../..");
    assert.ok(cwdReply.startsWith("250") || cwdReply.startsWith("550"));
    const pwd = await client.command("PWD");
    assert.ok(pwd.includes('"/"') || pwd.includes("/pub") || pwd.includes("/backup"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: modules import no " + "fs" + ", " + "child" + "_process, http or dns modules", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = [
    join(here, "..", "src", "server.js"),
    join(here, "..", "src", "session.js"),
    join(here, "..", "src", "commands.js"),
    join(here, "..", "src", "data-channel.js"),
    join(here, "..", "src", "events.js"),
    join(here, "..", "src", "ftp-seed.js"),
  ];
  const banned = ["node:" + "fs", "node:http", "node:dns", "node:" + "child" + "_process"];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const bannedModule of banned) {
      assert.ok(!text.includes(bannedModule), `${file} imports ${bannedModule}`);
    }
  }
});

test("ftp-events: connection_open and connection_close are emitted", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("QUIT");
    const opens = await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_open");
    assert.equal(opens[0].payload.clientVersion, null);
    const closes = await waitForEvents(made.eventsDir, (event) => event.eventType === "connection_close");
    assert.ok(closes[0].payload.reason);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: every command is logged as ftp_command with its response code", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("PWD");
    await client.command("NOOP");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "ftp_command" && event.payload.verb === "NOOP");
    assert.equal(events[0].payload.responseCode, 200);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: PASS argument is redacted in ftp_command events", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    await client.nextLine();
    await client.command("USER admin");
    await client.command("PASS supersecret999");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "ftp_command" && event.payload.verb === "PASS");
    assert.equal(events[0].payload.arg, "[redacted]");
    assert.ok(!JSON.stringify(events).includes("supersecret999") || events.some((event) => event.eventType === "auth_attempt"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: auth_attempt carries username and password", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("test", "test");
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "auth_attempt");
    assert.equal(events[0].payload.username, "test");
    assert.equal(events[0].payload.password, "test");
    assert.equal(events[0].payload.success, true);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: file_transfer carries direction, path, size and sha256", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const dataPort = await client.pasv();
    await client.dataCommand("RETR /pub/readme.txt", dataPort, null);
    const events = await waitForEvents(made.eventsDir, (event) => event.eventType === "file_transfer");
    assert.equal(events[0].payload.direction, "download");
    assert.equal(events[0].payload.path, "/pub/readme.txt");
    assert.ok(events[0].payload.size > 0);
    assert.equal(events[0].payload.sha256.length, 64);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: all emitted events pass validateEvent", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("admin", "admin");
    await client.command("PWD");
    const dataPort = await client.pasv();
    await client.dataCommand("LIST", dataPort, null);
    await client.command("QUIT");
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = readEvents(made.eventsDir);
    assert.ok(events.length > 0);
    for (const event of events) {
      const checked = validateEvent(event);
      assert.equal(checked.ok, true, JSON.stringify(checked.errors));
    }
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp-events: attacker passwords never appear in operational logs", async () => {
  const logs = [];
  const recordingLogger = {
    info: (fields, message) => logs.push(JSON.stringify({ fields, message })),
    warn: (fields, message) => logs.push(JSON.stringify({ fields, message })),
    error: (fields, message) => logs.push(JSON.stringify({ fields, message })),
  };
  const made = await startServer({ logger: recordingLogger });
  try {
    const client = new FtpClient(made.port);
    await client.connect();
    await client.nextLine();
    await client.command("USER victimuser");
    await client.command("PASS supersecret123");
    await new Promise((resolve) => setTimeout(resolve, 300));
    const allLogs = logs.join("\n");
    assert.ok(!allLogs.includes("supersecret123"));
    assert.ok(!allLogs.includes("victimuser"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("vfs: shared package exports the API used by the SSH honeypot", async () => {
  const vfs = createVfs(buildFtpSeed());
  assert.equal(typeof vfs.get, "function");
  assert.equal(typeof vfs.list, "function");
  assert.equal(typeof vfs.readFile, "function");
  assert.equal(typeof vfs.stat, "function");
  assert.equal(typeof vfs.mkdir, "function");
  assert.equal(typeof vfs.writeFile, "function");
  assert.equal(typeof vfs.removeFile, "function");
  assert.equal(typeof vfs.removeDir, "function");
  assert.equal(typeof vfs.rename, "function");
  assert.equal(typeof vfs.countNodes, "function");
  assert.equal(typeof vfs.resolve, "function");
  assert.ok(vfs.get("/pub"));
  assert.equal(vfs.stat("/pub/readme.txt").type, "file");
  assert.ok(vfs.writeFile("/pub/new.txt", Buffer.from("hi\n", "utf8"), {}));
  assert.equal(vfs.readFile("/pub/new.txt").toString("utf8"), "hi\n");
});

test("launcher: start-all starts ssh, http and ftp on port 0 and closes them cleanly", async () => {
  const { startAll } = await import("../../../tools/start-all.js");
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const baseConfig = loadConfig({ BIND_HOST: "127.0.0.1", EVENT_DIR: eventsDir, FTP_AUTH_FAIL_DELAY_MS: 0, LLM_MODE: "mock" });
  const cfg = { ...baseConfig, SSH_PORT: 0, HTTP_PORT: 0, FTP_PORT: 0 };
  const fakeLlm = {
    async respond() {
      return { output: "fake\n", exitCode: 0, meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0, reason: null, attempts: [] } };
    },
    async respondHttp() {
      return { ok: false };
    },
  };
  const result = await startAll({ config: cfg, logger: silentLogger, llmService: fakeLlm });
  try {
    assert.ok(result.services.ssh.address().port > 0);
    assert.ok(result.services.http.address().port > 0);
    assert.ok(result.services.ftp.address().port > 0);
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("integration: one session per service produces valid events in three event files", async () => {
  const { startAll } = await import("../../../tools/start-all.js");
  const { Client: SshClient } = await import("ssh2");
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const baseConfig = loadConfig({ BIND_HOST: "127.0.0.1", EVENT_DIR: eventsDir, FTP_AUTH_FAIL_DELAY_MS: 0, LLM_MODE: "mock", SSH_IDLE_TIMEOUT_MS: 60000 });
  const cfg = { ...baseConfig, SSH_PORT: 0, HTTP_PORT: 0, FTP_PORT: 0, SSH_LLM_DEADLINE_MS: 1000 };
  const fakeLlm = {
    async respond() {
      return { output: "fake-ssh\n", exitCode: 0, meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0, reason: null, attempts: [] } };
    },
    async respondHttp() {
      return { ok: false };
    },
  };
  const result = await startAll({ config: cfg, logger: silentLogger, llmService: fakeLlm });
  try {
    const sshPort = result.services.ssh.address().port;
    const httpPort = result.services.http.address().port;
    const ftpPort = result.services.ftp.address().port;
    // SSH login + command via ssh2 client
    await new Promise((resolve, reject) => {
      const conn = new SshClient();
      conn.on("ready", () => {
        conn.exec("whoami", (error, stream) => {
          if (error) {
            conn.end();
            reject(error);
            return;
          }
          stream.on("close", () => {
            conn.end();
            resolve();
          });
          stream.on("data", () => {});
        });
      });
      conn.on("error", reject);
      conn.connect({ host: "127.0.0.1", port: sshPort, username: "admin", password: "admin" });
    });
    // HTTP request
    await new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: httpPort, method: "GET", path: "/" }, (res) => {
        res.on("data", () => {});
        res.on("end", resolve);
      });
      req.on("error", reject);
      req.end();
    });
    // FTP login + LIST
    const ftpClient = new FtpClient(ftpPort);
    await ftpClient.login("anonymous", "x");
    const dataPort = await ftpClient.pasv();
    await ftpClient.dataCommand("LIST", dataPort, null);
    ftpClient.close();
    await new Promise((resolve) => setTimeout(resolve, 500));
    for (const name of ["ssh.jsonl", "http.jsonl", "ftp.jsonl"]) {
      const file = join(eventsDir, name);
      assert.ok(existsSync(file), `${name} should exist`);
      const lines = readFileSync(file, "utf8").trim().split("\n").filter((line) => line !== "");
      assert.ok(lines.length > 0, `${name} should have events`);
      for (const line of lines) {
        const event = JSON.parse(line);
        const checked = validateEvent(event);
        assert.equal(checked.ok, true, `${name}: ${JSON.stringify(checked.errors)}`);
        assert.ok(event.sessionId);
      }
    }
    const sshEvents = readFileSync(join(eventsDir, "ssh.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(sshEvents.some((event) => event.eventType === "connection_open" || event.eventType === "command"));
    const httpEvents = readFileSync(join(eventsDir, "http.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(httpEvents.some((event) => event.eventType === "http_request"));
    const ftpEvents = readFileSync(join(eventsDir, "ftp.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(ftpEvents.some((event) => event.eventType === "connection_open"));
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("integration: ssh and http share one LLM service instance", async () => {
  const { startAll } = await import("../../../tools/start-all.js");
  const dir = tempDir();
  const eventsDir = join(dir, "events");
  const baseConfig = loadConfig({ BIND_HOST: "127.0.0.1", EVENT_DIR: eventsDir, FTP_AUTH_FAIL_DELAY_MS: 0, LLM_MODE: "mock" });
  const cfg = { ...baseConfig, SSH_PORT: 0, HTTP_PORT: 0, FTP_PORT: 0 };
  const fakeLlm = {
    async respond() {
      return { output: "shared\n", exitCode: 0, meta: { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0, reason: null, attempts: [] } };
    },
    async respondHttp() {
      return { ok: false };
    },
  };
  const result = await startAll({ config: cfg, logger: silentLogger, llmService: fakeLlm });
  try {
    assert.equal(result.llmService, fakeLlm);
  } finally {
    await result.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ftp: login directory is root and PWD reports it", async () => {
  const made = await startServer({});
  try {
    const anon = new FtpClient(made.port);
    await anon.login("anonymous", "x");
    const pwdAnon = await anon.command("PWD");
    assert.ok(pwdAnon.startsWith('257 "/"'));
    anon.close();
    const admin = new FtpClient(made.port);
    await admin.login("admin", "admin");
    const pwdAdmin = await admin.command("PWD");
    assert.ok(pwdAdmin.startsWith('257 "/"'));
    admin.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: curl-style relative CWD reaches backup and incoming", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const cwdBackup = await client.command("CWD backup");
    assert.ok(cwdBackup.startsWith("250"));
    const pwdBackup = await client.command("PWD");
    assert.ok(pwdBackup.includes("/backup"));
    await client.command("CDUP");
    const cwdIncoming = await client.command("CWD incoming");
    assert.ok(cwdIncoming.startsWith("250"));
    const pwdIncoming = await client.command("PWD");
    assert.ok(pwdIncoming.includes("/incoming"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: curl-style RETR of pub/readme.txt works after a relative CWD", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const sizeReply = await client.command("SIZE pub/readme.txt");
    const size = Number(sizeReply.split(" ")[1]);
    assert.ok(size > 0);
    const dataPort = await client.pasv();
    const result = await client.dataCommand("RETR pub/readme.txt", dataPort, null);
    assert.ok(result.first.startsWith("150"));
    assert.equal(result.data.length, size);
    assert.ok(result.last.startsWith("226"));
    const cwdPub = await client.command("CWD pub");
    assert.ok(cwdPub.startsWith("250"));
    const dataPort2 = await client.pasv();
    const result2 = await client.dataCommand("RETR readme.txt", dataPort2, null);
    assert.equal(result2.data.length, size);
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});

test("ftp: anonymous upload is limited to incoming with relative paths", async () => {
  const made = await startServer({});
  try {
    const client = new FtpClient(made.port);
    await client.login("anonymous", "x");
    const storPort1 = await client.pasv();
    const ok = await client.dataCommand("STOR incoming/anon-rel.txt", storPort1, Buffer.from("anon-rel\n", "utf8"));
    assert.ok(ok.last.startsWith("226"));
    const storPort2 = await client.pasv();
    const bad = await client.dataCommand("STOR pub/evil.txt", storPort2, Buffer.from("evil\n", "utf8"));
    assert.ok(bad.last.startsWith("553"));
    await client.command("CWD incoming");
    const storPort3 = await client.pasv();
    const ok2 = await client.dataCommand("STOR anon-cwd.txt", storPort3, Buffer.from("anon-cwd\n", "utf8"));
    assert.ok(ok2.last.startsWith("226"));
    client.close();
  } finally {
    await made.ftp.close();
    rmSync(made.dir, { recursive: true, force: true });
  }
});
