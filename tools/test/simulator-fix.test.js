import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import ssh2 from "ssh2";
const SshServer = ssh2.Server;
import { runCli, buildRequestList, SCENARIO_NAMES } from "../attack-simulator.js";
import { generateEd25519HostKey } from "../../services/ssh-honeypot/src/hostkey.js";

function captureOutput() {
  const lines = [];
  const errors = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (...args) => {
    lines.push(args.join(" "));
  };
  console.error = (...args) => {
    errors.push(args.join(" "));
  };
  return {
    lines,
    errors,
    restore() {
      console.log = originalLog;
      console.error = originalError;
    },
  };
}

async function closedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function startFakeFtp(options = {}) {
  const sockets = new Set();
  let dataListener = null;
  let dataSocket = null;
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    let buffer = "";
    socket.write("220 (vsFTPd 3.0.5)\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let index;
      while ((index = buffer.indexOf("\r\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        const verb = line.split(" ")[0].toUpperCase();
        if (verb === "USER") {
          socket.write("331 Please specify the password.\r\n");
        } else if (verb === "PASS") {
          socket.write("230 Login successful.\r\n");
        } else if (verb === "PASV") {
          if (dataListener) dataListener.close();
          dataSocket = null;
          dataListener = net.createServer((candidate) => {
            dataSocket = candidate;
            sockets.add(candidate);
            candidate.on("close", () => sockets.delete(candidate));
            candidate.on("error", () => {});
          });
          dataListener.listen(0, "127.0.0.1", () => {
            const port = dataListener.address().port;
            socket.write(`227 Entering Passive Mode (127,0,0,1,${Math.floor(port / 256)},${port % 256}).\r\n`);
          });
        } else if (verb === "LIST") {
          socket.write("150 Here comes the directory listing.\r\n");
          if (dataSocket) {
            dataSocket.write("drwxr-xr-x    2 ftp      ftp          4096 Mar 05 10:21 backup\r\n");
            if (!options.neverCloseData) dataSocket.end();
          }
          socket.write("226 Directory send OK.\r\n");
        } else if (verb === "QUIT") {
          socket.write("221 Goodbye.\r\n");
          socket.end();
        } else {
          socket.write("502 Command not implemented.\r\n");
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    async close() {
      for (const socket of sockets) socket.destroy();
      if (dataListener) dataListener.close();
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

async function startFakeSsh(options = {}) {
  const { privateKey } = generateEd25519HostKey();
  const clients = new Set();
  const server = new SshServer({ hostKeys: [privateKey] }, (client) => {
    clients.add(client);
    client.on("close", () => clients.delete(client));
    client.on("error", () => {});
    client.on("authentication", (ctx) => {
      if (options.acceptAuth && ctx.method === "password" && ctx.username === "root" && ctx.password === "root") {
        ctx.accept();
      } else {
        ctx.reject(["password"]);
      }
    });
    client.on("session", (accept) => {
      const channel = accept();
      channel.on("pty", (acceptPty) => {
        acceptPty();
      });
      channel.on("shell", (acceptShell) => {
        const stream = acceptShell();
        stream.on("error", () => {});
        stream.write("Welcome to Ubuntu 22.0.0 LTS\r\n");
        stream.write("root@srv-web-01:~# ");
        let buffer = "";
        stream.on("data", (chunk) => {
          buffer += chunk.toString("utf8");
          let index;
          while ((index = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, index).replace(/\r$/, "");
            buffer = buffer.slice(index + 1);
            stream.write(`${line}\r\n`);
            if (line === "exit") {
              stream.close();
              client.end();
              return;
            }
            stream.write("root@srv-web-01:~# ");
          }
        });
      });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    async close() {
      for (const client of clients) {
        try {
          client.end();
        } catch {}
      }
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

async function startFakeHttp() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      seen.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "Content-Type": "text/html", Connection: "close" });
      res.end("<html>login</html>");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    seen,
    async close() {
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test("ftp-list prints summary on success against a fake FTP server", async () => {
  const ftp = await startFakeFtp();
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "ftp-list", "--count", "1", "--delay", "0"], { ports: { ftp: ftp.port } });
    assert.equal(code, 0);
    const joined = output.lines.join("\n");
    assert.ok(joined.length > 0);
    assert.ok(joined.includes("scenario: ftp-list"));
    assert.ok(joined.includes("requests sent: 2"));
    assert.ok(joined.includes("requests failed: 0"));
    assert.ok(joined.includes("ftp: LIST /"));
    assert.ok(joined.includes("ftp: LIST /backup"));
  } finally {
    output.restore();
    await ftp.close();
  }
});

test("ftp-list prints summary on failure against a closed port, with failed count, not blank", async () => {
  const port = await closedPort();
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "ftp-list", "--count", "1", "--delay", "0"], { ports: { ftp: port } });
    assert.equal(code, 1);
    const joined = output.lines.join("\n");
    assert.ok(joined.length > 0);
    assert.ok(joined.includes("scenario: ftp-list"));
    assert.ok(joined.includes("requests sent: 0"));
    assert.ok(joined.includes("requests failed: 2"));
  } finally {
    output.restore();
  }
});

test("mixed prints one summary when FTP succeeds, with all three sub-scenarios counted", async () => {
  const ssh = await startFakeSsh({ acceptAuth: true });
  const ftp = await startFakeFtp();
  const httpServer = await startFakeHttp();
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "mixed", "--count", "1", "--delay", "0"], { ports: { ssh: ssh.port, ftp: ftp.port, http: httpServer.port } });
    assert.equal(code, 0);
    const joined = output.lines.join("\n");
    assert.equal(output.lines.filter((line) => line.startsWith("scenario: mixed")).length, 1);
    assert.ok(joined.includes("requests sent: 8"));
    assert.ok(joined.includes("requests failed: 0"));
    assert.ok(joined.includes("ssh: whoami"));
    assert.ok(joined.includes("ftp: LIST /"));
    assert.ok(joined.includes("http: GET /wp-login.php"));
    assert.ok(joined.includes("http: POST /wp-login.php"));
    assert.deepEqual(httpServer.seen, ["GET /wp-login.php", "POST /wp-login.php"]);
  } finally {
    output.restore();
    await ssh.close();
    await ftp.close();
    await httpServer.close();
  }
});

test("mixed prints one summary when FTP fails, with FTP failed counted and HTTP still counted", async () => {
  const ssh = await startFakeSsh({ acceptAuth: true });
  const httpServer = await startFakeHttp();
  const ftpPort = await closedPort();
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "mixed", "--count", "1", "--delay", "0"], { ports: { ssh: ssh.port, ftp: ftpPort, http: httpServer.port } });
    assert.equal(code, 1);
    const joined = output.lines.join("\n");
    assert.equal(output.lines.filter((line) => line.startsWith("scenario: mixed")).length, 1);
    assert.ok(joined.includes("requests sent: 6"));
    assert.ok(joined.includes("requests failed: 2"));
    assert.deepEqual(httpServer.seen, ["GET /wp-login.php", "POST /wp-login.php"]);
  } finally {
    output.restore();
    await ssh.close();
    await httpServer.close();
  }
});

test("basic-ssh prints summary on auth failure, with failed count, not blank", async () => {
  const ssh = await startFakeSsh({ acceptAuth: false });
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "basic-ssh", "--count", "1", "--delay", "0"], { ports: { ssh: ssh.port } });
    assert.equal(code, 1);
    const joined = output.lines.join("\n");
    assert.ok(joined.length > 0);
    assert.ok(joined.includes("scenario: basic-ssh"));
    assert.ok(joined.includes("requests sent: 0"));
    assert.ok(joined.includes("requests failed: 4"));
  } finally {
    output.restore();
    await ssh.close();
  }
});

test("live run exits with code 1 when any request failed, and code 0 when none failed", async () => {
  const ftp = await startFakeFtp();
  const output = captureOutput();
  try {
    const okCode = await runCli(["--scenario", "ftp-list", "--count", "1", "--delay", "0"], { ports: { ftp: ftp.port } });
    assert.equal(okCode, 0);
    const port = await closedPort();
    const failCode = await runCli(["--scenario", "ftp-list", "--count", "1", "--delay", "0"], { ports: { ftp: port } });
    assert.equal(failCode, 1);
  } finally {
    output.restore();
    await ftp.close();
  }
});

test("dry-run mixed still prints the exact 8-request list in SSH, FTP, HTTP order, with no connection", async () => {
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "mixed", "--dry-run"]);
    assert.equal(code, 0);
    assert.deepEqual(output.lines.join("\n").split("\n"), [
      "dry-run: mixed",
      "ssh: whoami",
      "ssh: ls",
      "ssh: pwd",
      "ssh: exit",
      "ftp: LIST /",
      "ftp: LIST /backup",
      "http: GET /wp-login.php",
      "http: POST /wp-login.php",
      "requests: 8",
    ]);
    assert.deepEqual(buildRequestList("mixed", 1).map((request) => `${request.protocol}: ${request.display}`), [
      "ssh: whoami",
      "ssh: ls",
      "ssh: pwd",
      "ssh: exit",
      "ftp: LIST /",
      "ftp: LIST /backup",
      "http: GET /wp-login.php",
      "http: POST /wp-login.php",
    ]);
  } finally {
    output.restore();
  }
});

test("list still prints exactly the six scenario names, one per line", async () => {
  const output = captureOutput();
  try {
    const code = await runCli(["--list"]);
    assert.equal(code, 0);
    assert.deepEqual(output.lines, ["basic-ssh", "advanced-ssh", "ftp-list", "http-login", "http-traversal", "mixed"]);
    assert.deepEqual(SCENARIO_NAMES, ["basic-ssh", "advanced-ssh", "ftp-list", "http-login", "http-traversal", "mixed"]);
  } finally {
    output.restore();
  }
});

test("ftp-list prints summary when the data connection never closes", async () => {
  const ftp = await startFakeFtp({ neverCloseData: true });
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "ftp-list", "--count", "1", "--delay", "0"], { ports: { ftp: ftp.port } });
    assert.equal(code, 1);
    const joined = output.lines.join("\n");
    assert.ok(joined.length > 0);
    assert.ok(joined.includes("scenario: ftp-list"));
    assert.ok(joined.includes("requests sent: 0"));
    assert.ok(joined.includes("requests failed: 2"));
  } finally {
    output.restore();
    await ftp.close();
  }
});

test("basic-ssh prints summary on success against a fake SSH server", async () => {
  const ssh = await startFakeSsh({ acceptAuth: true });
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "basic-ssh", "--count", "1", "--delay", "0"], { ports: { ssh: ssh.port } });
    assert.equal(code, 0);
    const joined = output.lines.join("\n");
    assert.ok(joined.includes("scenario: basic-ssh"));
    assert.ok(joined.includes("requests sent: 4"));
    assert.ok(joined.includes("requests failed: 0"));
  } finally {
    output.restore();
    await ssh.close();
  }
});

test("http-login sends both requests in order", async () => {
  const httpServer = await startFakeHttp();
  const output = captureOutput();
  try {
    const code = await runCli(["--scenario", "http-login", "--count", "1", "--delay", "0"], { ports: { http: httpServer.port } });
    assert.equal(code, 0);
    const joined = output.lines.join("\n");
    assert.ok(joined.includes("requests sent: 2"));
    assert.ok(joined.includes("requests failed: 0"));
    assert.deepEqual(httpServer.seen, ["GET /wp-login.php", "POST /wp-login.php"]);
  } finally {
    output.restore();
    await httpServer.close();
  }
});
