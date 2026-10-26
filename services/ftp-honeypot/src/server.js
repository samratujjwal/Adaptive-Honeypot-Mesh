import net from "node:net";
import { createEvent } from "../../../packages/shared/src/event.js";
import { logger as sharedLogger } from "../../../packages/shared/src/logger.js";
import { createVfs } from "../../../packages/vfs/src/vfs.js";
import { buildFtpSeed } from "./ftp-seed.js";
import { createPersona } from "../../../packages/persona/src/persona.js";
import { createHoneytokens } from "../../../packages/persona/src/honeytokens.js";
import { createFtpSession, resolveFtpPath } from "./session.js";
import { parseFtpCommand, formatList, formatNlst, formatListLine, fileSize, fileBytes, formatMdtm, parseListArg, previewTextFromBytes, sha256Hex } from "./commands.js";
import { isAllowedDataPeer, normalizeIp } from "./data-channel.js";
import { buildConnectionOpenPayload, buildAuthPayload, buildCommandPayload, buildFileTransferPayload, buildClosePayload } from "./events.js";

function stripIacBytes(buffer) {
  const out = [];
  let i = 0;
  while (i < buffer.length) {
    if (buffer[i] === 0xff) {
      if (i + 1 >= buffer.length) break;
      const cmd = buffer[i + 1];
      if (cmd >= 251 && cmd <= 254) {
        i += 3;
      } else {
        i += 2;
      }
      continue;
    }
    out.push(buffer[i]);
    i += 1;
  }
  return Buffer.from(out);
}

/**
 * Create an FTP honeypot server.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} options.sink
 * @param {object} [options.logger]
 * @param {string} [options.credentialsPath]
 * @param {Array<{ username: string, password: string }>} [options.credentials]
 * @returns {{ listen: (port?: number, host?: string) => Promise<void>, close: () => Promise<void>, address: () => object | null, server: object }}
 */
export function createFtpHoneypot(options) {
  const { config, sink } = options;
  const log = options.logger || sharedLogger;
  const credentials = options.credentials || [
    { username: "admin", password: "admin" },
    { username: "admin", password: "admin123" },
    { username: "root", password: "root" },
    { username: "root", password: "toor" },
    { username: "ftp", password: "ftp" },
    { username: "user", password: "user" },
    { username: "test", password: "test" },
    { username: "ubuntu", password: "ubuntu" },
    { username: "ftpuser", password: "ftpuser" },
    { username: "administrator", password: "administrator" },
  ];
  const persona = options.persona || createPersona({ seed: config.PERSONA_SEED || "change-me-default-seed", hostname: config.HONEYPOT_HOSTNAME, domain: config.HONEYPOT_DOMAIN });
  const honeytokens = options.honeytokens || createHoneytokens(persona, { enabled: config.HONEYTOKENS_ENABLED !== false });
  const tokenCredentials = honeytokens.tokens.filter((token) => token.account).map((token) => ({ username: token.account, password: token.value }));
  const allCredentials = [...credentials, ...tokenCredentials];
  let server = null;
  const connections = new Set();
  const perIp = new Map();

  function emitEvent(session, eventType, payload) {
    const event = createEvent({
      honeypot: { service: "ftp", nodeId: config.NODE_ID },
      sessionId: session.sessionId,
      source: { ip: session.sourceIp, port: session.sourcePort },
      eventType,
      payload,
    });
    try {
      sink.emit(event);
    } catch {
      /* Ignore. */
    }
    return event;
  }

  function emitHoneytokenUsed(session, text, via) {
    if (!honeytokens.tokens.length) return;
    for (const token of honeytokens.lookup(text || "")) {
      emitEvent(session, "honeytoken", { tokenId: token.id, kind: token.kind, action: "used", via });
    }
  }
  function emitHoneytokenViewed(session, output, via) {
    if (!honeytokens.tokens.length) return;
    if (!session.viewedTokens) session.viewedTokens = new Set();
    for (const token of honeytokens.lookup(output || "")) {
      if (!session.viewedTokens.has(token.id)) {
        session.viewedTokens.add(token.id);
        emitEvent(session, "honeytoken", { tokenId: token.id, kind: token.kind, action: "viewed", via });
      }
    }
  }
  function closeDataListener(session) {
    if (session.dataListener) {
      try {
        session.dataListener.close();
      } catch {
        /* Ignore. */
      }
      session.dataListener = null;
    }
    if (session.dataSocket && !session.dataSocket.destroyed) {
      try {
        session.dataSocket.destroy();
      } catch {
        /* Ignore. */
      }
    }
    session.dataSocket = null;
    session.dataSocketPromise = null;
    session.dataSocketResolve = null;
  }

  function createPassiveListener(session) {
    closeDataListener(session);
    return new Promise((resolve) => {
      const ports = [];
      for (let port = config.FTP_PASV_MIN_PORT; port <= config.FTP_PASV_MAX_PORT; port += 1) ports.push(port);
      for (let i = ports.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = ports[i];
        ports[i] = ports[j];
        ports[j] = tmp;
      }
      let index = 0;
      const tryNext = () => {
        if (index >= ports.length) {
          resolve(null);
          return;
        }
        const port = ports[index];
        index += 1;
        const listener = net.createServer((socket) => {
          const peerIp = normalizeIp(socket.remoteAddress || "");
          if (!isAllowedDataPeer(session.sourceIp, peerIp)) {
            try {
              socket.destroy();
            } catch {
              /* Ignore. */
            }
            return;
          }
          session.dataSocket = socket;
          if (session.dataSocketResolve) {
            const resolveFn = session.dataSocketResolve;
            session.dataSocketResolve = null;
            resolveFn(socket);
          }
          try {
            listener.close();
          } catch {
            /* Ignore. */
          }
          session.dataListener = null;
        });
        listener.on("error", () => {
          try {
            listener.close();
          } catch {
            /* Ignore. */
          }
          tryNext();
        });
        listener.listen(port, config.BIND_HOST, () => {
          session.dataListener = listener;
          session.dataPort = port;
          resolve(port);
        });
      };
      tryNext();
    });
  }

  function awaitDataSocket(session) {
    if (session.dataSocket && !session.dataSocket.destroyed) return Promise.resolve(session.dataSocket);
    return new Promise((resolve) => {
      session.dataSocketResolve = resolve;
      session.dataSocketPromise = null;
      const timer = setTimeout(() => {
        if (session.dataSocketResolve) {
          session.dataSocketResolve = null;
          resolve(null);
        }
      }, config.FTP_DATA_TIMEOUT_MS);
      timer.unref?.();
      const originalResolve = session.dataSocketResolve;
      session.dataSocketResolve = (socket) => {
        clearTimeout(timer);
        if (originalResolve) originalResolve(socket);
        resolve(socket);
      };
    });
  }

  server = net.createServer((socket) => {
    const sourceIp = normalizeIp(socket.remoteAddress || "127.0.0.1");
    const sourcePort = socket.remotePort || 0;
    if (connections.size >= config.FTP_MAX_CONNECTIONS || (perIp.get(sourceIp) || 0) >= config.FTP_MAX_CONNECTIONS_PER_IP) {
      try {
        socket.write("421 Too many connections.\r\n", () => {
          try {
            socket.end();
          } catch {
            /* Ignore. */
          }
        });
      } catch {
        try {
          socket.destroy();
        } catch {
          /* Ignore. */
        }
      }
      return;
    }
    connections.add(socket);
    perIp.set(sourceIp, (perIp.get(sourceIp) || 0) + 1);
    const vfs = createVfs(buildFtpSeed({ persona, honeytokens }));
    const session = createFtpSession({ config, vfs, sourceIp });
    session.sourcePort = sourcePort;
    session.socket = socket;
    let closed = false;
    let closeReason = "client_disconnect";
    let buffer = Buffer.alloc(0);
    let idleTimer = null;
    let maxTimer = null;

    function resetIdle() {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        closeReason = "idle_timeout";
        try {
          socket.end();
        } catch {
          try {
            socket.destroy();
          } catch {
            /* Ignore. */
          }
        }
      }, config.FTP_IDLE_TIMEOUT_MS);
      idleTimer.unref?.();
    }

    function sendReply(text, eventVerb, eventArg, eventLoggedIn, eventUser) {
      const line = text.endsWith("\r\n") ? text : `${text}\r\n`;
      session.bytesOut += Buffer.byteLength(line, "utf8");
      try {
        socket.write(line);
      } catch {
        /* Ignore. */
      }
      const code = Number.parseInt(text.slice(0, 3), 10) || 0;
      if (eventVerb) {
        emitEvent(session, "ftp_command", buildCommandPayload({
          verb: eventVerb,
          arg: eventVerb === "PASS" ? "[redacted]" : eventArg,
          loggedIn: Boolean(eventLoggedIn),
          user: eventUser || session.username || "",
          responseCode: code,
        }));
      }
      return code;
    }

    function sendRaw(text) {
      const line = text.endsWith("\r\n") ? text : `${text}\r\n`;
      session.bytesOut += Buffer.byteLength(line, "utf8");
      try {
        socket.write(line);
      } catch {
        /* Ignore. */
      }
    }

    function closeSession(reason) {
      if (closed) return;
      closed = true;
      closeReason = reason || closeReason;
      if (idleTimer) clearTimeout(idleTimer);
      if (maxTimer) clearTimeout(maxTimer);
      closeDataListener(session);
      try {
        socket.end();
      } catch {
        try {
          socket.destroy();
        } catch {
          /* Ignore. */
        }
      }
    }

    function emitClose() {
      emitEvent(session, "connection_close", buildClosePayload({
        durationMs: Math.max(0, Date.now() - session.startMs),
        commandCount: session.commandCount,
        authAttempts: session.authAttempts,
        bytesIn: session.bytesIn,
        bytesOut: session.bytesOut,
        reason: closeReason,
      }));
    }

    socket.on("close", () => {
      if (idleTimer) clearTimeout(idleTimer);
      if (maxTimer) clearTimeout(maxTimer);
      closeDataListener(session);
      connections.delete(socket);
      const remaining = (perIp.get(sourceIp) || 1) - 1;
      if (remaining <= 0) perIp.delete(sourceIp);
      else perIp.set(sourceIp, remaining);
      if (!closed) {
        closed = true;
        emitClose();
      } else {
        emitClose();
      }
    });

    socket.on("error", () => {
      closeReason = "error";
    });

    emitEvent(session, "connection_open", buildConnectionOpenPayload());
    try {
      const banner = `220 ${config.FTP_BANNER}\r\n`;
      session.bytesOut += Buffer.byteLength(banner, "utf8");
      socket.write(banner);
    } catch {
      /* Ignore. */
    }
    resetIdle();
    maxTimer = setTimeout(() => {
      closeReason = "max_duration";
      try {
        socket.write("421 Service not available.\r\n", () => {
          try {
            socket.end();
          } catch {
            /* Ignore. */
          }
        });
      } catch {
        /* Ignore. */
      }
      setTimeout(() => closeSession("max_duration"), 100);
    }, config.FTP_MAX_SESSION_MS);
    maxTimer.unref?.();

    async function handleCommand(verb, arg) {
      session.commandCount += 1;
      if (verb !== "PASS") emitHoneytokenUsed(session, arg, "ftp_command");
      session.lastActivityMs = Date.now();
      resetIdle();
      const nowMs = Date.now();
      session.commandTimes = session.commandTimes.filter((time) => nowMs - time < 60000);
      session.commandTimes.push(nowMs);
      if (session.commandTimes.length > config.FTP_MAX_CMDS_PER_MIN) {
        sendReply("421 Too many commands.", verb, arg, session.loggedIn, session.username);
        closeSession("rate_limit");
        setTimeout(() => {
          try {
            socket.end();
          } catch {
            /* Ignore. */
          }
        }, 50);
        return;
      }

      const beforeLoginAllowed = ["USER", "PASS", "QUIT", "FEAT", "SYST", "NOOP", "HELP"];
      if (!session.loggedIn && !beforeLoginAllowed.includes(verb)) {
        sendReply("530 Please login with USER and PASS.", verb, arg, false, session.username);
        return;
      }

      if (verb === "USER") {
        session.pendingUser = arg;
        sendReply("331 Please specify the password.", verb, arg, false, arg);
        return;
      }

      if (verb === "PASS") {
        if (!session.pendingUser) {
          sendReply("503 Login with USER first.", verb, arg, false, "");
          return;
        }
        const username = session.pendingUser;
        const password = arg;
        const isAnonymous = username === "anonymous" || username === "ftp";
        let success = false;
        if (isAnonymous) {
          success = true;
        } else {
          success = allCredentials.some((entry) => entry.username === username && entry.password === password);
        }
        emitEvent(session, "auth_attempt", buildAuthPayload({ username, password, success }));
        if (honeytokens.tokens.length > 0) {
          for (const token of honeytokens.lookup(password)) {
            emitEvent(session, "honeytoken", { tokenId: token.id, kind: token.kind, action: "used", via: "ftp_auth", success });
          }
        }
        if (success) {
          session.username = username;
          session.loggedIn = true;
          session.anonymous = isAnonymous;
          if (config.FTP_AUTH_FAIL_DELAY_MS > 0) {
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
          sendReply("230 Login successful.", verb, arg, true, username);
        } else {
          session.authAttempts += 1;
          if (config.FTP_AUTH_FAIL_DELAY_MS > 0) {
            await new Promise((resolve) => setTimeout(resolve, config.FTP_AUTH_FAIL_DELAY_MS));
          }
          if (session.authAttempts >= config.FTP_MAX_AUTH_ATTEMPTS) {
            sendReply("421 Service not available.", verb, arg, false, username);
            closeSession("auth_limit");
            setTimeout(() => {
              try {
                socket.end();
              } catch {
                /* Ignore. */
              }
            }, 50);
          } else {
            sendReply("530 Login incorrect.", verb, arg, false, username);
          }
        }
        return;
      }

      if (verb === "QUIT") {
        sendReply("221 Goodbye.", verb, arg, session.loggedIn, session.username);
        closeSession("client_quit");
        setTimeout(() => {
          try {
            socket.end();
          } catch {
            /* Ignore. */
          }
        }, 50);
        return;
      }

      if (verb === "FEAT") {
        const lines = ["211-Features:", " EPSV", " MDTM", " PASV", " REST STREAM", " SIZE", " TVFS", " UTF8", "211 End"];
        const text = lines.join("\r\n");
        session.bytesOut += Buffer.byteLength(text + "\r\n", "utf8");
        try {
          socket.write(`${text}\r\n`);
        } catch {
          /* Ignore. */
        }
        emitEvent(session, "ftp_command", buildCommandPayload({ verb, arg, loggedIn: session.loggedIn, user: session.username || "", responseCode: 211 }));
        return;
      }

      if (verb === "SYST") {
        sendReply("215 UNIX Type: L8", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "NOOP") {
        sendReply("200 NOOP ok.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "HELP") {
        sendReply("214 Help OK.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "PWD" || verb === "XPWD") {
        sendReply(`257 "${session.cwd}" is the current directory.`, verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "CWD") {
        const target = resolveFtpPath(session, arg);
        const node = session.vfs.get(target);
        if (node && node.type === "dir") {
          session.cwd = target;
          sendReply("250 Directory successfully changed.", verb, arg, session.loggedIn, session.username);
        } else {
          sendReply("550 Failed to change directory.", verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "CDUP") {
        const target = resolveFtpPath(session, "..");
        const node = session.vfs.get(target);
        if (node && node.type === "dir") {
          session.cwd = target;
          sendReply("250 Directory successfully changed.", verb, arg, session.loggedIn, session.username);
        } else {
          sendReply("550 Failed to change directory.", verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "TYPE") {
        if (arg === "A") {
          session.type = "A";
          sendReply("200 Switching to ASCII mode.", verb, arg, session.loggedIn, session.username);
        } else if (arg === "I") {
          session.type = "I";
          sendReply("200 Switching to Binary mode.", verb, arg, session.loggedIn, session.username);
        } else {
          sendReply("500 Unrecognised TYPE command.", verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "STRU") {
        if (arg === "F") sendReply("200 Structure set to F.", verb, arg, session.loggedIn, session.username);
        else sendReply("500 Unrecognised STRU command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "MODE") {
        if (arg === "S") sendReply("200 Mode set to S.", verb, arg, session.loggedIn, session.username);
        else sendReply("500 Unrecognised MODE command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "OPTS") {
        if (arg.toUpperCase() === "UTF8 ON") sendReply("200 Always in UTF8 mode.", verb, arg, session.loggedIn, session.username);
        else sendReply("500 Unknown command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "ABOR") {
        sendReply("225 No transfer to ABOR.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "SITE") {
        sendReply("500 Unknown SITE command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "PORT") {
        sendReply("500 Illegal PORT command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "EPRT") {
        sendReply("500 Illegal EPRT command.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "PASV") {
        const port = await createPassiveListener(session);
        if (!port) {
          sendReply("425 Can't open data connection.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const octets = String(config.FTP_PASV_ADDRESS).split(".");
        const p1 = Math.floor(port / 256);
        const p2 = port % 256;
        sendReply(`227 Entering Passive Mode (${octets[0]},${octets[1]},${octets[2]},${octets[3]},${p1},${p2}).`, verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "EPSV") {
        const port = await createPassiveListener(session);
        if (!port) {
          sendReply("425 Can't open data connection.", verb, arg, session.loggedIn, session.username);
          return;
        }
        sendReply(`229 Entering Extended Passive Mode (|||${port}|).`, verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "LIST" || verb === "NLST") {
        if (!session.dataListener && !session.dataSocket) {
          sendReply("425 Use PORT or PASV first.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const pathArg = parseListArg(arg);
        const target = pathArg ? resolveFtpPath(session, pathArg) : session.cwd;
        const node = session.vfs.get(target);
        if (!node) {
          sendReply("550 Failed to open file.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        let listing = "";
        if (node.type === "dir") {
          listing = verb === "LIST" ? formatList(node) : formatNlst(node);
        } else {
          const name = target.split("/").filter((part) => part !== "").pop() || target;
          listing = verb === "LIST" ? `${formatListLine(name, node)}\r\n` : `${name}\r\n`;
        }
        const listingBytes = Buffer.from(listing, "utf8");
        sendRaw("150 Here comes the directory listing.");
        const dataSocket = await awaitDataSocket(session);
        if (!dataSocket) {
          sendReply("425 Can't open data connection.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        try {
          dataSocket.write(listingBytes);
          dataSocket.end();
        } catch {
          /* Ignore. */
        }
        session.bytesOut += listingBytes.length;
        closeDataListener(session);
        sendReply("226 Directory send OK.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "RETR") {
        if (!session.dataListener && !session.dataSocket) {
          sendReply("425 Use PORT or PASV first.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const node = session.vfs.get(target);
        if (!node || node.type !== "file") {
          sendReply("550 Failed to open file.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        const fullBytes = fileBytes(node);
        const offset = session.restOffset || 0;
        session.restOffset = 0;
        const bytes = offset >= fullBytes.length ? Buffer.alloc(0) : fullBytes.subarray(offset);
        sendRaw(`150 Opening BINARY mode data connection for ${target} (${bytes.length} bytes).`);
        const dataSocket = await awaitDataSocket(session);
        if (!dataSocket) {
          sendReply("425 Can't open data connection.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        try {
          if (bytes.length > 0) dataSocket.write(bytes);
          dataSocket.end();
        } catch {
          /* Ignore. */
        }
        session.bytesOut += bytes.length;
        closeDataListener(session);
        sendReply("226 Transfer complete.", verb, arg, session.loggedIn, session.username);
        emitHoneytokenViewed(session, bytes.toString("utf8"), "ftp_read");
        emitEvent(session, "file_transfer", buildFileTransferPayload({
          direction: "download",
          path: target,
          size: bytes.length,
          sha256: sha256Hex(bytes),
          previewText: previewTextFromBytes(bytes),
          previewHex: Buffer.from(bytes.subarray(0, 64)).toString("hex"),
          completed: true,
          truncated: false,
        }));
        return;
      }

      if (verb === "STOR") {
        if (!session.dataListener && !session.dataSocket) {
          sendReply("425 Use PORT or PASV first.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const parentPath = target.split("/").slice(0, -1).join("/") || "/";
        const parentNode = session.vfs.get(parentPath);
        if (!parentNode || parentNode.type !== "dir") {
          sendReply("553 Could not create file.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        if (session.anonymous && !target.startsWith("/incoming/") && target !== "/incoming") {
          sendReply("553 Could not create file.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        const existingNode = session.vfs.get(target);
        if (existingNode && existingNode.type === "dir") {
          sendReply("553 Could not create file.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const isNew = !existingNode;
        if (isNew && session.vfs.countNodes() + 1 > config.FTP_MAX_NODES) {
          sendReply("552 Requested file action aborted.", verb, arg, session.loggedIn, session.username);
          return;
        }
        sendRaw("150 Ok to send data.");
        const dataSocket = await awaitDataSocket(session);
        if (!dataSocket) {
          sendReply("425 Can't open data connection.", verb, arg, session.loggedIn, session.username);
          closeDataListener(session);
          return;
        }
        const chunks = [];
        let totalBytes = 0;
        let overCap = false;
        const received = await new Promise((resolve) => {
          let done = false;
          const finish = (value) => {
            if (!done) {
              done = true;
              resolve(value);
            }
          };
          const timer = setTimeout(() => finish(null), config.FTP_DATA_TIMEOUT_MS);
          timer.unref?.();
          dataSocket.on("data", (chunk) => {
            totalBytes += chunk.length;
            if (totalBytes > config.FTP_MAX_UPLOAD_BYTES || session.sessionBytes + totalBytes > config.FTP_MAX_SESSION_BYTES) {
              overCap = true;
            }
            if (!overCap) chunks.push(chunk);
          });
          dataSocket.on("end", () => {
            clearTimeout(timer);
            finish(Buffer.concat(chunks));
          });
          dataSocket.on("close", () => {
            clearTimeout(timer);
            finish(Buffer.concat(chunks));
          });
          dataSocket.on("error", () => {
            clearTimeout(timer);
            finish(null);
          });
        });
        closeDataListener(session);
        if (received === null || overCap) {
          sendReply("552 Requested file action aborted.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const ok = session.vfs.writeFile(target, received, { mode: "0644", owner: session.username || "ftp", group: session.username || "ftp", mtime: new Date().toISOString() });
        if (!ok) {
          sendReply("553 Could not create file.", verb, arg, session.loggedIn, session.username);
          return;
        }
        session.sessionBytes += received.length;
        session.bytesIn += received.length;
        sendReply("226 Transfer complete.", verb, arg, session.loggedIn, session.username);
        emitEvent(session, "file_transfer", buildFileTransferPayload({
          direction: "upload",
          path: target,
          size: received.length,
          sha256: sha256Hex(received),
          previewText: previewTextFromBytes(received),
          previewHex: Buffer.from(received.subarray(0, 64)).toString("hex"),
          completed: true,
          truncated: false,
        }));
        return;
      }

      if (verb === "SIZE") {
        const target = resolveFtpPath(session, arg);
        const node = session.vfs.get(target);
        if (!node || node.type !== "file") {
          sendReply("550 Could not get file size.", verb, arg, session.loggedIn, session.username);
        } else {
          sendReply(`213 ${fileSize(node)}`, verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "MDTM") {
        const target = resolveFtpPath(session, arg);
        const node = session.vfs.get(target);
        if (!node || node.type !== "file") {
          sendReply("550 Could not get the file modification time.", verb, arg, session.loggedIn, session.username);
        } else {
          sendReply(`213 ${formatMdtm(node.mtime)}`, verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "DELE") {
        if (session.anonymous) {
          sendReply("550 Delete operation failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const removed = session.vfs.removeFile(target);
        if (removed) sendReply("250 Delete operation successful.", verb, arg, session.loggedIn, session.username);
        else sendReply("550 Delete operation failed.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "MKD") {
        if (session.anonymous) {
          sendReply("550 Create directory operation failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        if (session.vfs.countNodes() + 1 > config.FTP_MAX_NODES) {
          sendReply("550 Create directory operation failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const ok = session.vfs.mkdir(target, { type: "dir", mode: "0755", owner: session.username || "ftp", group: session.username || "ftp", mtime: new Date().toISOString(), children: {} });
        if (ok) sendReply(`257 "${target}" created`, verb, arg, session.loggedIn, session.username);
        else sendReply("550 Create directory operation failed.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "RMD") {
        if (session.anonymous) {
          sendReply("550 Remove directory operation failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const removed = session.vfs.removeDir(target);
        if (removed) sendReply("250 Remove directory operation successful.", verb, arg, session.loggedIn, session.username);
        else sendReply("550 Remove directory operation failed.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "RNFR") {
        if (session.anonymous) {
          sendReply("550 RNFR command failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const node = session.vfs.get(target);
        if (!node) {
          sendReply("550 RNFR command failed.", verb, arg, session.loggedIn, session.username);
        } else {
          session.renameFrom = target;
          sendReply("350 Ready for RNTO.", verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      if (verb === "RNTO") {
        if (!session.renameFrom) {
          sendReply("503 RNFR required first.", verb, arg, session.loggedIn, session.username);
          return;
        }
        if (session.anonymous) {
          session.renameFrom = null;
          sendReply("550 Rename failed.", verb, arg, session.loggedIn, session.username);
          return;
        }
        const target = resolveFtpPath(session, arg);
        const from = session.renameFrom;
        session.renameFrom = null;
        const ok = session.vfs.rename(from, target);
        if (ok) sendReply("250 Rename successful.", verb, arg, session.loggedIn, session.username);
        else sendReply("550 Rename failed.", verb, arg, session.loggedIn, session.username);
        return;
      }

      if (verb === "REST") {
        const value = Number.parseInt(arg, 10);
        if (Number.isFinite(value) && value >= 0) {
          session.restOffset = value;
          sendReply(`350 Restart position accepted (${value}).`, verb, arg, session.loggedIn, session.username);
        } else {
          sendReply("500 Unrecognised REST command.", verb, arg, session.loggedIn, session.username);
        }
        return;
      }

      sendReply("500 Unknown command.", verb, arg, session.loggedIn, session.username);
      return;
    }

    socket.on("data", async (chunk) => {
      session.bytesIn += chunk.length;
      resetIdle();
      buffer = Buffer.concat([buffer, stripIacBytes(chunk)]);
      while (true) {
        const newlineIndex = buffer.indexOf(0x0a);
        if (newlineIndex < 0) break;
        let lineBuffer = buffer.subarray(0, newlineIndex);
        buffer = buffer.subarray(newlineIndex + 1);
        if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
        const line = lineBuffer.toString("utf8");
        if (line.length > config.FTP_MAX_LINE) {
          try {
            const reply = "500 Command too long.\r\n";
            session.bytesOut += Buffer.byteLength(reply, "utf8");
            socket.write(reply);
          } catch {
            /* Ignore. */
          }
          continue;
        }
        if (line.trim() === "") continue;
        const { verb, arg } = parseFtpCommand(line);
        try {
          await handleCommand(verb, arg);
        } catch (error) {
          try {
            log.error({ verb }, "FTP command failed");
          } catch {
            /* Ignore. */
          }
          if (!closed) {
            try {
              socket.write("500 Unknown command.\r\n");
            } catch {
              /* Ignore. */
            }
          }
        }
        if (closed) break;
      }
    });
  });

  return {
    server,
    listen(port, host) {
      const bindHost = host || config.BIND_HOST;
      const bindPort = port === undefined || port === null ? config.FTP_PORT : port;
      if ((bindHost === "0.0.0.0" || bindHost === "::") && !config.ALLOW_PUBLIC_BIND) {
        return Promise.reject(new Error("Refusing to bind to a public address without ALLOW_PUBLIC_BIND=true"));
      }
      return new Promise((resolve, reject) => {
        const onError = (error) => {
          server.removeListener("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.removeListener("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(bindPort, bindHost);
      });
    },
    close() {
      return new Promise((resolve) => {
        for (const socket of [...connections]) {
          try {
            socket.destroy();
          } catch {
            /* Ignore. */
          }
        }
        if (!server.listening) {
          resolve();
          return;
        }
        server.close(() => resolve());
        const fallback = setTimeout(resolve, 2000);
        fallback.unref?.();
      });
    },
    address() {
      return server.address();
    },
  };
}

export { isAllowedDataPeer };
