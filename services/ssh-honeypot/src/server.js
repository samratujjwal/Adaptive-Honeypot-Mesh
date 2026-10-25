import ssh2 from "ssh2";
import { v4 as uuidv4 } from "uuid";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createEvent } from "../../../packages/shared/src/event.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { checkPassword, loadCredentials, publicKeyFingerprint } from "./auth.js";
import { loadOrCreateHostKey } from "./hostkey.js";
import { createShellSession, MAX_INPUT_LINE } from "./shell.js";
import { createVfs } from "./vfs.js";
import { buildSeed, uidForUser } from "./seed/ubuntu-2204.js";
import { createCommandEngine } from "./commands.js";

const { Server } = ssh2;
const CLOSE_REASONS = ["client_exit", "idle_timeout", "max_duration", "auth_limit", "client_disconnect", "error"];

function defaultCredentialsPath() {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "config", "credentials.json");
}

function clientVersionOf(info) {
  const software = info && info.header && info.header.versions && info.header.versions.software;
  if (typeof software !== "string" || software === "") return null;
  return software.slice(0, 128);
}

/**
 * Create an SSH honeypot server. The returned object lets callers
 * listen on port 0 for tests, read the bound address, and close
 * cleanly. No attacker input is ever run as a command.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} options.sink
 * @param {Array<{ username: string, password: string }>} [options.credentials]
 * @param {string} [options.credentialsPath]
 * @param {string} [options.hostKeyPath]
 * @returns {{ listen: (port?: number, host?: string) => Promise<void>, close: () => Promise<void>, address: () => object | null, server: object }}
 */
export function createSshHoneypot(options) {
  const { config, sink } = options;
  const log = options.logger || logger;
  const credentials = options.credentials || loadCredentials(options.credentialsPath || defaultCredentialsPath());
  const hostKeyPath = options.hostKeyPath || config.SSH_HOST_KEY_PATH;
  const hostKey = loadOrCreateHostKey(hostKeyPath);
  const ident = config.SSH_IDENT;
  const connections = new Map();
  const perIp = new Map();
  let server = null;

  function emitEvent(session, eventType, payload) {
    const event = createEvent({
      honeypot: { service: "ssh", nodeId: config.NODE_ID },
      sessionId: session.sessionId,
      source: { ip: session.sourceIp, port: session.sourcePort },
      eventType,
      payload,
    });
    sink.emit(event);
    return event;
  }

  function closeConnection(session, reason) {
    if (session.closeEmitted) return;
    session.closeEmitted = true;
    if (session.idleTimer) clearTimeout(session.idleTimer);
    if (session.maxTimer) clearTimeout(session.maxTimer);
    const safeReason = CLOSE_REASONS.includes(reason) ? reason : "error";
    emitEvent(session, "connection_close", {
      durationMs: Date.now() - session.startMs,
      commandCount: session.commandCount,
      authAttempts: session.authAttempts,
      bytesIn: session.bytesIn,
      bytesOut: session.bytesOut,
      reason: safeReason,
    });
    try {
      session.client.end();
    } catch {
      /* Closing an already-closed connection is not an error. */
    }
  }

  function resetIdle(session) {
    if (session.idleTimer) clearTimeout(session.idleTimer);
    if (config.SSH_IDLE_TIMEOUT_MS > 0) {
      session.idleTimer = setTimeout(() => {
        closeConnection(session, "idle_timeout");
      }, config.SSH_IDLE_TIMEOUT_MS);
      session.idleTimer.unref?.();
    }
  }

  server = new Server({ hostKeys: [hostKey.privateKey], ident }, (client, info) => {
    const sourceIp = (info && info.ip) || "127.0.0.1";
    const sourcePort = (info && info.port) || 0;
    const total = connections.size;
    const perIpCount = perIp.get(sourceIp) || 0;
    if (total >= config.SSH_MAX_CONNECTIONS || perIpCount >= config.SSH_MAX_CONNECTIONS_PER_IP) {
      try {
        client.end();
      } catch {
        /* Dropped connections need no further handling. */
      }
      return;
    }
    const session = {
      sessionId: uuidv4(),
      client,
      sourceIp,
      sourcePort,
      startMs: Date.now(),
      commandCount: 0,
      authAttempts: 0,
      failedAuthAttempts: 0,
      bytesIn: 0,
      bytesOut: 0,
      closeEmitted: false,
      idleTimer: null,
      maxTimer: null,
      username: null,
      authenticated: false,
      engine: null,
    };
    connections.set(session.sessionId, session);
    perIp.set(sourceIp, perIpCount + 1);
    emitEvent(session, "connection_open", { clientVersion: clientVersionOf(info) });
    resetIdle(session);
    if (config.SSH_MAX_SESSION_MS > 0) {
      session.maxTimer = setTimeout(() => {
        closeConnection(session, "max_duration");
      }, config.SSH_MAX_SESSION_MS);
      session.maxTimer.unref?.();
    }

    client.on("authentication", (ctx) => {
      if (session.closeEmitted) return;
      resetIdle(session);
      session.authAttempts += 1;
      const method = ctx.method;
      const methodsLeft = ["password", "publickey", "keyboard-interactive"];
      if (method === "password") {
        const username = ctx.username;
        const password = ctx.password || "";
        const success = checkPassword(username, password, credentials);
        emitEvent(session, "auth_attempt", { method, username, password, success });
        log.info({ method, username, success }, "auth attempt");
        if (success) {
          session.username = username;
          session.authenticated = true;
          ctx.accept();
          return;
        }
        session.failedAuthAttempts += 1;
        ctx.reject(methodsLeft);
      } else if (method === "publickey") {
        const key = ctx.key || {};
        const fingerprint = key.data ? publicKeyFingerprint(key.data) : null;
        emitEvent(session, "auth_attempt", { method, username: ctx.username, keyFingerprint: fingerprint, success: false });
        log.info({ method, username: ctx.username, keyType: key.algo || null, keyFingerprint: fingerprint }, "auth attempt");
        session.failedAuthAttempts += 1;
        ctx.reject(methodsLeft);
      } else {
        emitEvent(session, "auth_attempt", { method, username: ctx.username, success: false });
        log.info({ method, username: ctx.username, success: false }, "auth attempt");
        if (method === "keyboard-interactive") {
          session.failedAuthAttempts += 1;
        }
        ctx.reject(methodsLeft);
      }
      if (session.failedAuthAttempts >= config.SSH_MAX_AUTH_ATTEMPTS) {
        closeConnection(session, "auth_limit");
      }
    });

    function getEngine() {
      if (session.engine) return session.engine;
      const vfs = createVfs(buildSeed(config.HONEYPOT_HOSTNAME));
      vfs.ensureUserHome(session.username);
      session.engine = createCommandEngine({
        vfs,
        user: { name: session.username, uid: uidForUser(session.username) },
        hostname: config.HONEYPOT_HOSTNAME,
      });
      return session.engine;
    }

    client.on("session", (accept, reject) => {
      if (!session.authenticated) {
        reject();
        return;
      }
      resetIdle(session);
      const sessionChannel = accept();
      let shellSession = null;
      sessionChannel.on("pty", (ptyAccept) => {
        resetIdle(session);
        ptyAccept();
      });
      sessionChannel.on("shell", (shellAccept) => {
        resetIdle(session);
        const stream = shellAccept();
        shellSession = createShellSession({
          stream,
          username: session.username,
          hostname: config.HONEYPOT_HOSTNAME,
          sourceIp: session.sourceIp,
          engine: getEngine(),
          onBytesOut: (bytes) => {
            session.bytesOut += bytes;
          },
          onCommand: (commandRecord) => {
            session.commandCount += 1;
            emitEvent(session, "command", commandRecord);
          },
          onLogout: () => {
            closeConnection(session, "client_exit");
          },
        });
        stream.on("data", (data) => {
          session.bytesIn += data.length;
          resetIdle(session);
          shellSession.handleData(data);
        });
        stream.on("close", () => {
          if (!session.closeEmitted) {
            closeConnection(session, "client_disconnect");
          }
        });
        shellSession.welcome();
      });
      sessionChannel.on("exec", (execAccept, _reject, info) => {
        const stream = execAccept();
        const rawCommand = (info && info.command) || "";
        session.bytesIn += Buffer.byteLength(rawCommand, "utf8");
        resetIdle(session);
        const truncated = rawCommand.length > MAX_INPUT_LINE;
        const command = truncated ? rawCommand.slice(0, MAX_INPUT_LINE) : rawCommand;
        if (command.trim() === "") {
          stream.exit(0);
          stream.end();
          closeConnection(session, "client_exit");
          return;
        }
        const engine = getEngine();
        const result = engine.run(command, { tty: false });
        session.commandCount += 1;
        emitEvent(session, "command", {
          command,
          source: "exec",
          keystrokeCount: 0,
          typingDurationMs: 0,
          usedBackspace: false,
          truncated,
          cwd: result.cwd,
          handled: result.handled,
          exitCode: result.exitCode,
        });
        session.bytesOut += Buffer.byteLength(result.output, "utf8");
        if (result.output !== "") stream.write(result.output);
        stream.exit(result.exitCode);
        stream.end();
        closeConnection(session, "client_exit");
      });
    });

    client.on("error", () => {
      if (!session.closeEmitted) {
        closeConnection(session, "error");
      }
    });
    client.on("close", () => {
      if (session.idleTimer) clearTimeout(session.idleTimer);
      if (session.maxTimer) clearTimeout(session.maxTimer);
      connections.delete(session.sessionId);
      const remaining = (perIp.get(sourceIp) || 1) - 1;
      if (remaining <= 0) {
        perIp.delete(sourceIp);
      } else {
        perIp.set(sourceIp, remaining);
      }
      if (!session.closeEmitted) {
        closeConnection(session, "client_disconnect");
      }
    });
  });

  return {
    server,
    listen(port, host) {
      const bindHost = host || config.BIND_HOST;
      const bindPort = port === undefined || port === null ? config.SSH_PORT : port;
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
        for (const session of [...connections.values()]) {
          if (!session.closeEmitted) {
            closeConnection(session, "client_disconnect");
          }
          const sock = session.client && session.client._sock;
          if (sock && typeof sock.destroy === "function") {
            sock.destroy();
          }
        }
        if (server._srv && typeof server._srv.closeAllConnections === "function") {
          server._srv.closeAllConnections();
        }
        if (!server.listening && !(server._srv && server._srv.listening)) {
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
