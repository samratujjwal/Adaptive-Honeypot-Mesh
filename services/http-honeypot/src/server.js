import http from "node:http";
import { createEvent } from "../../../packages/shared/src/event.js";
import { logger as sharedLogger } from "../../../packages/shared/src/logger.js";
import { toEventLlm } from "../../../packages/llm/src/service.js";
import { loadPages } from "./pages.js";
import { createPersona } from "../../../packages/persona/src/persona.js";
import { createHoneytokens } from "../../../packages/persona/src/honeytokens.js";
import { routeRequest, nginxPageForTest } from "./router.js";
import { createSessionStore, createTokenStore } from "./sessions.js";
import { buildHttpPayload, buildLlmPayload } from "./events.js";

function parseRawPath(rawUrl) {
  try {
    const url = new URL(rawUrl, "http://127.0.0.1");
    return { pathname: url.pathname, query: url.search ? url.search.slice(1) : "" };
  } catch {
    const parts = String(rawUrl || "/").split("?");
    return { pathname: parts[0] || "/", query: parts[1] || "" };
  }
}

function decodePath(pathname) {
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  return decoded;
}

function isTraversal(pathname) {
  if (pathname.includes("..")) {
    const parts = pathname.split("/");
    if (parts.includes("..")) return true;
  }
  const lower = pathname.toLowerCase();
  if (lower.includes("%2e") || lower.includes("%5c") || lower.includes("..\\")) return true;
  return false;
}

/**
 * Create an HTTP honeypot server.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {{ emit: (event: unknown) => boolean, close: () => void }} options.sink
 * @param {object} [options.llmService]
 * @param {object} [options.logger]
 * @param {string} [options.pagesDir]
 * @param {string} [options.credentialsPath]
 * @param {() => number} [options.now]
 * @returns {{ listen: (port?: number, host?: string) => Promise<void>, close: () => Promise<void>, address: () => object | null, server: object }}
 */
export function createHttpHoneypot(options) {
  const { config, sink } = options;
  const log = options.logger || sharedLogger;
  const clock = typeof options.now === "function" ? options.now : Date.now;
  const persona = options.persona || createPersona({ seed: config.PERSONA_SEED || "change-me-default-seed", hostname: config.HONEYPOT_HOSTNAME, domain: config.HONEYPOT_DOMAIN });
  const honeytokens = options.honeytokens || createHoneytokens(persona, { enabled: config.HONEYTOKENS_ENABLED !== false });
  if (config.PERSONA_SEED === "change-me-default-seed") {
    try { log.warn("PERSONA_SEED is the default value; set your own random seed in .env"); } catch {}
  }
  const loaded = loadPages({ pagesDir: options.pagesDir, credentialsPath: options.credentialsPath, persona, honeytokens });
  const pages = loaded.pages;
  const tokenCredentials = honeytokens.tokens.filter((token) => token.account).map((token) => ({ username: token.account, password: token.value }));
  const credentials = [...loaded.credentials, ...tokenCredentials];
  const tokenStore = createTokenStore({ now: clock });
  const sessionStore = createSessionStore({ windowMs: config.HTTP_SESSION_WINDOW_MS, now: clock });
  const serverHeader = config.HTTP_SERVER_HEADER;
  const connections = new Map();
  const perIp = new Map();
  const rateMap = new Map();
  let server = null;

  function emitEvent(sessionId, sourceIp, sourcePort, eventType, payload, llmField) {
    const input = {
      honeypot: { service: "http", nodeId: config.NODE_ID },
      sessionId,
      source: { ip: sourceIp, port: sourcePort },
      eventType,
      payload,
    };
    if (llmField) input.llm = llmField;
    const event = createEvent(input);
    sink.emit(event);
    return event;
  }

  function checkRate(ip) {
    const nowMs = clock();
    let entry = rateMap.get(ip);
    if (!entry || nowMs - entry.windowStart >= 60000) {
      entry = { count: 0, windowStart: nowMs, warned: false };
      rateMap.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count > config.HTTP_MAX_REQ_PER_MIN_PER_IP) {
      if (!entry.warned) {
        entry.warned = true;
        try {
          log.warn({ ip }, "http rate limit");
        } catch {
          /* Logging must never break the server. */
        }
      }
      return false;
    }
    return true;
  }

  server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    const sourceIp = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress.replace("::ffff:", "") : "127.0.0.1";
    const sourcePort = req.socket && req.socket.remotePort ? req.socket.remotePort : 0;
    const sessionId = sessionStore.getSessionId(sourceIp);
    const method = (req.method || "GET").toUpperCase();
    const httpVersion = req.httpVersion || "1.1";
    const rawUrl = req.url || "/";
    const { pathname: rawPathname, query } = parseRawPath(rawUrl);
    const isOptions = method === "OPTIONS";

    if (!checkRate(sourceIp)) {
      try {
        req.socket.destroy();
      } catch {
        /* Ignore. */
      }
      return;
    }

    let bodyChunks = [];
    let requestBodyText = "";
    let bodyBytes = 0;
    let bodyTruncated = false;
    let oversize = false;
    let responded = false;

    function sendResponse(status, contentType, body, extraHeaders, matchedRoute, credentialsOut, authenticated, llmMeta, llmCommand) {
      if (responded) return;
      responded = true;
      const bodyBuffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
      const headers = {
        Server: serverHeader,
        Date: new Date().toUTCString(),
        "Content-Type": contentType,
        "Content-Length": bodyBuffer.length,
        ...(extraHeaders || {}),
      };
      const isHead = method === "HEAD";
      try {
        res.writeHead(status, headers);
        if (!isHead && bodyBuffer.length > 0) res.write(bodyBuffer);
        res.end();
      } catch {
        try {
          res.end();
        } catch {
          /* Ignore. */
        }
      }
      const responseBodyText = Buffer.isBuffer(body) ? "" : String(body || "");
      const payload = buildHttpPayload({
        method,
        path: rawPathname,
        query,
        httpVersion,
        headers: req.headers,
        bodyPreview: responseBodyText.slice(0, 4096) === "" && bodyChunks.length > 0 ? Buffer.concat(bodyChunks).toString("utf8").slice(0, 4096) : Buffer.concat(bodyChunks).toString("utf8").slice(0, 4096),
        bodyBytes,
        bodyTruncated,
        matchedRoute,
        credentials: credentialsOut || undefined,
        responseStatus: status,
        responseBytes: bodyBuffer.length,
        authenticated: Boolean(authenticated),
      });
      // bodyPreview should be request body, not response body
      payload.bodyPreview = Buffer.concat(bodyChunks).toString("utf8").slice(0, 4096);
      requestBodyText = Buffer.concat(bodyChunks).toString("utf8");
      try {
        emitEvent(sessionId, sourceIp, sourcePort, "http_request", payload);
      } catch {
        /* Event failure must not break the response. */
      }
      try {
        if (honeytokens.tokens.length > 0) {
          const requestText = `${rawPathname}?${query} ${requestBodyText} ${Object.entries(req.headers || {}).map(([k, v]) => `${k}: ${v}`).join(" ")}`;
          const seenUsed = new Set();
          for (const token of honeytokens.lookup(requestText)) {
            if (seenUsed.has(token.id)) continue;
            seenUsed.add(token.id);
            emitEvent(sessionId, sourceIp, sourcePort, "honeytoken", { tokenId: token.id, kind: token.kind, action: "used", via: "http_request" });
          }
          if (matchedRoute === "wp_login" && credentialsOut && credentialsOut.password) {
            for (const token of honeytokens.lookup(credentialsOut.password)) {
              emitEvent(sessionId, sourceIp, sourcePort, "honeytoken", { tokenId: token.id, kind: token.kind, action: "used", via: "http_login", success: status === 302 });
            }
          }
          if ((matchedRoute === "sensitive_env" || matchedRoute === "wp_config_bak") && status === 200) {
            if (!sessionStore.viewedTokens) sessionStore.viewedTokens = new Map();
            let viewed = sessionStore.viewedTokens.get(sessionId);
            if (!viewed) { viewed = new Set(); sessionStore.viewedTokens.set(sessionId, viewed); }
            const bodyStr = Buffer.isBuffer(body) ? body.toString("utf8") : String(body || "");
            for (const token of honeytokens.lookup(bodyStr)) {
              if (!viewed.has(token.id)) {
                viewed.add(token.id);
                emitEvent(sessionId, sourceIp, sourcePort, "honeytoken", { tokenId: token.id, kind: token.kind, action: "viewed", via: "http_read" });
              }
            }
          }
        }
      } catch {
        /* Honeytoken detection must never break the response. */
      }
      if (llmMeta && llmCommand) {
        try {
          emitEvent(sessionId, sourceIp, sourcePort, "llm_response", buildLlmPayload({ command: llmCommand, exitCode: status, outputLength: bodyBuffer.length, outputPreview: responseBodyText.slice(0, 500) }), toEventLlm(llmMeta));
        } catch {
          /* Ignore. */
        }
      }
      try {
        log.info({ method, path: rawPathname, status, ip: sourceIp }, "http request");
      } catch {
        /* Ignore. */
      }
    }

    const requestTimeout = setTimeout(() => {
      if (!responded) {
        responded = true;
        try {
          res.writeHead(408, { Server: serverHeader, "Content-Type": "text/plain", "Content-Length": 0 });
          res.end();
        } catch {
          try {
            req.socket.destroy();
          } catch {
            /* Ignore. */
          }
        }
      }
    }, config.HTTP_REQUEST_TIMEOUT_MS);
    requestTimeout.unref?.();
    req.on("close", () => {
      clearTimeout(requestTimeout);
    });
    res.on("finish", () => {
      clearTimeout(requestTimeout);
    });

    req.on("data", (chunk) => {
      if (oversize) return;
      bodyBytes += chunk.length;
      if (bodyBytes > config.HTTP_MAX_BODY_BYTES) {
        oversize = true;
        bodyTruncated = true;
        try {
          req.pause();
        } catch {
          /* Ignore. */
        }
        const body = nginxPageForTest(serverHeader, 413, "Content Too Large");
        sendResponse(413, "text/html", body, {}, "body_too_large", null, false, null, null);
        return;
      }
      bodyChunks.push(chunk);
    });

    req.on("end", async () => {
      if (oversize || responded) return;
      clearTimeout(requestTimeout);
      const bodyText = Buffer.concat(bodyChunks).toString("utf8");
      requestBodyText = bodyText;
      const decoded = decodePath(rawPathname);
      if (decoded === null || isTraversal(rawPathname) || isTraversal(decoded)) {
        const body = nginxPageForTest(serverHeader, 404, "Not Found");
        sendResponse(404, "text/html", body, {}, "not_found", null, false, null, null);
        return;
      }
      const path = decoded;
      const route = routeRequest({
        method,
        path,
        query,
        headers: req.headers,
        bodyText,
        pages,
        credentials,
        tokenStore,
        sourceIp,
        serverHeader,
        persona,
        honeytokens,
      });
      if (!route.llmEligible) {
        sendResponse(route.status, route.contentType, route.body, route.headers, route.matchedRoute, route.credentials, route.authenticated, null, null);
        return;
      }
      // LLM-eligible path
      const llmEnabled = config.HTTP_LLM_ENABLED && config.LLM_MODE === "real" && options.llmService && typeof options.llmService.respondHttp === "function";
      if (!llmEnabled) {
        const body = nginxPageForTest(serverHeader, 404, "Not Found");
        sendResponse(404, "text/html", body, {}, "not_found", null, route.authenticated, null, null);
        return;
      }
      const llmRequest = {
        method,
        path,
        query,
        headers: req.headers,
        bodyPreview: bodyText.slice(0, 4096),
      };
      let llmResult = null;
      try {
        const deadlineMs = config.HTTP_LLM_DEADLINE_MS;
        const llmPromise = Promise.resolve(options.llmService.respondHttp({ request: llmRequest, ctx: { hostname: config.HONEYPOT_HOSTNAME, sessionId, sourceIp, authenticated: route.authenticated } }));
        const deadlinePromise = new Promise((resolve) => setTimeout(() => resolve({ deadline: true }), deadlineMs));
        const winner = await Promise.race([llmPromise.then((value) => ({ value })), deadlinePromise]);
        if (winner && winner.deadline) {
          llmResult = null;
        } else if (winner && winner.value) {
          llmResult = winner.value;
        }
      } catch {
        llmResult = null;
      }
      if (!llmResult || llmResult.ok === false || typeof llmResult.status !== "number") {
        const body = nginxPageForTest(serverHeader, 404, "Not Found");
        sendResponse(404, "text/html", body, {}, "not_found", null, route.authenticated, null, null);
        return;
      }
      const allowedStatus = new Set([200, 301, 302, 400, 401, 403, 404, 500]);
      const allowedTypes = new Set(["text/html; charset=UTF-8", "application/json", "text/plain", "text/xml"]);
      if (!allowedStatus.has(llmResult.status) || !allowedTypes.has(llmResult.contentType) || typeof llmResult.body !== "string") {
        const body = nginxPageForTest(serverHeader, 404, "Not Found");
        sendResponse(404, "text/html", body, {}, "not_found", null, route.authenticated, null, null);
        return;
      }
      const truncatedBody = Buffer.byteLength(llmResult.body, "utf8") > 32768 ? Buffer.from(llmResult.body, "utf8").subarray(0, 32768).toString("utf8") : llmResult.body;
      sendResponse(llmResult.status, llmResult.contentType, truncatedBody, {}, "llm", null, route.authenticated, llmResult.meta || { source: "llm", model: "fake", cached: false, fallback: false, latencyMs: 0 }, `${method} ${path}`);
    });

    req.on("error", () => {
      clearTimeout(requestTimeout);
    });
  });

  server.on("connection", (socket) => {
    const ip = socket.remoteAddress ? socket.remoteAddress.replace("::ffff:", "") : "127.0.0.1";
    const total = connections.size;
    const perIpCount = perIp.get(ip) || 0;
    if (total >= config.HTTP_MAX_CONNECTIONS || perIpCount >= config.HTTP_MAX_CONNECTIONS_PER_IP) {
      try {
        socket.destroy();
      } catch {
        /* Ignore. */
      }
      return;
    }
    connections.set(socket, ip);
    perIp.set(ip, perIpCount + 1);
    socket.on("close", () => {
      if (connections.has(socket)) {
        connections.delete(socket);
        const remaining = (perIp.get(ip) || 1) - 1;
        if (remaining <= 0) perIp.delete(ip);
        else perIp.set(ip, remaining);
      }
    });
  });

  server.on("clientError", (err, socket) => {
    try {
      const body = nginxPageForTest(serverHeader, 400, "Bad Request");
      socket.end(`HTTP/1.1 400 Bad Request\r\nServer: ${serverHeader}\r\nContent-Type: text/html\r\nContent-Length: ${Buffer.byteLength(body, "utf8")}\r\nConnection: close\r\n\r\n${body}`);
    } catch {
      try { socket.destroy(); } catch {}
    }
    setTimeout(() => { try { socket.destroy(); } catch {} }, 100);
  });
  server.requestTimeout = config.HTTP_REQUEST_TIMEOUT_MS;
  server.headersTimeout = config.HTTP_REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = 0;

  return {
    server,
    listen(port, host) {
      const bindHost = host || config.BIND_HOST;
      const bindPort = port === undefined || port === null ? config.HTTP_PORT : port;
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
        for (const socket of [...connections.keys()]) {
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
