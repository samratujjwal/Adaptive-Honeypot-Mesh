import { createServer as createHttpServer } from "node:http";
import express from "express";
import { Server } from "socket.io";
import { createRouter } from "./routes.js";
import { createLiveFeed } from "./live.js";
import { getStats } from "../../../packages/search/src/reads.js";

/**
 * Create the Day 14 API server: Express app plus Socket.IO on
 * one HTTP server, loopback only in dev, read-only routes.
 *
 * @param {object} deps
 * @param {object} deps.es
 * @param {object} deps.logger
 * @param {object} deps.config
 * @returns {object}
 */
export function createServer({ es, logger, config, apiRateLimiter }) {
  const log = logger || { info: () => {}, warn: () => {}, error: () => {} };
  const prefix = config.ES_INDEX_PREFIX;
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "64kb" }));
  app.use(createRouter({ es, prefix, logger: log, apiRateLimiter }));
  const server = createHttpServer(app);
  const io = new Server(server, {
    cors: {
      origin: ["http://127.0.0.1:3001", "http://localhost:3001"],
      methods: ["GET"],
    },
  });
  const live = createLiveFeed({
    es, prefix, io,
    pollMs: config.API_POLL_MS,
    logger: log,
    getStats: () => getStats(es, prefix),
  });
  io.on("connection", async (socket) => {
    try {
      const stats = await getStats(es, prefix);
      socket.emit("hello", { counts: stats, serverTime: new Date().toISOString() });
    } catch {
      socket.emit("hello", { counts: null, serverTime: new Date().toISOString() });
    }
  });
  // Shutdown must go through closeApi, never by overriding
  // server.close: Socket.IO close() itself closes the http server,
  // so an override that calls io.close() recurses into itself and
  // starves the event loop. closeApi stops the live poll first,
  // then lets Socket.IO close the http server.
  server.closeApi = (callback) => {
    live.close();
    try { void io.close(callback); } catch { if (callback) callback(); }
  };
  server.live = live;
  server.io = io;
  server.startLive = () => live.start();
  return server;
}
