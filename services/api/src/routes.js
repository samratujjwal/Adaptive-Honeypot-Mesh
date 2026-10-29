import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isIP } from "node:net";
import { sanitizeDoc } from "./sanitize.js";
import { searchEvents, searchSessions, searchProfiles, searchAttackers, getAttackerByIp, getStats } from "../../../packages/search/src/reads.js";
import { randomUUID } from "node:crypto";

const INTENTS = ["recon", "credential_access", "exploitation", "persistence", "exfiltration", "unknown"];
const SKILLS = ["beginner", "intermediate", "advanced", "unknown"];
const ACTORS = ["bot", "human", "unknown"];
const STRATEGIES = ["engage", "deceive", "contain", "observe"];

function badRequest(res, code) {
  return res.status(400).json({ error: { code } });
}

function serverError(res) {
  return res.status(500).json({ error: { code: "INTERNAL_ERROR" } });
}

function parseLimit(value) {
  if (value === undefined) return 50;
  if (!/^\d+$/.test(String(value))) return null;
  const parsed = Number.parseInt(String(value), 10);
  if (parsed < 1) return 1;
  if (parsed > 200) return 200;
  return parsed;
}

function parseOffset(value) {
  if (value === undefined) return 0;
  if (!/^\d+$/.test(String(value))) return null;
  return Number.parseInt(String(value), 10);
}

function parseEnum(value, allowed) {
  if (value === undefined) return undefined;
  if (!allowed.includes(value)) return null;
  return value;
}

function parseClosed(value) {
  if (value === undefined) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

function parseSafeString(value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value === "" || /[\r\n<>]/.test(value)) return null;
  return value;
}

/**
 * Build the read-only Express router for the Day 14 API.
 *
 * @param {object} deps
 * @param {object} deps.es
 * @param {string} deps.prefix
 * @param {object} deps.logger
 * @returns {object}
 */
export function createRouter({ es, prefix, logger }) {
  const router = express.Router();
  const log = logger || { error: () => {}, warn: () => {} };

  async function health(req, res) {
    let reachable = false;
    try {
      await es.info();
      reachable = true;
    } catch (error) {
      try { log.warn({ code: "ES_UNREACHABLE" }, "Health check could not reach Elasticsearch"); } catch {}
    }
    return res.json({ status: "ok", uptimeMs: Math.max(0, Date.now() - startedAt), es: { reachable } });
  }

  const startedAt = Date.now();

  const dashboardDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../dashboard/public");
  router.use("/dashboard", express.static(dashboardDir));

  router.get("/api/health", health);

  router.get("/api/events", async (req, res) => {
    const limit = parseLimit(req.query.limit);
    const offset = parseOffset(req.query.offset);
    if (limit === null || offset === null) return badRequest(res, "INVALID_PAGINATION");
    const service = parseSafeString(req.query.service);
    const type = parseSafeString(req.query.type);
    const sourceIp = parseSafeString(req.query.sourceIp);
    if (service === null || type === null || sourceIp === null) return badRequest(res, "INVALID_FILTER");
    try {
      const { docs, total } = await searchEvents(es, prefix, { service, type, sourceIp, limit, offset, from: req.query.from, to: req.query.to });
      return res.json({ data: docs.map((doc) => sanitizeDoc(doc)), total, limit, offset });
    } catch (error) {
      try { log.error({ code: "ES_ERROR" }, "Events search failed"); } catch {}
      return serverError(res);
    }
  });

  router.get("/api/sessions", async (req, res) => {
    const limit = parseLimit(req.query.limit);
    const offset = parseOffset(req.query.offset);
    if (limit === null || offset === null) return badRequest(res, "INVALID_PAGINATION");
    const service = parseSafeString(req.query.service);
    const sourceIp = parseSafeString(req.query.sourceIp);
    const closed = parseClosed(req.query.closed);
    if (service === null || sourceIp === null || closed === null) return badRequest(res, "INVALID_FILTER");
    try {
      const { docs, total } = await searchSessions(es, prefix, { service, sourceIp, closed, limit, offset });
      return res.json({ data: docs.map((doc) => sanitizeDoc(doc)), total, limit, offset });
    } catch {
      return serverError(res);
    }
  });

  router.get("/api/profiles", async (req, res) => {
    const limit = parseLimit(req.query.limit);
    const offset = parseOffset(req.query.offset);
    if (limit === null || offset === null) return badRequest(res, "INVALID_PAGINATION");
    const service = parseSafeString(req.query.service);
    const intent = parseEnum(req.query.intent, INTENTS);
    const skill = parseEnum(req.query.skill, SKILLS);
    const actor = parseEnum(req.query.actor, ACTORS);
    if (service === null || intent === null || skill === null || actor === null) return badRequest(res, "INVALID_FILTER");
    try {
      const { docs, total } = await searchProfiles(es, prefix, { service, intent, skill, actor, limit, offset });
      return res.json({ data: docs.map((doc) => sanitizeDoc(doc)), total, limit, offset });
    } catch {
      return serverError(res);
    }
  });

  router.get("/api/attackers", async (req, res) => {
    const limit = parseLimit(req.query.limit);
    const offset = parseOffset(req.query.offset);
    if (limit === null || offset === null) return badRequest(res, "INVALID_PAGINATION");
    const strategy = parseEnum(req.query.strategy, STRATEGIES);
    const intent = parseEnum(req.query.intent, INTENTS);
    if (strategy === null || intent === null) return badRequest(res, "INVALID_FILTER");
    try {
      const { docs, total } = await searchAttackers(es, prefix, { strategy, intent, limit, offset });
      return res.json({ data: docs.map((doc) => sanitizeDoc(doc)), total, limit, offset });
    } catch {
      return serverError(res);
    }
  });

  router.get("/api/attackers/:ip/stix", async (req, res) => {
    const ip = req.params.ip;
    if (isIP(ip) === 0) return badRequest(res, "INVALID_IP");
    try {
      const attacker = await getAttackerByIp(es, prefix, ip);
      if (!attacker) return res.status(404).json({ error: { code: "NOT_FOUND" } });
      const now = new Date().toISOString();
      const objects = [];
      objects.push({
        type: "identity",
        spec_version: "2.1",
        id: "identity--" + randomUUID(),
        created: now,
        modified: now,
        name: ip,
        identity_class: "system",
        description: "honeypot-observed source only. No real-world attribution is claimed.",
      });
      const allowed = new Set(["T1033", "T1057", "T1082", "T1083", "T1087", "T1003", "T1552.001", "T1016", "T1046", "T1105", "T1027", "T1547", "T1190", "T1110.001", "T1078"]);
      const techniques = [...new Set(Array.isArray(attacker.mitreTechniqueIds) ? attacker.mitreTechniqueIds : [])].filter((id) => allowed.has(id));
      for (const techniqueId of techniques) {
        objects.push({
          type: "attack-pattern",
          spec_version: "2.1",
          id: "attack-pattern--" + randomUUID(),
          created: now,
          modified: now,
          name: techniqueId,
          external_references: [{ source_name: "mitre-attack", external_id: techniqueId }],
        });
      }
      const sessions = await searchSessions(es, prefix, { sourceIp: ip, limit: 20, offset: 0 });
      for (const session of sessions.docs) {
        objects.push({
          type: "observed-data",
          spec_version: "2.1",
          id: "observed-data--" + randomUUID(),
          created: now,
          modified: now,
          first_observed: session.firstSeen || now,
          last_observed: session.lastSeen || now,
          number_observed: typeof session.eventCount === "number" ? session.eventCount : 0,
          object_refs: [],
        });
      }
      return res.json({ type: "bundle", spec_version: "2.1", id: "bundle--" + randomUUID(), objects });
    } catch {
      return serverError(res);
    }
  });

  router.get("/api/attackers/:ip", async (req, res) => {
    const ip = req.params.ip;
    if (isIP(ip) === 0) return badRequest(res, "INVALID_IP");
    try {
      const doc = await getAttackerByIp(es, prefix, ip);
      if (!doc) return res.status(404).json({ error: { code: "NOT_FOUND" } });
      return res.json({ data: sanitizeDoc(doc) });
    } catch {
      return serverError(res);
    }
  });

  router.get("/api/stats", async (req, res) => {
    try {
      const stats = await getStats(es, prefix);
      return res.json(stats);
    } catch {
      return serverError(res);
    }
  });

  router.use((req, res) => res.status(404).json({ error: { code: "NOT_FOUND" } }));

  return router;
}
