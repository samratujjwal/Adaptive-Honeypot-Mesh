/**
 * Read-only Elasticsearch helpers for the Day 14 API. These never
 * write, never change templates, and never touch Kafka.
 *
 * @param {object} es
 * @returns {object}
 */

function unwrap(response) {
  return response && typeof response === "object" && "body" in response ? response.body : response;
}

function hitsOf(response) {
  const body = unwrap(response);
  const hits = body && body.hits ? body.hits : {};
  const total = hits.total && typeof hits.total.value === "number" ? hits.total.value : (Array.isArray(hits.hits) ? hits.hits.length : 0);
  const docs = (Array.isArray(hits.hits) ? hits.hits : []).map((hit) => ({ id: hit._id, ...(hit._source || {}) }));
  return { docs, total };
}

function termQuery(field, value) {
  return value ? [{ term: { [field]: value } }] : [];
}

function rangeQuery(field, from, to) {
  if (!from && !to) return [];
  const range = {};
  if (from) range.gte = from;
  if (to) range.lte = to;
  return [{ range: { [field]: range } }];
}

async function searchIndex(es, index, query, limit, offset) {
  const response = await es.search({ index, from: offset, size: limit, query: { bool: { filter: query } } });
  return hitsOf(response);
}

/**
 * Search events from daily indices.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {object} filters
 * @returns {Promise<{docs: object[], total: number}>}
 */
export async function searchEvents(es, prefix, filters = {}) {
  const query = [
    ...termQuery("honeypot.service", filters.service),
    ...termQuery("eventType", filters.type),
    ...termQuery("source.ip", filters.sourceIp),
    ...rangeQuery("timestamp", filters.from, filters.to),
  ];
  return searchIndex(es, `${prefix}-events-*`, query, filters.limit ?? 50, filters.offset ?? 0);
}

/**
 * Search sessions.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {object} filters
 * @returns {Promise<{docs: object[], total: number}>}
 */
export async function searchSessions(es, prefix, filters = {}) {
  const query = [
    ...termQuery("service", filters.service),
    ...termQuery("sourceIp", filters.sourceIp),
  ];
  if (typeof filters.closed === "boolean") query.push({ term: { closed: filters.closed } });
  return searchIndex(es, `${prefix}-sessions`, query, filters.limit ?? 50, filters.offset ?? 0);
}

/**
 * Search profiles.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {object} filters
 * @returns {Promise<{docs: object[], total: number}>}
 */
export async function searchProfiles(es, prefix, filters = {}) {
  const query = [
    ...termQuery("service", filters.service),
    ...termQuery("classification.intent", filters.intent),
    ...termQuery("classification.skillLevel", filters.skill),
    ...termQuery("classification.actorType", filters.actor),
  ];
  return searchIndex(es, `${prefix}-profiles`, query, filters.limit ?? 50, filters.offset ?? 0);
}

/**
 * Search attackers.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {object} filters
 * @returns {Promise<{docs: object[], total: number}>}
 */
export async function searchAttackers(es, prefix, filters = {}) {
  const query = [
    ...termQuery("strategy.name", filters.strategy),
    ...termQuery("classification.intent", filters.intent),
  ];
  return searchIndex(es, `${prefix}-attackers`, query, filters.limit ?? 50, filters.offset ?? 0);
}

/**
 * Fetch one attacker by IP, or null when not found.
 *
 * @param {object} es
 * @param {string} prefix
 * @param {string} ip
 * @returns {Promise<object|null>}
 */
export async function getAttackerByIp(es, prefix, ip) {
  try {
    const response = await es.get({ index: `${prefix}-attackers`, id: ip });
    const body = unwrap(response);
    if (!body || !body.found) return null;
    return { id: body._id || ip, ...(body._source || {}) };
  } catch (error) {
    if (error && error.meta && error.meta.statusCode === 404) return null;
    if (error && error.statusCode === 404) return null;
    throw error;
  }
}

/**
 * Compute stats from Elasticsearch counts and aggregations.
 *
 * @param {object} es
 * @param {string} prefix
 * @returns {Promise<object>}
 */
export async function getStats(es, prefix) {
  const eventsResponse = await es.search({
    index: `${prefix}-events-*`, size: 0,
    aggs: { byService: { terms: { field: "honeypot.service" } }, bySourceIp: { terms: { field: "source.ip", size: 10 } } },
  });
  const eventsBody = unwrap(eventsResponse);
  const eventsTotal = eventsBody && eventsBody.hits && eventsBody.hits.total && typeof eventsBody.hits.total.value === "number" ? eventsBody.hits.total.value : 0;
  const eventsByService = {};
  const byService = eventsBody && eventsBody.aggregations && eventsBody.aggregations.byService && eventsBody.aggregations.byService.buckets ? eventsBody.aggregations.byService.buckets : [];
  for (const bucket of byService) eventsByService[bucket.key] = bucket.doc_count;
  const topSourceIps = [];
  const bySourceIp = eventsBody && eventsBody.aggregations && eventsBody.aggregations.bySourceIp && eventsBody.aggregations.bySourceIp.buckets ? eventsBody.aggregations.bySourceIp.buckets : [];
  for (const bucket of bySourceIp) topSourceIps.push({ ip: bucket.key, count: bucket.doc_count });
  async function count(index) {
    const response = await es.search({ index, size: 0 });
    const body = unwrap(response);
    return body && body.hits && body.hits.total && typeof body.hits.total.value === "number" ? body.hits.total.value : 0;
  }
  const sessions = await count(`${prefix}-sessions`);
  const profiles = await count(`${prefix}-profiles`);
  const attackers = await count(`${prefix}-attackers`);
  const profilesResponse = await es.search({
    index: `${prefix}-profiles`, size: 0,
    aggs: { byTool: { terms: { field: "classification.tools", size: 10 } } },
  });
  const profilesBody = unwrap(profilesResponse);
  const topTools = [];
  const byTool = profilesBody && profilesBody.aggregations && profilesBody.aggregations.byTool && profilesBody.aggregations.byTool.buckets ? profilesBody.aggregations.byTool.buckets : [];
  for (const bucket of byTool) topTools.push({ tool: bucket.key, count: bucket.doc_count });
  return { eventsByService, events: eventsTotal, sessions, profiles, attackers, topSourceIps, topTools };
}
