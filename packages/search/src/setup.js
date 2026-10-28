import { buildTemplates } from "./templates.js";

/**
 * Ensure index templates and the sessions index exist (idempotent).
 *
 * @param {object} es
 * @param {object} options
 * @param {string} options.prefix
 * @returns {Promise<{ eventsTemplate: boolean, sessionsTemplate: boolean, sessionsIndex: boolean }>}
 */
export async function ensureTemplates(es, { prefix }) {
  const { eventsTemplate, sessionsTemplate } = buildTemplates(prefix);
  await es.indices.putIndexTemplate({ name: `${prefix}-events`, ...eventsTemplate });
  await es.indices.putIndexTemplate({ name: `${prefix}-sessions`, ...sessionsTemplate });
  const exists = await es.indices.exists({ index: `${prefix}-sessions` });
  const existsValue = exists && typeof exists === "object" && "body" in exists ? exists.body : exists;
  if (!existsValue) {
    await es.indices.create({ index: `${prefix}-sessions`, mappings: sessionsTemplate.template.mappings, settings: sessionsTemplate.template.settings });
  }
  return { eventsTemplate: true, sessionsTemplate: true, sessionsIndex: true };
}
