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
  const { eventsTemplate, sessionsTemplate, profilesTemplate, attackersTemplate } = buildTemplates(prefix);
  await es.indices.putIndexTemplate({ name: `${prefix}-events`, ...eventsTemplate });
  await es.indices.putIndexTemplate({ name: `${prefix}-sessions`, ...sessionsTemplate });
  await es.indices.putIndexTemplate({ name: `${prefix}-profiles`, ...profilesTemplate });
  await es.indices.putIndexTemplate({ name: `${prefix}-attackers`, ...attackersTemplate });
  const exists = await es.indices.exists({ index: `${prefix}-sessions` });
  const existsValue = exists && typeof exists === "object" && "body" in exists ? exists.body : exists;
  if (!existsValue) {
    await es.indices.create({ index: `${prefix}-sessions`, mappings: sessionsTemplate.template.mappings, settings: sessionsTemplate.template.settings });
  }
  const profilesExists = await es.indices.exists({ index: `${prefix}-profiles` });
  const profilesExistsValue = profilesExists && typeof profilesExists === "object" && "body" in profilesExists ? profilesExists.body : profilesExists;
  if (!profilesExistsValue) {
    await es.indices.create({ index: `${prefix}-profiles`, mappings: profilesTemplate.template.mappings, settings: profilesTemplate.template.settings });
  }
  const attackersExists = await es.indices.exists({ index: `${prefix}-attackers` });
  const attackersExistsValue = attackersExists && typeof attackersExists === "object" && "body" in attackersExists ? attackersExists.body : attackersExists;
  if (!attackersExistsValue) {
    await es.indices.create({ index: `${prefix}-attackers`, mappings: attackersTemplate.template.mappings, settings: attackersTemplate.template.settings });
  }
  return { eventsTemplate: true, sessionsTemplate: true, sessionsIndex: true, profilesTemplate: true, profilesIndex: true, attackersTemplate: true, attackersIndex: true };
}
