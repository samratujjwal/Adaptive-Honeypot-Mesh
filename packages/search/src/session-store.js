/**
 * Load sessions from Elasticsearch by id (mget).
 *
 * @param {object} es
 * @param {string} prefix
 * @param {Array<string>} ids
 * @returns {Promise<Map<string, object>>}
 */
export async function getSessions(es, prefix, ids) {
  const map = new Map();
  if (!ids || ids.length === 0) return map;
  const response = await es.mget({ body: { docs: ids.map((id) => ({ _index: `${prefix}-sessions`, _id: id })) } });
  const result = response && response.body ? response.body : response;
  const docs = result && result.docs ? result.docs : [];
  for (const doc of docs) {
    if (doc && doc.found && doc._source) map.set(doc._id, doc._source);
  }
  return map;
}
