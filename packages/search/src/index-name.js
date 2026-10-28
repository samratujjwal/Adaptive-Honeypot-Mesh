/**
 * Build the daily events index name from an event timestamp (UTC).
 *
 * @param {string} prefix
 * @param {string} timestamp
 * @returns {string}
 */
export function eventsIndexName(prefix, timestamp) {
  const d = new Date(timestamp);
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${prefix}-events-${year}.${month}.${day}`;
}
