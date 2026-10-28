import { normalizeIp, classifyIp } from "./ip.js";

/**
 * Enrich an event with IP classification and geo data.
 *
 * @param {object} event
 * @param {object} [options]
 * @param {object} [options.geoip]
 * @returns {Promise<{ ipClass: string, geo: object|null, ip: string }>}
 */
export async function enrichEvent(event, options = {}) {
  const rawIp = event && event.source && event.source.ip ? String(event.source.ip) : "";
  const ip = normalizeIp(rawIp);
  const ipClass = classifyIp(ip);
  let geo = null;
  if (ipClass === "public" && options.geoip) {
    try {
      geo = await options.geoip.lookup(ip);
    } catch {
      geo = null;
    }
  }
  return { ipClass, geo, ip };
}
