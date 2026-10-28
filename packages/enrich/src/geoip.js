import geoip from "fast-geoip";

/**
 * Create a geoip lookup. This is the only file importing the geoip package.
 *
 * @param {object} [options]
 * @param {boolean} [options.enabled]
 * @param {Function} [options.lookupImpl]
 * @returns {{ lookup: (ip: string) => Promise<object|null> }}
 */
export function createGeoip(options = {}) {
  const enabled = options.enabled !== false;
  const impl = options.lookupImpl || ((ip) => geoip.lookup(ip));
  const display = new Intl.DisplayNames(["en"], { type: "region" });
  return {
    async lookup(ip) {
      if (!enabled) return null;
      try {
        const result = await impl(ip);
        if (!result) return null;
        const country = result.country || null;
        let countryName = null;
        if (country) {
          try { countryName = display.of(country); } catch { countryName = null; }
        }
        const location = result.ll && result.ll.length >= 2 ? { lat: result.ll[0], lon: result.ll[1] } : null;
        return {
          country,
          countryName,
          region: result.region || null,
          city: result.city || null,
          location,
          timezone: result.timezone || null,
        };
      } catch {
        return null;
      }
    },
  };
}
