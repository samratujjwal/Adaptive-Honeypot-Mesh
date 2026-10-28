/**
 * Normalize an IP string: strip ::ffff: mapping, trim, lower-case IPv6.
 *
 * @param {unknown} ip
 * @returns {string}
 */
export function normalizeIp(ip) {
  let value = String(ip || "").trim().toLowerCase();
  if (value.startsWith("::ffff:")) value = value.slice(7);
  return value;
}

function ipv4Parts(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    nums.push(n);
  }
  return nums;
}

function ipv6Groups(ip) {
  if (!ip.includes(":")) return null;
  const expanded = expandIpv6(ip);
  if (!expanded) return null;
  return expanded;
}

function expandIpv6(ip) {
  try {
    const [head, tail] = ip.split("::");
    if (tail === undefined) {
      const groups = ip.split(":");
      if (groups.length !== 8) return null;
      return groups.map((g) => parseInt(g, 16));
    }
    const headGroups = head ? head.split(":") : [];
    const tailGroups = tail ? tail.split(":") : [];
    if (headGroups.length + tailGroups.length > 7) return null;
    const missing = 8 - headGroups.length - tailGroups.length;
    const groups = [...headGroups, ...Array(missing).fill("0"), ...tailGroups];
    return groups.map((g) => parseInt(g, 16));
  } catch {
    return null;
  }
}

/**
 * Classify an IP address.
 *
 * @param {unknown} ip
 * @returns {"public"|"private"|"loopback"|"link_local"|"invalid"}
 */
export function classifyIp(ip) {
  const value = normalizeIp(ip);
  if (!value) return "invalid";
  const v4 = ipv4Parts(value);
  if (v4) {
    const [a, b] = v4;
    if (a === 0) return "invalid";
    if (a === 127) return "loopback";
    if (a === 10) return "private";
    if (a === 172 && b >= 16 && b <= 31) return "private";
    if (a === 192 && b === 168) return "private";
    if (a === 169 && b === 254) return "link_local";
    if (a === 100 && b >= 64 && b <= 127) return "private";
    return "public";
  }
  const groups = ipv6Groups(value);
  if (groups) {
    if (value === "::1") return "loopback";
    if (groups[0] >= 0xfc00 && groups[0] <= 0xfdff) return "private";
    if (groups[0] >= 0xfe80 && groups[0] <= 0xfebf) return "link_local";
    return "public";
  }
  return "invalid";
}
