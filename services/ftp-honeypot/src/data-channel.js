/**
 * Normalize an IP address: strip the IPv4-mapped IPv6 prefix.
 *
 * @param {string} ip
 * @returns {string} normalized IP
 */
export function normalizeIp(ip) {
  if (!ip) return "";
  return String(ip).replace(/^::ffff:/, "");
}

/**
 * Check whether a data-connection peer is allowed: it must be the
 * same IP as the control connection.
 *
 * @param {string} controlIp
 * @param {string} peerIp
 * @returns {boolean} true if the peer is allowed
 */
export function isAllowedDataPeer(controlIp, peerIp) {
  return normalizeIp(controlIp) === normalizeIp(peerIp);
}
