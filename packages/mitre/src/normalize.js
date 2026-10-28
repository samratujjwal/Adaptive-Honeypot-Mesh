/**
 * Normalize a command or request text for rule matching.
 *
 * @param {unknown} text
 * @returns {string}
 */
export function normalize(text) {
  if (typeof text !== "string") return "";
  let out = text.toLowerCase().trim().replace(/\s+/g, " ");
  while (out.startsWith("sudo ")) out = out.slice(5).trimStart();
  return out;
}
