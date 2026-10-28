import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { createEsClient } from "../packages/search/src/es-client.js";
import { getAttacker } from "../packages/search/src/index.js";
import { buildAttackerProfile } from "../packages/adaptive/src/index.js";

const FORBIDDEN = ["\"password\"", "\"token\"", "\"credential\""];

function refuse(message) {
  console.error(message);
  process.exit(1);
}

/**
 * Build an attacker profile from a source IP or a JSON file of
 * profiles. Prints the attacker JSON only, never input secrets.
 *
 * @param {string[]} args
 * @returns {Promise<void>}
 */
export async function adaptiveCheck(args) {
  const target = args[0];
  if (!target) refuse("Usage: node tools/adaptive-check.js 127.0.0.1  OR  node tools/adaptive-check.js profiles.json");
  if (target.endsWith(".json")) {
    let text;
    try {
      text = readFileSync(target, "utf8");
    } catch {
      refuse(`Cannot read file: ${target}`);
    }
    for (const key of FORBIDDEN) {
      if (text.includes(key)) refuse("Refusing file containing a password, token, or credential field.");
    }
    let profiles;
    try {
      profiles = JSON.parse(text);
    } catch {
      refuse("File is not valid JSON.");
    }
    if (!Array.isArray(profiles)) refuse("File must contain a JSON array of profiles.");
    const attacker = buildAttackerProfile(profiles);
    console.log(JSON.stringify(attacker, null, 2));
    return;
  }
  const es = createEsClient({ config, logger });
  const existing = await getAttacker(es, config.ES_INDEX_PREFIX, target);
  if (!existing) {
    console.log(JSON.stringify({ attackerId: target, sourceIp: target, message: "No attacker document found for this IP. Pass a JSON file of profiles instead." }, null, 2));
    return;
  }
  console.log(JSON.stringify(existing, null, 2));
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  adaptiveCheck(process.argv.slice(2)).catch(() => {
    console.error("Adaptive check failed.");
    process.exit(1);
  });
}
