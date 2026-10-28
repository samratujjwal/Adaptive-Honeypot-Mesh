import { readFileSync } from "node:fs";
import { classifyProfile } from "../packages/profile/src/classify.js";
import { createLlmEnhancer } from "../packages/profile/src/llm-classify.js";
import { loadConfig } from "../packages/shared/src/config.js";

const path = process.argv[2];
if (!path) {
  console.error("Usage: node tools/profile-check.js <path-to-session-summary.json>");
  process.exit(1);
}
const text = readFileSync(path, "utf8");
let input;
try {
  input = JSON.parse(text);
} catch {
  console.error("Invalid JSON in the session summary file.");
  process.exit(1);
}
const forbidden = ["password", "token", "credential"];
const lower = text.toLowerCase();
for (const field of forbidden) {
  if (lower.includes(`"${field}"`)) {
    console.error(`Refusing file: it contains a ${field} field. Remove secrets before checking.`);
    process.exit(1);
  }
}
const profile = classifyProfile(input);
let enhanced = profile;
try {
  const config = loadConfig({});
  const enhancer = createLlmEnhancer({ config });
  enhanced = await enhancer(profile, input);
} catch {
  enhanced = profile;
}
console.log(JSON.stringify(enhanced, null, 2));
