import { config } from "../packages/shared/src/config.js";
import { createLlmService } from "../packages/llm/src/service.js";

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--debug");
  const debug = process.argv.includes("--debug");
  const command = args[0] || "ps aux";
  const service = createLlmService({ config });
  const result = await service.respond({
    command,
    ctx: { user: "root", cwd: "/root", hostname: config.HONEYPOT_HOSTNAME, sessionId: "demo", sourceIp: "127.0.0.1" },
  });
  console.log(`source: ${result.meta.source}`);
  console.log(`model: ${result.meta.model}`);
  console.log(`cached: ${result.meta.cached}`);
  console.log(`reason: ${result.meta.reason || "none"}`);
  console.log(`latencyMs: ${result.meta.latencyMs}`);
  console.log(`exitCode: ${result.exitCode}`);
  if (debug && Array.isArray(result.meta.attempts)) {
    for (const attempt of result.meta.attempts) {
      const preview = config.GEMINI_API_KEY ? String(attempt.rawPreview || "").split(config.GEMINI_API_KEY).join("[REDACTED]") : attempt.rawPreview || "";
      console.log(`attempt: ${attempt.model} status=${attempt.status === null ? "-" : attempt.status} finishReason=${attempt.finishReason || "-"} promptTokens=${attempt.promptTokens === null ? "-" : attempt.promptTokens} outputTokens=${attempt.outputTokens === null ? "-" : attempt.outputTokens} latencyMs=${attempt.latencyMs} errorKind=${attempt.errorKind || "ok"} rawPreview=${preview}`);
    }
  }
  console.log(result.output);
}

main().catch((error) => {
  console.error("llm demo failed");
  process.exit(1);
});
