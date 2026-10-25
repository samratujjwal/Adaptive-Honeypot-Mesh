import { config } from "../packages/shared/src/config.js";
import { createLlmService } from "../packages/llm/src/service.js";

async function main() {
  const command = process.argv[2] || "ps aux";
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
  console.log(result.output);
}

main().catch((error) => {
  console.error("llm demo failed");
  process.exit(1);
});
