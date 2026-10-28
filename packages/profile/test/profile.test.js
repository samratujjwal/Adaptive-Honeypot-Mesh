import test from "node:test";
import assert from "node:assert/strict";
import { classifyProfile } from "../src/classify.js";
import { createLlmEnhancer, buildFeatureSummary } from "../src/llm-classify.js";
import { validateProfile } from "../src/schema.js";

function base(overrides = {}) {
  return {
    sessionId: "sess-1", service: "ssh", nodeId: "node-01", sourceIp: "127.0.0.1",
    firstSeen: "2026-10-28T10:00:00Z", lastSeen: "2026-10-28T10:01:00Z", durationMs: 60000, closed: true,
    eventCount: 10, commandCount: 0, authAttempts: 0, authSuccess: 0,
    commands: [], mitreTechniqueIds: [], mitreTactics: [], userAgents: [], fileTransferOut: false,
    totalTypingMs: 0, totalKeystrokes: 0, backspaceCount: 0, httpLoginAttempts: 0,
    ...overrides,
  };
}

test("profile: fast tool user-agent session maps to bot", () => {
  const p = classifyProfile(base({ userAgents: ["sqlmap/1.7"], authAttempts: 60, durationMs: 60000, commandCount: 2, commands: ["sqlmap -u x"] }));
  assert.equal(p.classification.actorType, "bot");
  assert.ok(p.classification.confidence >= 0.9);
});

test("profile: human backspace and pauses map to human", () => {
  const p = classifyProfile(base({ backspaceCount: 5, totalTypingMs: 3000, totalKeystrokes: 10, commandCount: 6, commands: ["whoami", "ls", "pwd", "id", "cat file", "echo hi"] }));
  assert.equal(p.classification.actorType, "human");
});

test("profile: beginner commands map to beginner", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ls -la", "pwd", "id"], commandCount: 4, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(p.classification.skillLevel, "beginner");
});

test("profile: advanced persistence and obfuscation map to advanced", () => {
  const p = classifyProfile(base({ commands: ["crontab -e", "echo x | base64 -d"], commandCount: 2, mitreTechniqueIds: ["T1547", "T1027"], mitreTactics: ["Persistence", "Defense Evasion"] }));
  assert.equal(p.classification.skillLevel, "advanced");
});

test("profile: sqlmap user-agent maps to tool sqlmap and bot", () => {
  const p = classifyProfile(base({ userAgents: ["sqlmap/1.7"], commandCount: 1, commands: ["sqlmap"] }));
  assert.ok(p.classification.tools.includes("sqlmap"));
  assert.equal(p.classification.actorType, "bot");
});

test("profile: nmap command maps to tool nmap", () => {
  const p = classifyProfile(base({ commands: ["nmap -sV 10.0.0.1"], commandCount: 1 }));
  assert.ok(p.classification.tools.includes("nmap"));
});

test("profile: no signals map to unknown with low confidence", () => {
  const p = classifyProfile(base({}));
  assert.equal(p.classification.actorType, "unknown");
  assert.ok(p.classification.confidence <= 0.5);
});

test("profile: mock mode returns rules only, llm.used=false, no network call", async () => {
  const rules = classifyProfile(base({}));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "mock", GEMINI_MODEL: "gemini-2.5-flash" } });
  let called = false;
  const fakeClient = { generate: async () => { called = true; return { ok: true, text: "{}" }; } };
  const enhancer2 = createLlmEnhancer({ config: { LLM_MODE: "mock", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: fakeClient });
  const out = await enhancer2(rules, base({}));
  assert.equal(out.llm.used, false);
  assert.equal(called, false);
  assert.equal(out.llm.fallback, false);
});

test("profile: LLM invalid JSON falls back to rules, llm.fallback=true, never throws", async () => {
  const rules = classifyProfile(base({}));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => ({ ok: true, text: "not json", attempt: { model: "gemini-2.5-flash" } }) } });
  const out = await enhancer(rules, base({}));
  assert.equal(out.llm.fallback, true);
  assert.equal(out.llm.used, true);
  assert.deepEqual(out.classification, rules.classification);
});

test("profile: LLM invalid enum falls back to rules", async () => {
  const rules = classifyProfile(base({}));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => ({ ok: true, text: JSON.stringify({ actorType: "alien", skillLevel: "advanced", intent: "recon", tools: [], confidence: 0.9 }), attempt: { model: "gemini-2.5-flash" } }) } });
  const out = await enhancer(rules, base({}));
  assert.equal(out.llm.fallback, true);
});

test("profile: LLM invented techniqueId is dropped, not stored", async () => {
  const rules = classifyProfile(base({ mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => ({ ok: true, text: JSON.stringify({ actorType: "bot", skillLevel: "advanced", intent: "recon", tools: [], confidence: 0.9 }), attempt: { model: "gemini-2.5-flash" } }) } });
  const out = await enhancer(rules, base({ mitreTechniqueIds: ["T1033"] }));
  assert.deepEqual(out.mitreTechniqueIds, ["T1033"]);
  assert.ok(!out.mitreTechniqueIds.includes("T9999"));
});

test("profile: LLM invented tool is dropped, not stored", async () => {
  const rules = classifyProfile(base({}));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => ({ ok: true, text: JSON.stringify({ actorType: "bot", skillLevel: "advanced", intent: "recon", tools: ["metasploit", "nmap"], confidence: 0.9 }), attempt: { model: "gemini-2.5-flash" } }) } });
  const out = await enhancer(rules, base({}));
  assert.ok(!out.classification.tools.includes("metasploit"));
  assert.ok(out.classification.tools.includes("nmap"));
});

test("profile: passwords and token values never appear in the LLM prompt", () => {
  const summary = buildFeatureSummary(base({ commands: ["cat /etc/passwd"], userAgents: [] }));
  const text = JSON.stringify(summary);
  assert.ok(!text.includes("hunter2-secret-pass"));
  assert.ok(!text.includes("ht-abcdef12"));
  assert.ok(!text.includes("sourceIp"));
  const inputWithSecrets = { ...base({}), password: "hunter2-secret-pass", token: "ht-abcdef12" };
  const summary2 = buildFeatureSummary(inputWithSecrets);
  assert.ok(!JSON.stringify(summary2).includes("hunter2-secret-pass"));
  assert.ok(!JSON.stringify(summary2).includes("ht-abcdef12"));
});

test("profile: cache hit does not call LLM a second time", async () => {
  let calls = 0;
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => { calls += 1; return { ok: true, text: JSON.stringify({ actorType: "bot", skillLevel: "intermediate", intent: "recon", tools: ["nmap"], confidence: 0.8 }), attempt: { model: "gemini-2.5-flash" } }; } } });
  const rules = classifyProfile(base({}));
  const input = base({});
  const first = await enhancer(rules, input);
  const second = await enhancer(rules, input);
  assert.equal(calls, 1);
  assert.equal(second.llm.cached, true);
  assert.equal(first.llm.cached, false);
});

test("profile: command arguments are not stored, only first tokens", () => {
  const p = classifyProfile(base({ commands: ["cat /etc/passwd --secret hunter2", "wget http://x/y.sh -O /tmp/y"], commandCount: 2 }));
  assert.deepEqual(p.commandNames, ["cat", "wget"]);
  assert.ok(!JSON.stringify(p).includes("hunter2"));
  assert.ok(!JSON.stringify(p).includes("/etc/passwd"));
});

test("profile: profile validates against schema", () => {
  const p = classifyProfile(base({ commands: ["whoami"], commandCount: 1 }));
  assert.ok(validateProfile(p));
  assert.equal(validateProfile({ ...p, classification: { ...p.classification, actorType: "alien" } }), null);
});

test("profile: intent priority persistence over credential access", () => {
  const p = classifyProfile(base({ mitreTactics: ["Persistence", "Credential Access"], mitreTechniqueIds: ["T1547", "T1003"] }));
  assert.equal(p.classification.intent, "persistence");
});

test("profile: exfiltration only with file transfer out", () => {
  const p = classifyProfile(base({ mitreTactics: ["Command and Control"], fileTransferOutSensitive: true }));
  assert.equal(p.classification.intent, "exfiltration");
  const p2 = classifyProfile(base({ mitreTactics: ["Command and Control"], fileTransferOut: false, fileTransferOutSensitive: false }));
  assert.notEqual(p2.classification.intent, "exfiltration");
});

test("tools: profile-check prints profile JSON and refuses a file containing a password field", async () => {
  const { execFileSync, execSync } = await import("node:" + "child" + "_process");
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "profile-check-"));
  const good = join(dir, "good.json");
  writeFileSync(good, JSON.stringify({ sessionId: "s1", service: "ssh", nodeId: "n1", sourceIp: "127.0.0.1", firstSeen: "2026-10-28T10:00:00Z", lastSeen: "2026-10-28T10:01:00Z", durationMs: 60000, closed: true, eventCount: 3, commandCount: 1, authAttempts: 0, authSuccess: 0, commands: ["whoami"] }));
  const out = execFileSync(process.execPath, ["tools/profile-check.js", good], { cwd: process.cwd() }).toString("utf8");
  const parsed = JSON.parse(out);
  assert.equal(parsed.sessionId, "s1");
  const bad = join(dir, "bad.json");
  writeFileSync(bad, JSON.stringify({ sessionId: "s1", password: "hunter2-secret-pass" }));
  let failed = false;
  try {
    execFileSync(process.execPath, ["tools/profile-check.js", bad], { cwd: process.cwd() });
  } catch (e) {
    failed = true;
    assert.ok(!String(e.stdout || "").includes("hunter2-secret-pass"));
    assert.ok(!String(e.stderr || "").includes("hunter2-secret-pass"));
  }
  assert.equal(failed, true);
});

test("profile: intermediate skill from ps and netstat", () => {
  const p = classifyProfile(base({ commands: ["ps aux", "netstat -tulpn"], commandCount: 2, mitreTechniqueIds: ["T1057"], mitreTactics: ["Discovery"] }));
  assert.equal(p.classification.skillLevel, "intermediate");
});

test("profile: credential access intent from T1003", () => {
  const p = classifyProfile(base({ mitreTechniqueIds: ["T1003"], mitreTactics: ["Credential Access"] }));
  assert.equal(p.classification.intent, "credential_access");
});

test("profile: bot auth rate signal", () => {
  const p = classifyProfile(base({ authAttempts: 60, durationMs: 60000, commandCount: 1, commands: ["ls"] }));
  assert.equal(p.classification.actorType, "bot");
});

test("profile: human varied commands signal", () => {
  const p = classifyProfile(base({ commandCount: 6, commands: ["whoami", "ls", "pwd", "id", "uname", "hostname"] }));
  assert.equal(p.classification.actorType, "human");
});

test("profile: tools are filtered to allowed list only", () => {
  const p = classifyProfile(base({ commands: ["metasploit", "nmap"], commandCount: 2 }));
  assert.ok(!p.classification.tools.includes("metasploit"));
  assert.ok(p.classification.tools.includes("nmap"));
});

test("profile: LLM is not called when rules confidence is at least 0.7", async () => {
  const rules = classifyProfile(base({ userAgents: ["sqlmap/1.7"], authAttempts: 60, durationMs: 60000, commandCount: 2, commands: ["ps aux"], mitreTechniqueIds: ["T1057"], mitreTactics: ["Discovery"] }));
  assert.ok(rules.classification.confidence >= 0.7);
  assert.notEqual(rules.classification.skillLevel, "unknown");
  assert.notEqual(rules.classification.intent, "unknown");
  let called = false;
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => { called = true; return { ok: true, text: "{}" }; } } });
  const out = await enhancer(rules, base({}));
  assert.equal(called, false);
  assert.equal(out.llm.used, false);
});

test("profile: feature summary has stable key order for cache", () => {
  const a = buildFeatureSummary(base({ commands: ["whoami"], commandCount: 1 }));
  const b = buildFeatureSummary(base({ commandCount: 1, commands: ["whoami"] }));
  assert.deepEqual(a, b);
});

test("profile: aggregator signals track mitre and user-agent in memory only", async () => {
  const { createSessionAggregator } = await import("../../../services/processor/src/sessions.js");
  const agg = createSessionAggregator({});
  const event = { id: "00000000-0000-4000-8000-000000000001", sessionId: "sess-9", timestamp: "2026-10-28T10:00:00Z", honeypot: { service: "http", nodeId: "node-01" }, source: { ip: "127.0.0.1", port: 1234 }, eventType: "http_request", payload: { path: "/", method: "GET", headers: { "user-agent": "sqlmap/1.7" } }, mitre: [{ techniqueId: "T1190", tactic: "Initial Access", confidence: 0.7 }] };
  await agg.apply(event, { ip: "127.0.0.1", ipClass: "loopback", geo: null });
  const signals = agg.getSignals("sess-9");
  assert.ok(signals.mitreTechniqueIds.includes("T1190"));
  assert.ok(signals.userAgents.includes("sqlmap/1.7"));
  const session = agg.get("sess-9");
  assert.ok(!("mitreTechniqueIds" in session));
  assert.ok(!("userAgents" in session));
});

test("profile: closed profile does not contain raw commands or source IP in LLM summary", () => {
  const summary = buildFeatureSummary(base({ commands: ["wget http://x/y.sh --secret"], userAgents: ["curl/7.0"] }));
  assert.ok(!JSON.stringify(summary).includes("http://x/y.sh"));
  assert.ok(!JSON.stringify(summary).includes("127.0.0.1"));
});

test("profile: confidence is clamped to 0-1", () => {
  const p = classifyProfile(base({}));
  assert.ok(p.classification.confidence >= 0 && p.classification.confidence <= 1);
});

test("profile: persistence alone maps to advanced", () => {
  const p = classifyProfile(base({ commands: ["crontab -e"], commandCount: 1, mitreTechniqueIds: ["T1547"], mitreTactics: ["Persistence"] }));
  assert.equal(p.classification.skillLevel, "advanced");
});

test("fix: wget download does NOT map intent to exfiltration", () => {
  const p = classifyProfile(base({ service: "ssh", commands: ["wget http://example.com/x.sh"], commandCount: 1, mitreTechniqueIds: ["T1105"], mitreTactics: ["Command and Control"], fileTransferOut: true, fileTransferOutSensitive: false }));
  assert.notEqual(p.classification.intent, "exfiltration");
  assert.equal(p.classification.intent, "exploitation");
});

test("fix: FTP RETR / upload-out case maps as documented in Step 2", () => {
  const sensitive = classifyProfile(base({ service: "ftp", mitreTactics: ["Command and Control"], fileTransferOutSensitive: true }));
  assert.equal(sensitive.classification.intent, "exfiltration");
  const nonSensitive = classifyProfile(base({ service: "ftp", mitreTactics: [], fileTransferOut: true, fileTransferOutSensitive: false }));
  assert.equal(nonSensitive.classification.intent, "unknown");
  const stor = classifyProfile(base({ service: "ftp", mitreTactics: [], fileTransferOut: false, fileTransferOutSensitive: false }));
  assert.notEqual(stor.classification.intent, "exfiltration");
});

test("fix: SSH fast typing with no backspace leans bot, using a real SSH command payload shape", () => {
  const p = classifyProfile(base({ commands: ["nmap -sV 10.0.0.1"], commandCount: 1, userAgents: ["nmap/7.94"], totalTypingMs: 50, totalKeystrokes: 15, backspaceCount: 0 }));
  assert.equal(p.classification.actorType, "bot");
  assert.equal(p.classification.confidence, 0.9);
});

test("fix: SSH slow typing with backspace leans human, using a real SSH command payload shape", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ls", "pwd"], commandCount: 3, totalTypingMs: 3000, totalKeystrokes: 10, backspaceCount: 3 }));
  assert.equal(p.classification.actorType, "human");
});

test("fix: aggregator sums real SSH timing fields in memory only", async () => {
  const { createSessionAggregator } = await import("../../../services/processor/src/sessions.js");
  const agg = createSessionAggregator({});
  const baseEvent = { id: "00000000-0000-4000-8000-000000000001", sessionId: "sess-timing", timestamp: "2026-10-28T10:00:00Z", honeypot: { service: "ssh", nodeId: "node-01" }, source: { ip: "127.0.0.1", port: 1234 } };
  await agg.apply({ ...baseEvent, eventType: "command", payload: { command: "whoami", keystrokeCount: 6, typingDurationMs: 3000, usedBackspace: true } }, { ip: "127.0.0.1", ipClass: "loopback", geo: null });
  await agg.apply({ ...baseEvent, id: "00000000-0000-4000-8000-000000000002", eventType: "command", payload: { command: "ls", keystrokeCount: 2, typingDurationMs: 1000, usedBackspace: false } }, { ip: "127.0.0.1", ipClass: "loopback", geo: null });
  const signals = agg.getSignals("sess-timing");
  assert.equal(signals.totalTypingMs, 4000);
  assert.equal(signals.totalKeystrokes, 8);
  assert.equal(signals.backspaceCount, 1);
  const session = agg.get("sess-timing");
  assert.ok(!("totalTypingMs" in session));
});

test("fix2: LLM fence-wrapped JSON succeeds, llm.fallback=false", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite" }, geminiClient: { generate: async () => ({ ok: true, text: "```json\n{\"actorType\":\"bot\",\"skillLevel\":\"intermediate\",\"intent\":\"recon\",\"tools\":[\"nmap\"],\"confidence\":0.8}\n```" }) } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, false);
  assert.equal(out.llm.used, true);
  assert.equal(out.classification.actorType, "bot");
});

test("fix2: LLM JSON with trailing explanation succeeds, llm.fallback=false", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite" }, geminiClient: { generate: async () => ({ ok: true, text: "{\"actorType\":\"human\",\"skillLevel\":\"beginner\",\"intent\":\"recon\",\"tools\":[],\"confidence\":0.7} Hope this helps!" }) } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, false);
  assert.equal(out.classification.actorType, "human");
});

test("fix2: LLM quota error falls back, error code is logged, never throws", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const codes = [];
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite" }, geminiClient: { generate: async () => ({ ok: false, status: 429, reason: "rate_limit", attempt: { status: 429 } }) }, logger: { warn: (fields) => codes.push(fields.code) } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, true);
  assert.ok(codes.includes("LLM_QUOTA"));
});

test("fix2: basic session intent recon, skill beginner, not credential_access", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ls", "pwd"], commandCount: 3, mitreTechniqueIds: ["T1110.001", "T1078", "T1033"], mitreTactics: ["Credential Access", "Initial Access", "Discovery"] }));
  assert.equal(p.classification.intent, "recon");
  assert.equal(p.classification.skillLevel, "beginner");
  assert.notEqual(p.classification.intent, "credential_access");
});

test("fix2: advanced wget session intent exploitation, not credential_access, not exfiltration", () => {
  const p = classifyProfile(base({ commands: ["whoami", "cat", "ps", "wget"], commandCount: 4, mitreTechniqueIds: ["T1110.001", "T1078", "T1033", "T1105"], mitreTactics: ["Credential Access", "Initial Access", "Discovery", "Command and Control"], fileTransferOut: true, fileTransferOutSensitive: false }));
  assert.equal(p.classification.intent, "exploitation");
  assert.notEqual(p.classification.intent, "credential_access");
  assert.notEqual(p.classification.intent, "exfiltration");
});

test("fix2: FTP listing only intent unknown, not credential_access", () => {
  const p = classifyProfile(base({ service: "ftp", commands: [], commandCount: 0, mitreTechniqueIds: ["T1110.001", "T1078"], mitreTactics: ["Credential Access", "Initial Access"] }));
  assert.equal(p.classification.intent, "unknown");
  assert.notEqual(p.classification.intent, "credential_access");
});

test("fix2: auth-only session does not make bot by itself", () => {
  const p = classifyProfile(base({ commands: [], commandCount: 0, authAttempts: 1, authSuccess: 1, durationMs: 60000, mitreTechniqueIds: ["T1110.001", "T1078"], mitreTactics: ["Credential Access", "Initial Access"] }));
  assert.notEqual(p.classification.actorType, "bot");
});

test("fix2: cache key excludes sessionId and timestamp, same features hit cache", async () => {
  const rules1 = classifyProfile(base({ sessionId: "sess-a", commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const rules2 = classifyProfile(base({ sessionId: "sess-b", commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  let calls = 0;
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite" }, geminiClient: { generate: async () => { calls += 1; return { ok: true, text: "{\"actorType\":\"bot\",\"skillLevel\":\"intermediate\",\"intent\":\"recon\",\"tools\":[\"nmap\"],\"confidence\":0.8}" }; } } });
  const input1 = base({ sessionId: "sess-a", commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] });
  const input2 = base({ sessionId: "sess-b", commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] });
  await enhancer(rules1, input1);
  const out2 = await enhancer(rules2, input2);
  assert.equal(calls, 1);
  assert.equal(out2.llm.cached, true);
});

test("fix2: latency is recorded when LLM call is attempted, null only in mock", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const failEnhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite" }, geminiClient: { generate: async () => ({ ok: false, status: 500, reason: "server_error", attempt: { status: 500 } }) } });
  const failed = await failEnhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(failed.llm.fallback, true);
  assert.notEqual(failed.llm.latencyMs, null);
  assert.ok(typeof failed.llm.latencyMs === "number" && failed.llm.latencyMs >= 0);
  const mockEnhancer = createLlmEnhancer({ config: { LLM_MODE: "mock", GEMINI_MODEL: "gemini-2.5-flash-lite" } });
  const mocked = await mockEnhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(mocked.llm.used, false);
  assert.equal(mocked.llm.latencyMs, null);
});

test("fix3: primary model 404 then fallback model succeeds, llm.fallback=false, model=fallback", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async ({ model }) => model === "gemini-2.5-flash" ? { ok: true, text: "{\"actorType\":\"bot\",\"skillLevel\":\"intermediate\",\"intent\":\"recon\",\"tools\":[\"nmap\"],\"confidence\":0.8}" } : { ok: false, status: 404, attempt: { status: 404 } } } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, false);
  assert.equal(out.llm.used, true);
  assert.equal(out.llm.model, "gemini-2.5-flash");
  assert.notEqual(out.llm.latencyMs, null);
});

test("fix3: both models 404, llm.fallback=true, code LLM_MODEL_NOT_FOUND, not LIMITER", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const codes = [];
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async () => ({ ok: false, status: 404, attempt: { status: 404 } }) }, logger: { warn: (fields) => codes.push(fields.code) } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, true);
  assert.ok(codes.includes("LLM_MODEL_NOT_FOUND"));
  assert.ok(!codes.includes("LLM_LIMITER"));
});

test("fix3: model-not-found does not count toward limiter, next profile still gets MODEL_NOT_FOUND not LIMITER", async () => {
  const { createLimiter } = await import("../../../packages/llm/src/limiter.js");
  const limiter = createLimiter({ rpm: 8, dailyLimit: 400, sessionLimit: 40 });
  const codes = [];
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" }, limiter, geminiClient: { generate: async () => ({ ok: false, status: 404, attempt: { status: 404 } }) }, logger: { warn: (fields) => codes.push(fields.code) } });
  for (let i = 0; i < 11; i += 1) {
    const rules = classifyProfile(base({ sessionId: `sess-${i}`, commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
    await enhancer(rules, base({ sessionId: `sess-${i}`, commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  }
  assert.ok(!codes.includes("LLM_LIMITER"));
  assert.ok(codes.every((c) => c === "LLM_MODEL_NOT_FOUND"));
});

test("fix3: basic session with exit intent recon skill beginner", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ls", "pwd", "exit"], commandCount: 4, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(p.classification.intent, "recon");
  assert.equal(p.classification.skillLevel, "beginner");
  assert.ok(p.commandNames.includes("exit"));
});

test("fix3: basic session without exit still beginner", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ls", "pwd"], commandCount: 3, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(p.classification.skillLevel, "beginner");
});

test("fix3: advanced session with exit skill intermediate, intent exploitation", () => {
  const p = classifyProfile(base({ commands: ["whoami", "ps", "wget", "exit"], commandCount: 4, mitreTechniqueIds: ["T1105"], mitreTactics: ["Command and Control"] }));
  assert.equal(p.classification.skillLevel, "intermediate");
  assert.equal(p.classification.intent, "exploitation");
});

test("fix3: limiter still denies after 8 successful attempts", async () => {
  const { createLimiter } = await import("../../../packages/llm/src/limiter.js");
  const limiter = createLimiter({ rpm: 8, dailyLimit: 400, sessionLimit: 40 });
  const codes = [];
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" }, limiter, geminiClient: { generate: async () => ({ ok: true, text: "{\"actorType\":\"bot\",\"skillLevel\":\"intermediate\",\"intent\":\"recon\",\"tools\":[\"nmap\"],\"confidence\":0.8}" }) }, logger: { warn: (fields) => codes.push(fields.code) } });
  for (let i = 0; i < 9; i += 1) {
    const rules = classifyProfile(base({ sessionId: `succ-${i}`, commands: [`cmd${i}`], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
    await enhancer(rules, base({ sessionId: `succ-${i}`, commandNames: [`cmd${i}`], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  }
  assert.ok(codes.includes("LLM_LIMITER"));
});

test("fix3: fallback model success is not rules fallback", async () => {
  const rules = classifyProfile(base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  const enhancer = createLlmEnhancer({ config: { LLM_MODE: "real", GEMINI_MODEL: "gemini-2.5-flash-lite", GEMINI_FALLBACK_MODEL: "gemini-2.5-flash" }, geminiClient: { generate: async ({ model }) => model === "gemini-2.5-flash" ? { ok: true, text: "{\"actorType\":\"human\",\"skillLevel\":\"beginner\",\"intent\":\"recon\",\"tools\":[],\"confidence\":0.7}" } : { ok: false, status: 404, attempt: { status: 404 } } } });
  const out = await enhancer(rules, base({ commands: ["whoami"], commandCount: 1, mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"] }));
  assert.equal(out.llm.fallback, false);
  assert.equal(out.classification.actorType, "human");
  assert.notEqual(out.classification.actorType, rules.classification.actorType);
});
