import test from "node:test";
import assert from "node:assert/strict";
import { correlateProfiles, decideStrategy, validateAttacker, buildAttackerProfile, mergeAttacker } from "../src/index.js";

function profile(overrides = {}) {
  return {
    sessionId: "sess-1", service: "ssh", nodeId: "node-01", sourceIp: "10.0.0.1",
    firstSeen: "2026-10-28T10:00:00Z", lastSeen: "2026-10-28T10:01:00Z",
    commandNames: ["whoami"], mitreTechniqueIds: ["T1033"], mitreTactics: ["Discovery"],
    classification: { actorType: "unknown", skillLevel: "beginner", intent: "recon", tools: [], confidence: 0.3 },
    ...overrides,
  };
}

test("adaptive: correlation merges SSH + FTP profiles by same IP, serviceCount 2, crossService true", () => {
  const ssh = profile({ sessionId: "s1", service: "ssh" });
  const ftp = profile({ sessionId: "s2", service: "ftp", firstSeen: "2026-10-28T10:05:00Z", lastSeen: "2026-10-28T10:06:00Z", commandNames: ["wget"], mitreTechniqueIds: ["T1105"], mitreTactics: ["Command and Control"], classification: { actorType: "unknown", skillLevel: "intermediate", intent: "exploitation", tools: ["wget"], confidence: 0.7 } });
  const attacker = buildAttackerProfile([ssh, ftp]);
  assert.equal(attacker.serviceCount, 2);
  assert.equal(attacker.strategy.crossService, true);
  assert.deepEqual(attacker.services, ["ftp", "ssh"]);
  assert.equal(attacker.sessionCount, 2);
});

test("adaptive: correlation rejects mixed sourceIps", () => {
  const a = profile({ sourceIp: "10.0.0.1" });
  const b = profile({ sessionId: "s2", sourceIp: "10.0.0.2" });
  assert.throws(() => correlateProfiles([a, b]), /mixed sourceIps/);
});

test("adaptive: skill is highest across profiles", () => {
  const a = profile({ classification: { actorType: "unknown", skillLevel: "beginner", intent: "recon", tools: [], confidence: 0.3 } });
  const b = profile({ sessionId: "s2", classification: { actorType: "unknown", skillLevel: "advanced", intent: "recon", tools: [], confidence: 0.3 } });
  assert.equal(buildAttackerProfile([a, b]).classification.skillLevel, "advanced");
});

test("adaptive: actor is majority, tie is unknown", () => {
  const bot = (id) => profile({ sessionId: id, classification: { actorType: "bot", skillLevel: "unknown", intent: "recon", tools: [], confidence: 0.7 } });
  const human = (id) => profile({ sessionId: id, classification: { actorType: "human", skillLevel: "unknown", intent: "recon", tools: [], confidence: 0.7 } });
  assert.equal(buildAttackerProfile([bot("s1"), bot("s2"), human("s3")]).classification.actorType, "bot");
  assert.equal(buildAttackerProfile([bot("s1"), human("s2")]).classification.actorType, "unknown");
});

test("adaptive: intent is highest priority rules intent, not LLM intent", () => {
  const recon = profile({ classification: { actorType: "unknown", skillLevel: "beginner", intent: "recon", tools: [], confidence: 0.3 } });
  const exploit = profile({ sessionId: "s2", classification: { actorType: "unknown", skillLevel: "intermediate", intent: "credential_access", tools: [], confidence: 0.3 }, rulesIntent: "exploitation" });
  const attacker = buildAttackerProfile([recon, exploit]);
  assert.equal(attacker.classification.intent, "exploitation");
  assert.notEqual(attacker.classification.intent, "credential_access");
});

test("adaptive: llmIntentMismatch true when stored intent differs from rulesIntent", () => {
  const p = profile({ classification: { actorType: "unknown", skillLevel: "beginner", intent: "credential_access", tools: [], confidence: 0.7 }, rulesIntent: "recon" });
  const attacker = buildAttackerProfile([p]);
  assert.equal(attacker.classification.llmIntentMismatch, true);
  assert.equal(attacker.classification.intent, "recon");
});

test("adaptive: strategy contain for persistence", () => {
  const attacker = { classification: { actorType: "unknown", skillLevel: "unknown", intent: "persistence", tools: [], confidence: 0.3 }, serviceCount: 1, services: ["ssh"] };
  assert.equal(decideStrategy(attacker).name, "contain");
});

test("adaptive: strategy contain for exploitation + intermediate", () => {
  const attacker = { classification: { actorType: "unknown", skillLevel: "intermediate", intent: "exploitation", tools: [], confidence: 0.7 }, serviceCount: 1, services: ["ssh"] };
  const strategy = decideStrategy(attacker);
  assert.equal(strategy.name, "contain");
  assert.equal(strategy.reason, "exploitation+intermediate");
});

test("adaptive: strategy deceive for credential_access + intermediate", () => {
  const attacker = { classification: { actorType: "unknown", skillLevel: "intermediate", intent: "credential_access", tools: [], confidence: 0.7 }, serviceCount: 1, services: ["ssh"] };
  assert.equal(decideStrategy(attacker).name, "deceive");
});

test("adaptive: strategy engage for bot + recon", () => {
  const attacker = { classification: { actorType: "bot", skillLevel: "unknown", intent: "recon", tools: [], confidence: 0.7 }, serviceCount: 1, services: ["ssh"] };
  assert.equal(decideStrategy(attacker).name, "engage");
});

test("adaptive: strategy observe for human + recon", () => {
  const attacker = { classification: { actorType: "human", skillLevel: "unknown", intent: "recon", tools: [], confidence: 0.7 }, serviceCount: 1, services: ["ssh"] };
  assert.equal(decideStrategy(attacker).name, "observe");
});

test("adaptive: cross-service escalates observe to engage, and deceive to contain", () => {
  const observe = { classification: { actorType: "human", skillLevel: "unknown", intent: "recon", tools: [], confidence: 0.7 }, serviceCount: 2, services: ["ftp", "ssh"] };
  assert.equal(decideStrategy(observe).name, "engage");
  const deceive = { classification: { actorType: "unknown", skillLevel: "intermediate", intent: "credential_access", tools: [], confidence: 0.7 }, serviceCount: 2, services: ["ftp", "ssh"] };
  assert.equal(decideStrategy(deceive).name, "contain");
});

test("adaptive: attacker schema rejects password field", () => {
  const attacker = buildAttackerProfile([profile()]);
  assert.notEqual(validateAttacker(attacker), null);
  assert.equal(validateAttacker({ ...attacker, password: "hunter2-secret-pass" }), null);
  assert.equal(validateAttacker({ ...attacker, token: "secret-token-value" }), null);
});

test("adaptive: mergeAttacker unions sessions and keeps highest skill and intent", () => {
  const a = buildAttackerProfile([profile()]);
  const b = buildAttackerProfile([profile({ sessionId: "s2", service: "ftp", firstSeen: "2026-10-28T10:05:00Z", lastSeen: "2026-10-28T10:06:00Z", classification: { actorType: "unknown", skillLevel: "intermediate", intent: "exploitation", tools: ["wget"], confidence: 0.7 } })]);
  const merged = mergeAttacker(a, b);
  assert.equal(merged.sessionCount, 2);
  assert.equal(merged.classification.skillLevel, "intermediate");
  assert.equal(merged.classification.intent, "exploitation");
  assert.notEqual(validateAttacker(merged), null);
});
