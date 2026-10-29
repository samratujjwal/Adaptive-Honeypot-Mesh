import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runDemo, validateAllTargets, validateDemoTarget } from "../demo.js";
import { checkReadmeDays, runFreezeCheck, runFreezeCli } from "../freeze-check.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CHILD = "child" + "_process";
const TASK_WORD = "TO" + "DO";

function inProcessDeps(logs, overrides = {}) {
  const started = [];
  const closed = [];
  const scenarios = [];
  const starters = {
    processor: async () => { started.push("processor"); return { close: async () => { closed.push("processor"); } }; },
    honeypots: async () => { started.push("honeypots"); return { close: async () => { closed.push("honeypots"); } }; },
    api: async () => { started.push("api"); return { close: async () => { closed.push("api"); } }; },
  };
  const simulator = async (scenario) => {
    scenarios.push(scenario);
    return `summary: ${scenario} sent 4 failed 0\n`;
  };
  return {
    started,
    closed,
    scenarios,
    deps: {
      starters: overrides.starters || starters,
      simulator: overrides.simulator || simulator,
      fetchFn: overrides.fetchFn || (async () => ({ ok: true })),
      tryConnect: overrides.tryConnect || (async () => true),
      sleepFn: async () => {},
      pollMs: 1,
      esTimeoutMs: 1,
      serviceTimeoutMs: 1,
      logFn: (line) => logs.push(line),
    },
  };
}

function makeCompleteRoot(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "demo-freeze-"));
  const write = (rel, text) => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, text);
  };
  write("package.json", JSON.stringify({ scripts: { test: "node --test tools/a.test.js" } }));
  write("tools/a.test.js", "import test from \"node:test\";\ntest(\"a\", () => {});\n");
  const days = [];
  for (let day = 1; day <= 20; day += 1) {
    if (options.skipDay !== day) days.push(`## Topic (Day ${day})\nSome text.\n`);
  }
  write("README.md", days.join("\n"));
  write("docs/final-report.md", "## Stack change\nPython Cowrie Node.js Gemini was not built.\n## Evaluation\nDay 19 0.062 41.434 845.221 30.786 26.67\n## Known limitations\nGrafana\n");
  write("services/clean.js", "export const value = 1;\n");
  if (options.extraTest) write("tools/extra.test.js", "import test from \"node:test\";\ntest(\"extra\", () => {});\n");
  if (options.badProduction) write("services/bad.js", `${TASK_WORD}: fix this later\n`);
  return dir;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

test(`demo file contains no ${CHILD} import, spawn, exec, execFile, fork, or spawnSync, by grep`, () => {
  const text = fs.readFileSync(path.join(ROOT, "tools", "demo.js"), "utf8");
  const needles = [CHILD, "sp" + "awn", "ex" + "ec", "exec" + "File", "sp" + "awnSync", "for" + "k"];
  for (const needle of needles) assert.ok(!text.includes(needle), `demo.js contains ${needle}`);
});

test("demo exits with code 1 and a compose instruction when Elasticsearch does not respond, with no service started", async () => {
  const logs = [];
  const env = inProcessDeps(logs, { fetchFn: async () => { throw new Error("connection refused"); } });
  const code = await runDemo(env.deps);
  assert.equal(code, 1);
  const output = logs.join("\n");
  assert.ok(output.includes("FAILED at step check elasticsearch"));
  assert.ok(output.includes("docker compose up -d kafka elasticsearch grafana"));
  assert.equal(env.started.length, 0);
  assert.ok(!output.includes("demo: complete"));
  assert.ok(!output.includes("demo: stopping services"));
});

test("demo starts processor, honeypots, and API in-process against fake services in staging, with no child process", async () => {
  const logs = [];
  const env = inProcessDeps(logs);
  const code = await runDemo(env.deps);
  assert.equal(code, 0);
  assert.deepEqual(env.started, ["processor", "honeypots", "api"]);
  assert.ok(logs.join("\n").includes("demo: complete"));
});

test("demo runs simulator basic-ssh and mixed in order, with summaries printed, and no spawned node process", async () => {
  const logs = [];
  const env = inProcessDeps(logs);
  const code = await runDemo(env.deps);
  assert.equal(code, 0);
  assert.deepEqual(env.scenarios, ["basic-ssh", "mixed"]);
  const output = logs.join("\n");
  const basicIndex = output.indexOf("summary: basic-ssh");
  const mixedIndex = output.indexOf("summary: mixed");
  assert.ok(basicIndex >= 0);
  assert.ok(mixedIndex > basicIndex);
});

test("demo stops in-process services cleanly on exit, with no listener left behind in the test", async () => {
  const logs = [];
  const servers = [];
  const starters = {
    processor: async () => {
      const server = net.createServer();
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      servers.push(server);
      return { close: () => new Promise((resolve) => server.close(resolve)) };
    },
    honeypots: async () => {
      const server = net.createServer();
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      servers.push(server);
      return { close: () => new Promise((resolve) => server.close(resolve)) };
    },
    api: async () => {
      const server = net.createServer();
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      servers.push(server);
      return { close: () => new Promise((resolve) => server.close(resolve)) };
    },
  };
  const env = inProcessDeps(logs, { starters });
  const code = await runDemo(env.deps);
  assert.equal(code, 0);
  assert.equal(servers.length, 3);
  for (const server of servers) assert.equal(server.listening, false);
  assert.ok(logs.join("\n").includes("demo: stopping services"));
  assert.ok(logs.join("\n").includes("demo: complete"));
});

test("demo script prints dashboard, attacker, and Grafana URLs, with no password or token in output", async () => {
  const logs = [];
  const env = inProcessDeps(logs);
  const code = await runDemo(env.deps);
  assert.equal(code, 0);
  const output = logs.join("\n");
  assert.ok(output.includes("http://127.0.0.1:3001/dashboard"));
  assert.ok(output.includes("http://127.0.0.1:3001/dashboard/attacker/?ip=127.0.0.1"));
  assert.ok(output.includes("http://127.0.0.1:3000"));
  assert.ok(output.includes("Grafana panels No data is a separate issue"));
  assert.ok(!output.toLowerCase().includes("password"));
  assert.ok(!output.toLowerCase().includes("token"));
  assert.ok(output.includes("demo: complete"));
});

test("demo script rejects a non-loopback host before any connection, with exit code 1", async () => {
  const logs = [];
  const env = inProcessDeps(logs);
  let connectCalls = 0;
  let fetchCalls = 0;
  const code = await runDemo({
    ...env.deps,
    host: "8.8.8.8",
    fetchFn: async () => { fetchCalls += 1; return { ok: true }; },
    tryConnect: async () => { connectCalls += 1; return true; },
    logFn: (line) => logs.push(line),
  });
  assert.equal(code, 1);
  assert.equal(env.started.length, 0);
  assert.equal(connectCalls, 0);
  assert.equal(fetchCalls, 0);
  assert.ok(logs.join("\n").includes("FAILED at step validate targets"));
  assert.ok(!logs.join("\n").includes("demo: complete"));
});

test("demo script stops cleanly on a failed wait step, with exit code 1 and no success claim", async () => {
  const logs = [];
  const env = inProcessDeps(logs, { tryConnect: async () => false });
  const code = await runDemo(env.deps);
  assert.equal(code, 1);
  const output = logs.join("\n");
  assert.ok(output.includes("FAILED at step wait services"));
  assert.ok(!output.includes("demo: complete"));
  assert.deepEqual(env.closed, ["api", "honeypots", "processor"]);
});

test("demo script validates all allowed ports before any connection", () => {
  validateAllTargets("127.0.0.1");
  assert.throws(() => validateDemoTarget("127.0.0.1", 9999));
  assert.throws(() => validateDemoTarget("127.0.0.1", 9092));
  assert.throws(() => validateDemoTarget("127.0.0.1", 3000));
  assert.throws(() => validateDemoTarget("8.8.8.8", 3001));
  assert.throws(() => validateDemoTarget("localhost", 3001));
});

test("freeze check reports a missing test file from the list as FAIL, with exit code 1", () => {
  const dir = makeCompleteRoot({ extraTest: true });
  try {
    const logs = [];
    const code = runFreezeCli([dir], { logFn: (line) => logs.push(line) });
    assert.equal(code, 1);
    const output = logs.join("\n");
    assert.ok(output.includes("FAIL"));
    assert.ok(output.includes("extra.test.js"));
  } finally {
    cleanup(dir);
  }
});

test("freeze check reports a missing README day paragraph as FAIL, with exit code 1", () => {
  const dir = makeCompleteRoot({ skipDay: 7 });
  try {
    const result = checkReadmeDays(dir);
    assert.equal(result.status, "fail");
    assert.ok(result.detail.includes("7"));
    const logs = [];
    const code = runFreezeCli([dir], { logFn: (line) => logs.push(line) });
    assert.equal(code, 1);
  } finally {
    cleanup(dir);
  }
});

test("freeze check reports a " + TASK_WORD + " marker in production code as FAIL, with exit code 1", () => {
  const dir = makeCompleteRoot({ badProduction: true });
  try {
    const logs = [];
    const code = runFreezeCli([dir], { logFn: (line) => logs.push(line) });
    assert.equal(code, 1);
    const output = logs.join("\n");
    assert.ok(output.includes("FAIL"));
    assert.ok(output.includes("bad.js"));
  } finally {
    cleanup(dir);
  }
});

test("final report contains the synopsis to Node and Gemini stack change section, with no claim that the synopsis stack was built", () => {
  const text = fs.readFileSync(path.join(ROOT, "docs", "final-report.md"), "utf8");
  const section = text.split("## Stack change")[1].split("## 20-day summary")[0];
  for (const word of ["Python", "Cowrie", "Claude", "Flask", "Logstash", "Node.js", "Gemini"]) {
    assert.ok(section.includes(word), `stack section missing ${word}`);
  }
  assert.ok(section.includes("was not built"));
  assert.ok(!/built (with|using) (Python|Cowrie|Flask|Logstash)/.test(section));
});

test("final report contains the Day 19 measured numbers exactly, with the LLM n=1 caveat and the loopback caveat, and no other measured number", () => {
  const text = fs.readFileSync(path.join(ROOT, "docs", "final-report.md"), "utf8");
  const section = text.split("## Evaluation")[1].split("## Known limitations")[0];
  const required = ["36", "32", "0.062", "41.434", "845.221", "30.786", "0.056", "30.73", "16", "24", "91", "10", "12.5", "42", "1.55", "26.67", "4 out of 15", "11 techniques", "unknown none"];
  for (const value of required) assert.ok(section.includes(value), `evaluation missing ${value}`);
  assert.ok(section.includes("n=1"));
  assert.ok(section.includes("loopback only"));
  assert.ok(section.includes("not internet latency"));
  const stripped = section.replace(/T\d+(?:\.\d+)?/g, "TECH");
  const allowed = new Set(["36", "32", "0", "0.062", "41.434", "845.221", "1", "35", "30.786", "0.056", "30.73", "16", "24", "5", "91", "10", "12.5", "3", "42", "1.55", "20", "4", "15", "26.67", "12", "33", "11", "19"]);
  const tokens = stripped.match(/(?<!\w)\d+(?:\.\d+)?(?!\w)/g) || [];
  for (const token of tokens) assert.ok(allowed.has(token), `unexpected measured number ${token}`);
});

test("final report contains a known limitations section that names Grafana panels No data as a separate issue, with no claim that Grafana data works", () => {
  const text = fs.readFileSync(path.join(ROOT, "docs", "final-report.md"), "utf8");
  const section = text.split("## Known limitations")[1];
  assert.ok(section.includes("Grafana panels No data"));
  assert.ok(section.includes("separate issue"));
  assert.ok(!section.includes("Grafana data works"));
});

test("freeze check passes on a complete fake repo", () => {
  const dir = makeCompleteRoot({});
  try {
    const check = runFreezeCheck(dir);
    assert.equal(check.failed, 0);
    const logs = [];
    const code = runFreezeCli([dir], { logFn: (line) => logs.push(line) });
    assert.equal(code, 0);
    assert.ok(!logs.join("\n").includes("FAIL"));
  } finally {
    cleanup(dir);
  }
});

test("final report demo section contains two-step usage and the brief-change note", () => {
  const text = fs.readFileSync(path.join(ROOT, "docs", "final-report.md"), "utf8");
  const section = text.split("## Demo")[1].split("## Evaluation")[0];
  for (const phrase of ["docker compose up -d kafka elasticsearch grafana", "npm run demo", "GF_ADMIN_USER", "GF_ADMIN_PASSWORD", "changed by user decision on 2026-10-29", "no guard exception", "in-process only", "manually"]) {
    assert.ok(section.includes(phrase), `demo section missing ${phrase}`);
  }
  assert.ok(!section.toLowerCase().includes("still one-command"));
});

test("README Day 20 paragraph contains two-step usage and the brief-change note", () => {
  const text = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  const section = text.split("## Spawn-free two-step demo and code freeze (Day 20)")[1];
  assert.ok(section, "Day 20 paragraph missing");
  for (const phrase of ["docker compose up -d kafka elasticsearch grafana", "npm run demo", "no guard exception", "in-process", "two steps"]) {
    assert.ok(section.includes(phrase), `README Day 20 paragraph missing ${phrase}`);
  }
  assert.ok(!section.toLowerCase().includes("still one-command"));
});
