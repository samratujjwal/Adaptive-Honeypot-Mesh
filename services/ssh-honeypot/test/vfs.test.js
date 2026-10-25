import test from "node:test";
import assert from "node:assert/strict";
import { createVfs } from "../src/vfs.js";
import { buildSeed } from "../src/seed/ubuntu-2204.js";

function makeVfs() {
  return createVfs(buildSeed("srv-web-01"));
}

test("vfs: resolves absolute and relative paths with . and ..", () => {
  const vfs = makeVfs();
  assert.equal(vfs.resolve("/var/log", "auth.log", "/home/ubuntu"), "/var/log/auth.log");
  assert.equal(vfs.resolve("/var/log", "../www/html", "/home/ubuntu"), "/var/www/html");
  assert.equal(vfs.resolve("/var/log", "./auth.log", "/home/ubuntu"), "/var/log/auth.log");
  assert.equal(vfs.resolve("/etc", "/etc/passwd", "/home/ubuntu"), "/etc/passwd");
  assert.equal(vfs.resolve("/home/ubuntu", "~/x", "/home/ubuntu"), "/home/ubuntu/x");
  assert.equal(vfs.resolve("/home/ubuntu", "~", "/home/ubuntu"), "/home/ubuntu");
  assert.equal(vfs.resolve("/var", "log//auth.log", "/home/ubuntu"), "/var/log/auth.log");
});

test("vfs: .. above root stays at root", () => {
  const vfs = makeVfs();
  assert.equal(vfs.resolve("/", "../../etc", "/root"), "/etc");
  assert.equal(vfs.resolve("/etc", "../../../passwd", "/root"), "/passwd");
  assert.equal(vfs.resolve("/", "..", "/root"), "/");
});

test("vfs: missing path returns not-found", () => {
  const vfs = makeVfs();
  assert.equal(vfs.get("/nope"), null);
  assert.equal(vfs.get("/etc/nope"), null);
  assert.equal(vfs.get("/etc/passwd/extra"), null);
  assert.equal(vfs.list("/etc/passwd"), null);
  assert.equal(vfs.readFile("/nope"), null);
});

test("vfs: sessions get independent copies", () => {
  const seed = buildSeed("srv-web-01");
  const first = createVfs(seed);
  const second = createVfs(seed);
  first.root.children["newdir"] = { type: "dir", mode: "0755", owner: "root", group: "root", mtime: "2024-03-05T10:21:00.000Z", children: {} };
  assert.equal(second.get("/newdir"), null);
  assert.equal(first.get("/newdir").type, "dir");
  const firstEtc = first.get("/etc");
  firstEtc.children["passwd"].content = "changed\n";
  assert.notEqual(second.readFile("/etc/passwd"), "changed\n");
});
