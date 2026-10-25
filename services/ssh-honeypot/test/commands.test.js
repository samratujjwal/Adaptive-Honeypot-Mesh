import test from "node:test";
import assert from "node:assert/strict";
import { createVfs } from "../src/vfs.js";
import { buildSeed, uidForUser } from "../src/seed/ubuntu-2204.js";
import { createCommandEngine } from "../src/commands.js";

function makeEngine(username = "ubuntu", hostname = "srv-web-01") {
  const vfs = createVfs(buildSeed(hostname));
  vfs.ensureUserHome(username);
  return createCommandEngine({ vfs, user: { name: username, uid: uidForUser(username) }, hostname });
}

test("cmd: pwd starts in the user home", async () => {
  const engine = makeEngine("ubuntu");
  assert.equal((await engine.run("pwd")).output, "/home/ubuntu\n");
  assert.equal(engine.cwd(), "/home/ubuntu");
  const rootEngine = makeEngine("root");
  assert.equal((await rootEngine.run("pwd")).output, "/root\n");
});

test("cmd: cd changes directory and pwd reflects it", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("cd /var/log"));
  assert.equal(result.exitCode, 0);
  assert.equal(engine.cwd(), "/var/log");
  assert.equal((await engine.run("pwd")).output, "/var/log\n");
});

test("cmd: cd to missing dir prints the bash error", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("cd /nope"));
  assert.equal(result.output, "bash: cd: /nope: No such file or directory\n");
  assert.equal(result.exitCode, 1);
  assert.equal(engine.cwd(), "/home/ubuntu");
});

test("cmd: cd to a file prints Not a directory", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("cd /etc/passwd"));
  assert.equal(result.output, "bash: cd: /etc/passwd: Not a directory\n");
  assert.equal(result.exitCode, 1);
});

test("cmd: cd with no args goes home; cd - goes back", async () => {
  const engine = makeEngine("ubuntu");
  (await engine.run("cd /var/log"));
  assert.equal((await engine.run("cd")).output, "");
  assert.equal(engine.cwd(), "/home/ubuntu");
  (await engine.run("cd /var/log"));
  const back = (await engine.run("cd -"));
  assert.equal(back.output, "/home/ubuntu\n");
  assert.equal(engine.cwd(), "/home/ubuntu");
});

test("cmd: ls lists directory contents sorted, hides dotfiles", async () => {
  const engine = makeEngine("root");
  const result = (await engine.run("ls /etc", { tty: false }));
  assert.equal(result.exitCode, 0);
  assert.ok(result.output.includes("passwd"));
  assert.ok(!result.output.includes(".bashrc"));
  const names = result.output.trim().split("\n");
  const sorted = [...names].sort();
  assert.deepEqual(names, sorted);
});

test("cmd: ls -a shows dotfiles", async () => {
  const engine = makeEngine("root");
  const result = (await engine.run("ls -a /root", { tty: false }));
  assert.ok(result.output.includes(".bashrc"));
  assert.ok(result.output.includes(".profile"));
});

test("cmd: ls -l shows permissions, owner, size", async () => {
  const engine = makeEngine("root");
  const result = (await engine.run("ls -l /etc/hostname", { tty: false }));
  assert.match(result.output, /-rw-r--r--/);
  assert.ok(result.output.includes("root"));
  assert.ok(result.output.includes("hostname"));
  const dirResult = (await engine.run("ls -l /etc", { tty: false }));
  assert.ok(dirResult.output.startsWith("total "));
  assert.match(dirResult.output, /Mar\s+5 10:21/);
});

test("cmd: ls missing path prints the ls error", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("ls /nope", { tty: false }));
  assert.equal(result.output, "ls: cannot access '/nope': No such file or directory\n");
  assert.equal(result.exitCode, 2);
});

test("cmd: cat prints a seeded file", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("cat /etc/hostname", { tty: false }));
  assert.equal(result.output, "srv-web-01\n");
  const passwd = (await engine.run("cat /etc/passwd", { tty: false }));
  assert.ok(passwd.output.includes("root:x:0:0:root:/root:/bin/bash"));
  assert.ok(passwd.output.includes("ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"));
});

test("cmd: cat missing file and directory print errors", async () => {
  const engine = makeEngine("ubuntu");
  const missing = (await engine.run("cat /nope", { tty: false }));
  assert.equal(missing.output, "cat: /nope: No such file or directory\n");
  assert.equal(missing.exitCode, 1);
  const dir = (await engine.run("cat /etc", { tty: false }));
  assert.equal(dir.output, "cat: /etc: Is a directory\n");
  assert.equal(dir.exitCode, 1);
});

test("cmd: non-root cannot read /etc/shadow", async () => {
  const engine = makeEngine("ubuntu");
  const result = (await engine.run("cat /etc/shadow", { tty: false }));
  assert.equal(result.output, "cat: /etc/shadow: Permission denied\n");
  assert.equal(result.exitCode, 1);
  const rootEngine = makeEngine("root");
  assert.ok((await rootEngine.run("cat /etc/shadow", { tty: false })).output.includes("root:*:"));
  const lsRoot = (await engine.run("ls /root", { tty: false }));
  assert.equal(lsRoot.output, "ls: cannot open directory '/root': Permission denied\n");
  assert.equal(lsRoot.exitCode, 2);
});

test("cmd: whoami and id match the login user", async () => {
  const engine = makeEngine("ubuntu");
  assert.equal((await engine.run("whoami")).output, "ubuntu\n");
  assert.equal((await engine.run("id")).output, "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)\n");
  assert.equal((await engine.run("id -u")).output, "1000\n");
  assert.equal((await engine.run("id -g")).output, "1000\n");
  assert.equal((await engine.run("id -un")).output, "ubuntu\n");
  const rootEngine = makeEngine("root");
  assert.equal((await rootEngine.run("id")).output, "uid=0(root) gid=0(root) groups=0(root)\n");
});

test("cmd: uname -a is consistent with hostname", async () => {
  const engine = makeEngine("ubuntu", "srv-web-01");
  const result = (await engine.run("uname -a", { tty: false }));
  assert.equal(result.output, "Linux srv-web-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n");
  assert.equal((await engine.run("uname -n")).output, "srv-web-01\n");
  assert.equal((await engine.run("uname -r")).output, "5.15.0-91-generic\n");
  assert.equal((await engine.run("hostname")).output, "srv-web-01\n");
});

test("cmd: echo prints args and expands ~ and $HOME", async () => {
  const engine = makeEngine("ubuntu");
  assert.equal((await engine.run("echo hello world")).output, "hello world\n");
  assert.equal((await engine.run("echo ~")).output, "/home/ubuntu\n");
  assert.equal((await engine.run("echo $HOME")).output, "/home/ubuntu\n");
  assert.equal((await engine.run("echo -n hi")).output, "hi");
  assert.equal((await engine.run("echo -e 'a\\nb'")).output, "a\nb\n");
});

test("cmd: chained commands respect ; && ||", async () => {
  const engine = makeEngine("ubuntu");
  assert.equal((await engine.run("pwd; echo hi")).output, "/home/ubuntu\nhi\n");
  const second = makeEngine("ubuntu");
  assert.equal((await second.run("cd /nope && echo hi")).output, "bash: cd: /nope: No such file or directory\n");
  assert.equal((await second.run("cd /nope || echo fallback")).output, "bash: cd: /nope: No such file or directory\nfallback\n");
  const third = makeEngine("ubuntu");
  assert.equal((await third.run("pwd && cd /var/log && pwd")).output, "/home/ubuntu\n/var/log\n");
  const fourth = makeEngine("ubuntu");
  assert.equal((await fourth.run("echo ok || echo fallback")).output, "ok\n");
});

test("cmd: unknown command uses the fallback hook", async () => {
  const vfs = createVfs(buildSeed("srv-web-01"));
  vfs.ensureUserHome("ubuntu");
  const seen = [];
  const engine = createCommandEngine({
    vfs,
    user: { name: "ubuntu", uid: 1000 },
    hostname: "srv-web-01",
    fallback: (ctx, line) => {
      seen.push(line);
      return { output: "custom-fallback\n", exitCode: 99 };
    },
  });
  const result = (await engine.run("nmap -sV 127.0.0.1"));
  assert.equal(result.output, "custom-fallback\n");
  assert.equal(result.exitCode, 99);
  assert.equal(result.handled, false);
  assert.equal(seen.length, 1);
  assert.ok(seen[0].includes("nmap"));
});

test("cmd: host filesystem is never exposed", async () => {
  const engine = makeEngine("ubuntu");
  const win = (await engine.run("cat C:\\Windows\\win.ini", { tty: false }));
  assert.ok(win.output.includes("No such file or directory"));
  assert.ok(!win.output.includes("Samrat-Ujjwal"));
  const climb = (await engine.run("cat ../../../../Windows/win.ini", { tty: false }));
  assert.ok(climb.output.includes("No such file or directory"));
  const mnt = (await engine.run("cat /mnt/d", { tty: false }));
  assert.ok(mnt.output.includes("No such file or directory"));
  const passwd = (await engine.run("cat /etc/../../../etc/passwd", { tty: false }));
  assert.ok(passwd.output.includes("root:x:0:0:root:/root:/bin/bash"));
  assert.ok(!passwd.output.includes("Samrat-Ujjwal"));
  const host = (await engine.run("cat /etc/hostname", { tty: false }));
  assert.equal(host.output, "srv-web-01\n");
});

test("cmd: ls -l total and -1 and -h formats", async () => {
  const engine = makeEngine("root");
  const one = (await engine.run("ls -1 /etc", { tty: true }));
  assert.ok(one.output.includes("passwd\n"));
  const human = (await engine.run("ls -lh /etc/hostname", { tty: false }));
  assert.ok(human.output.includes("srv-web-01") || human.output.includes("hostname"));
  const invalid = (await engine.run("ls -z", { tty: false }));
  assert.equal(invalid.output, "ls: invalid option -- 'z'\nTry 'ls --help' for more information.\n");
  assert.equal(invalid.exitCode, 2);
});
