import test from "node:test";
import assert from "node:assert/strict";
import { tokenize, splitCommands, hasUnsupportedSyntax } from "../src/parser.js";

test("parser: splits on ; && || outside quotes", () => {
  const parts = splitCommands("pwd; ls && echo hi || echo bye");
  assert.equal(parts.length, 4);
  assert.equal(parts[0].command.trim(), "pwd");
  assert.equal(parts[0].operator, null);
  assert.equal(parts[1].command.trim(), "ls");
  assert.equal(parts[1].operator, ";");
  assert.equal(parts[2].command.trim(), "echo hi");
  assert.equal(parts[2].operator, "&&");
  assert.equal(parts[3].command.trim(), "echo bye");
  assert.equal(parts[3].operator, "||");
  const quoted = splitCommands("echo 'a; b' && pwd");
  assert.equal(quoted.length, 2);
  assert.equal(quoted[0].command.trim(), "echo 'a; b'");
});

test("parser: honors single and double quotes", () => {
  assert.deepEqual(tokenize("echo 'hello world'"), ["echo", "hello world"]);
  assert.deepEqual(tokenize('echo "hello world"'), ["echo", "hello world"]);
  assert.deepEqual(tokenize("echo hello\\ world"), ["echo", "hello world"]);
  assert.deepEqual(tokenize("cat /etc/passwd"), ["cat", "/etc/passwd"]);
});

test("parser: flags pipes, redirects and subshells as unsupported", () => {
  assert.equal(hasUnsupportedSyntax("ls | grep x"), true);
  assert.equal(hasUnsupportedSyntax("echo hi > out"), true);
  assert.equal(hasUnsupportedSyntax("echo hi >> out"), true);
  assert.equal(hasUnsupportedSyntax("cat < file"), true);
  assert.equal(hasUnsupportedSyntax("sleep 1 &"), true);
  assert.equal(hasUnsupportedSyntax("echo `whoami`"), true);
  assert.equal(hasUnsupportedSyntax("echo $(whoami)"), true);
  assert.equal(hasUnsupportedSyntax("echo ${HOME}"), true);
  assert.equal(hasUnsupportedSyntax("echo 'a | b'"), false);
  assert.equal(hasUnsupportedSyntax("pwd && ls"), false);
  assert.equal(hasUnsupportedSyntax("pwd; ls"), false);
  assert.equal(hasUnsupportedSyntax("echo $HOME"), false);
});
