const MTIME = "2024-03-05T10:21:00.000Z";

function dirNode(owner, group, mode) {
  return { type: "dir", mode, owner, group, mtime: MTIME, children: {} };
}

function fileNode(content, owner, group, mode) {
  return { type: "file", mode, owner, group, mtime: MTIME, content };
}

/**
 * Build the fictional Ubuntu 22.04 seed tree for one hostname. The
 * content is invented for the honeypot persona and is not copied
 * from any real host.
 *
 * @param {string} hostname
 * @returns {object} seed tree root node
 */
export function buildSeed(hostname) {
  const host = hostname || "srv-web-01";
  const root = dirNode("root", "root", "0755");
  const passwd = [
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
    "admin:x:1001:1001::/home/admin:/bin/bash",
    "guest:x:1002:1002::/home/guest:/bin/bash",
    "oracle:x:1003:1003::/home/oracle:/bin/bash",
    "pi:x:1004:1004::/home/pi:/bin/bash",
    "postgres:x:1005:1005::/home/postgres:/bin/bash",
    "test:x:1006:1006::/home/test:/bin/bash",
    "user:x:1007:1007::/home/user:/bin/bash",
  ].join("\n") + "\n";
  const shadow = [
    "root:*:19000:0:99999:7:::",
    "daemon:*:19000:0:99999:7:::",
    "bin:*:19000:0:99999:7:::",
    "sys:*:19000:0:99999:7:::",
    "www-data:!:19000:0:99999:7:::",
    "sshd:!:19000:0:99999:7:::",
    "ubuntu:!:19000:0:99999:7:::",
    "admin:!:19000:0:99999:7:::",
    "guest:!:19000:0:99999:7:::",
    "oracle:!:19000:0:99999:7:::",
    "pi:!:19000:0:99999:7:::",
    "postgres:!:19000:0:99999:7:::",
    "test:!:19000:0:99999:7:::",
    "user:!:19000:0:99999:7:::",
  ].join("\n") + "\n";
  const bashrcRoot = [
    "# fictional .bashrc for the honeypot persona",
    "export PS1='\\u@\\h:\\w\\$ '",
    "alias ll='ls -alF'",
    "alias la='ls -A'",
  ].join("\n") + "\n";
  const profileRoot = [
    "# fictional .profile for the honeypot persona",
    "if [ -n \"$BASH_VERSION\" ]; then",
    "  if [ -f \"$HOME/.bashrc\" ]; then",
    "    . \"$HOME/.bashrc\"",
    "  fi",
    "fi",
  ].join("\n") + "\n";
  const bashrcUbuntu = [
    "# fictional .bashrc for the honeypot persona",
    "export PS1='\\u@\\h:\\w\\$ '",
    "alias ll='ls -alF'",
  ].join("\n") + "\n";
  const authLog = [
    `Mar  5 10:21:01 ${host} sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2`,
    `Mar  5 10:22:14 ${host} sshd[1235]: Failed password for root from 10.0.0.9 port 51234 ssh2`,
    `Mar  5 10:23:02 ${host} sshd[1236]: Disconnected from authenticating user root 10.0.0.9 port 51234`,
  ].join("\n") + "\n";
  const indexHtml = [
    "<!DOCTYPE html>",
    "<html>",
    "<head><title>Welcome</title></head>",
    "<body>",
    `<h1>Welcome to ${host}</h1>`,
    "<p>It works!</p>",
    "</body>",
    "</html>",
  ].join("\n") + "\n";
  const osRelease = [
    'NAME="Ubuntu"',
    'VERSION="22.04.3 LTS (Jammy Jellyfish)"',
    'ID=ubuntu',
    'ID_LIKE=debian',
    'PRETTY_NAME="Ubuntu 22.04.3 LTS"',
    'VERSION_ID="22.04"',
    'HOME_URL="https://www.ubuntu.com/"',
    'SUPPORT_URL="https://help.ubuntu.com/"',
    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"',
    'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms/ubuntu-privacy-policy"',
    'VERSION_CODENAME=jammy',
    'UBUNTU_CODENAME=jammy',
  ].join("\n") + "\n";

  function addDir(parent, name, owner, group, mode) {
    const node = dirNode(owner, group, mode);
    parent.children[name] = node;
    return node;
  }

  function addFile(parent, name, content, owner, group, mode) {
    parent.children[name] = fileNode(content, owner, group, mode);
  }

  const bin = addDir(root, "bin", "root", "root", "0755");
  addDir(root, "boot", "root", "root", "0755");
  addDir(root, "dev", "root", "root", "0755");
  const etc = addDir(root, "etc", "root", "root", "0755");
  const home = addDir(root, "home", "root", "root", "0755");
  addDir(root, "lib", "root", "root", "0755");
  addDir(root, "opt", "root", "root", "0755");
  addDir(root, "proc", "root", "root", "0555");
  const rootHome = addDir(root, "root", "root", "root", "0700");
  addDir(root, "srv", "root", "root", "0755");
  addDir(root, "tmp", "root", "root", "0755");
  addDir(root, "usr", "root", "root", "0755");
  const varDir = addDir(root, "var", "root", "root", "0755");
  const varLog = addDir(varDir, "log", "root", "root", "0755");
  const varWww = addDir(varDir, "www", "root", "root", "0755");
  const varWwwHtml = addDir(varWww, "html", "www-data", "www-data", "0755");
  const ubuntuHome = addDir(home, "ubuntu", "ubuntu", "ubuntu", "0755");

  addFile(etc, "passwd", passwd, "root", "root", "0644");
  addFile(etc, "shadow", shadow, "root", "shadow", "0640");
  addFile(etc, "hostname", host + "\n", "root", "root", "0644");
  addFile(etc, "hosts", `127.0.0.1 localhost\n127.0.1.1 ${host}\n::1 localhost ip6-localhost ip6-loopback\n`, "root", "root", "0644");
  addFile(etc, "os-release", osRelease, "root", "root", "0644");
  addFile(etc, "issue", "Ubuntu 22.04.3 LTS \\n \\l\n\n", "root", "root", "0644");
  addFile(etc, "resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n", "root", "root", "0644");
  addFile(rootHome, ".bashrc", bashrcRoot, "root", "root", "0644");
  addFile(rootHome, ".profile", profileRoot, "root", "root", "0644");
  addFile(ubuntuHome, ".bashrc", bashrcUbuntu, "ubuntu", "ubuntu", "0644");
  addFile(varLog, "auth.log", authLog, "root", "root", "0644");
  addFile(varWwwHtml, "index.html", indexHtml, "www-data", "www-data", "0644");
  void bin;
  return root;
}

/**
 * Deterministic, stable UID for a login username. root is 0,
 * ubuntu is 1000, every other login username is assigned from
 * 1001 upward in alphabetical order.
 *
 * @param {string} username
 * @returns {number} uid
 */
export function uidForUser(username) {
  if (username === "root") return 0;
  if (username === "ubuntu") return 1000;
  const others = ["admin", "guest", "oracle", "pi", "postgres", "test", "user"];
  const index = others.indexOf(username);
  if (index >= 0) return 1001 + index;
  let hash = 0;
  for (const ch of username) hash = (hash * 31 + ch.charCodeAt(0)) % 10000;
  return 2000 + (hash % 5000);
}
