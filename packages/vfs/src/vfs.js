function deepCopyNode(node) {
  if (node.type === "file") {
    const copied = { type: "file", mode: node.mode, owner: node.owner, group: node.group, mtime: node.mtime, content: Buffer.isBuffer(node.content) ? Buffer.from(node.content) : node.content };
    if (node.size !== undefined) copied.size = node.size;
    return copied;
  }
  const children = {};
  for (const [name, child] of Object.entries(node.children || {})) {
    children[name] = deepCopyNode(child);
  }
  return { type: "dir", mode: node.mode, owner: node.owner, group: node.group, mtime: node.mtime, children };
}

/**
 * Resolve a path against a cwd and a home directory. Supports
 * ".", "..", "//", "~" and "~/x". ".." above "/" stays at "/".
 *
 * @param {string} cwd
 * @param {string} path
 * @param {string} home
 * @returns {string} absolute normalized path
 */
export function resolvePath(cwd, path, home) {
  let input = path;
  if (input === "~") return home;
  if (input.startsWith("~/")) input = home + input.slice(1);
  const base = input.startsWith("/") ? "" : cwd;
  const parts = (base + "/" + input).split("/");
  const stack = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      stack.pop();
      continue;
    }
    stack.push(part);
  }
  return "/" + stack.join("/");
}

/**
 * Create a virtual filesystem from a seed tree. The returned
 * object owns a deep copy, so sessions never share state.
 *
 * @param {object} seed
 * @returns {object} vfs object with resolve/get/list/readFile/canRead
 */
export function createVfs(seed, options = {}) {
  const root = deepCopyNode(seed);
  const uidForUser = typeof options.uidForUser === "function" ? options.uidForUser : (username) => (username === "root" ? 0 : 1000);

  function get(absPath) {
    if (absPath === "/") return root;
    const parts = absPath.split("/").filter((part) => part !== "");
    let node = root;
    for (const part of parts) {
      if (!node || node.type !== "dir") return null;
      node = node.children[part];
      if (!node) return null;
    }
    return node;
  }

  function list(absPath) {
    const node = get(absPath);
    if (!node || node.type !== "dir") return null;
    return Object.entries(node.children).map(([name, child]) => ({ name, node: child }));
  }

  function readFile(absPath) {
    const node = get(absPath);
    if (!node || node.type !== "file") return null;
    return node.content;
  }

  function canRead(user, node) {
    if (!node) return false;
    if (user && user.uid === 0) return true;
    const mode = String(node.mode || "0644");
    const ownerBit = Number.parseInt(mode[mode.length - 3], 10);
    const groupBit = Number.parseInt(mode[mode.length - 2], 10);
    const otherBit = Number.parseInt(mode[mode.length - 1], 10);
    let bits;
    if (user && node.owner === user.name) bits = ownerBit;
    else if (user && node.group === user.name) bits = groupBit;
    else bits = otherBit;
    return (bits & 4) !== 0;
  }

  function canWrite(user, node) {
    if (!node) return false;
    if (user && user.uid === 0) return true;
    const mode = String(node.mode || "0644");
    const ownerBit = Number.parseInt(mode[mode.length - 3], 10);
    const groupBit = Number.parseInt(mode[mode.length - 2], 10);
    const otherBit = Number.parseInt(mode[mode.length - 1], 10);
    let bits;
    if (user && node.owner === user.name) bits = ownerBit;
    else if (user && node.group === user.name) bits = groupBit;
    else bits = otherBit;
    return (bits & 2) !== 0;
  }

  function countNodes() {
    let count = 0;
    function walk(node) {
      count += 1;
      if (node.type === "dir") {
        for (const child of Object.values(node.children || {})) walk(child);
      }
    }
    walk(root);
    return count;
  }

  function parentAndName(absPath) {
    const parts = absPath.split("/").filter((part) => part !== "");
    const name = parts.pop() || "";
    const parentPath = "/" + parts.join("/");
    return { parent: get(parentPath), name, parentPath };
  }

  function mkdirNode(absPath, node) {
    const { parent, name } = parentAndName(absPath);
    if (!parent || parent.type !== "dir" || !name || parent.children[name]) return false;
    parent.children[name] = node;
    return true;
  }

  function removeNode(absPath) {
    const { parent, name } = parentAndName(absPath);
    if (!parent || parent.type !== "dir" || !name || !parent.children[name]) return null;
    const removed = parent.children[name];
    delete parent.children[name];
    return removed;
  }

  function setNode(absPath, node) {
    const { parent, name } = parentAndName(absPath);
    if (!parent || parent.type !== "dir" || !name) return false;
    parent.children[name] = node;
    return true;
  }

  function ensureUserHome(username) {
    const home = username === "root" ? "/root" : `/home/${username}`;
    const homeNode = get(home);
    if (!homeNode) {
      const parent = get("/home");
      if (parent && parent.type === "dir") {
        parent.children[username] = {
          type: "dir",
          mode: "0755",
          owner: username,
          group: username,
          mtime: "2024-03-05T10:21:00.000Z",
          children: {},
        };
      }
    }
    const passwdNode = get("/etc/passwd");
    if (passwdNode && passwdNode.type === "file") {
      const lines = passwdNode.content.split("\n");
      const present = lines.some((line) => line.startsWith(username + ":"));
      if (!present) {
        const uid = uidForUser(username);
        const shell = "/bin/bash";
        const entry = `${username}:x:${uid}:${uid}::${home}:${shell}`;
        passwdNode.content = passwdNode.content.endsWith("\n") ? passwdNode.content + entry + "\n" : passwdNode.content + "\n" + entry + "\n";
      }
    }
    return home;
  }

  function byteSize(node) {
    if (!node || node.type !== "file") return 4096;
    if (typeof node.size === "number") return node.size;
    if (Buffer.isBuffer(node.content)) return node.content.length;
    return Buffer.byteLength(String(node.content || ""), "utf8");
  }

  function stat(absPath) {
    const node = get(absPath);
    if (!node) return null;
    return { type: node.type, mode: node.mode, owner: node.owner, group: node.group, mtime: node.mtime, size: byteSize(node) };
  }

  function mkdir(absPath, node) {
    const dirNode = node || { type: "dir", mode: "0755", owner: "ftp", group: "ftp", mtime: new Date().toISOString(), children: {} };
    return mkdirNode(absPath, dirNode);
  }

  function writeFile(absPath, content, meta) {
    const { parent, name } = parentAndName(absPath);
    if (!parent || parent.type !== "dir" || !name) return false;
    const existing = parent.children[name];
    if (existing && existing.type === "dir") return false;
    const info = meta || {};
    parent.children[name] = {
      type: "file",
      mode: info.mode || (existing ? existing.mode : "0644"),
      owner: info.owner || (existing ? existing.owner : "ftp"),
      group: info.group || (existing ? existing.group : "ftp"),
      mtime: info.mtime || new Date().toISOString(),
      content,
    };
    return true;
  }

  function removeFile(absPath) {
    const node = get(absPath);
    if (!node || node.type !== "file") return null;
    return removeNode(absPath);
  }

  function removeDir(absPath) {
    const node = get(absPath);
    if (!node || node.type !== "dir") return null;
    if (Object.keys(node.children || {}).length > 0) return null;
    return removeNode(absPath);
  }

  function rename(oldPath, newPath) {
    const node = get(oldPath);
    if (!node) return false;
    const { parent, name } = parentAndName(newPath);
    if (!parent || parent.type !== "dir" || !name) return false;
    const removed = removeNode(oldPath);
    if (!removed) return false;
    parent.children[name] = removed;
    return true;
  }

  return {
    root,
    resolve: resolvePath,
    get,
    list,
    readFile,
    canRead,
    canWrite,
    countNodes,
    mkdirNode,
    removeNode,
    setNode,
    ensureUserHome,
    stat,
    mkdir,
    writeFile,
    removeFile,
    removeDir,
    rename,
  };
}
