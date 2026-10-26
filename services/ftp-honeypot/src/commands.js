import { createHash } from "node:crypto";
import { resolveFtpPath } from "./session.js";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function modeToPerms(mode, isDir) {
  const digits = String(mode || "0644").slice(-3);
  let out = isDir ? "d" : "-";
  for (const digit of digits) {
    const value = Number.parseInt(digit, 10);
    out += (value & 4) !== 0 ? "r" : "-";
    out += (value & 2) !== 0 ? "w" : "-";
    out += (value & 1) !== 0 ? "x" : "-";
  }
  return out;
}

function formatDate(mtime) {
  const date = new Date(mtime || "2026-03-05T10:21:00.000Z");
  const month = MONTHS[date.getUTCMonth()] || "Mar";
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hour = String(date.getUTCHours()).padStart(2, "0");
  const minute = String(date.getUTCMinutes()).padStart(2, "0");
  return `${month} ${day} ${hour}:${minute}`;
}

function formatMdtm(mtime) {
  const date = new Date(mtime || "2026-03-05T10:21:00.000Z");
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hour = String(date.getUTCHours()).padStart(2, "0");
  const minute = String(date.getUTCMinutes()).padStart(2, "0");
  const second = String(date.getUTCSeconds()).padStart(2, "0");
  return `${year}${month}${day}${hour}${minute}${second}`;
}

function fileSize(node) {
  if (!node || node.type !== "file") return 4096;
  if (typeof node.size === "number") return node.size;
  if (Buffer.isBuffer(node.content)) return node.content.length;
  return Buffer.byteLength(String(node.content || ""), "utf8");
}

function fileBytes(node) {
  if (!node || node.type !== "file") return Buffer.alloc(0);
  if (Buffer.isBuffer(node.content)) return node.content;
  return Buffer.from(String(node.content || ""), "utf8");
}

function formatListLine(name, node) {
  const isDir = node.type === "dir";
  const perms = modeToPerms(node.mode, isDir);
  const links = isDir ? 2 : 1;
  const owner = (node.owner || "ftp").slice(0, 8);
  const group = (node.group || "ftp").slice(0, 8);
  const size = isDir ? 4096 : fileSize(node);
  const date = formatDate(node.mtime);
  const permsField = perms.padEnd(10, " ");
  const linksField = String(links).padStart(4, " ");
  const ownerField = owner.padEnd(8, " ");
  const groupField = group.padEnd(8, " ");
  const sizeField = String(size).padStart(8, " ");
  return `${permsField} ${linksField} ${ownerField} ${groupField} ${sizeField} ${date} ${name}`;
}

function parseListArg(arg) {
  if (!arg) return null;
  const tokens = String(arg).split(/\s+/).filter((token) => token !== "");
  const paths = tokens.filter((token) => !token.startsWith("-"));
  return paths.length > 0 ? paths[paths.length - 1] : null;
}

function previewTextFromBytes(bytes) {
  let out = "";
  for (const byte of bytes) {
    if (byte >= 0x20 && byte <= 0x7e) out += String.fromCharCode(byte);
    else if (byte === 0x0a || byte === 0x0d || byte === 0x09) out += " ";
    if (out.length >= 256) break;
  }
  return out.slice(0, 256);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Parse a raw FTP command line into verb and arg.
 *
 * @param {string} line
 * @returns {{ verb: string, arg: string }}
 */
export function parseFtpCommand(line) {
  const trimmed = String(line || "").trim();
  const space = trimmed.indexOf(" ");
  if (space < 0) return { verb: trimmed.toUpperCase(), arg: "" };
  return { verb: trimmed.slice(0, space).toUpperCase(), arg: trimmed.slice(space + 1).trim() };
}

/**
 * Format a LIST listing for a directory node.
 *
 * @param {object} dirNode
 * @returns {string} listing text with CRLF lines
 */
export function formatList(dirNode) {
  const lines = [];
  for (const [name, child] of Object.entries(dirNode.children || {})) {
    lines.push(formatListLine(name, child));
  }
  return lines.length > 0 ? lines.join("\r\n") + "\r\n" : "";
}

/**
 * Format an NLST listing for a directory node.
 *
 * @param {object} dirNode
 * @returns {string} names with CRLF lines
 */
export function formatNlst(dirNode) {
  const names = Object.keys(dirNode.children || {});
  return names.length > 0 ? names.join("\r\n") + "\r\n" : "";
}

export { fileSize, fileBytes, formatListLine, formatDate, formatMdtm, parseListArg, previewTextFromBytes, sha256Hex, resolveFtpPath };
