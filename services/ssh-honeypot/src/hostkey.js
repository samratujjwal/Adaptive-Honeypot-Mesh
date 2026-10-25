import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

function uint32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

function lengthPrefixed(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([uint32(data.length), data]);
}

function buildPublicBlob(publicBytes) {
  return Buffer.concat([lengthPrefixed("ssh-ed25519"), lengthPrefixed(publicBytes)]);
}

/**
 * Build an OpenSSH-format ed25519 private key from a node:crypto key
 * pair. ssh2 accepts OpenSSH keys but rejects PKCS8 PEM for ed25519,
 * so the OpenSSH container is built here instead of using ssh-keygen.
 *
 * @returns {{ privateKey: string, publicBlob: Buffer, fingerprint: string }}
 */
export function generateEd25519HostKey() {
  const pair = generateKeyPairSync("ed25519");
  const jwk = pair.privateKey.export({ format: "jwk" });
  const publicBytes = Buffer.from(jwk.x, "base64url");
  const seed = Buffer.from(jwk.d, "base64url");
  const privateBytes = Buffer.concat([seed, publicBytes]);
  const publicBlob = buildPublicBlob(publicBytes);
  const check = randomBytes(4).readUInt32BE(0);
  let privateSection = Buffer.concat([
    uint32(check),
    uint32(check),
    lengthPrefixed("ssh-ed25519"),
    lengthPrefixed(publicBytes),
    lengthPrefixed(privateBytes),
    lengthPrefixed(""),
  ]);
  const paddingLength = (8 - (privateSection.length % 8)) % 8;
  for (let i = 1; i <= paddingLength; i += 1) {
    privateSection = Buffer.concat([privateSection, Buffer.from([i])]);
  }
  const fileBytes = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    lengthPrefixed("none"),
    lengthPrefixed("none"),
    lengthPrefixed(""),
    uint32(1),
    lengthPrefixed(publicBlob),
    lengthPrefixed(privateSection),
  ]);
  const base64 = fileBytes.toString("base64").match(/.{1,70}/g).join("\n");
  const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----\n`;
  const fingerprint = `SHA256:${createHash("sha256").update(publicBlob).digest("base64").replace(/=+$/, "")}`;
  return { privateKey, publicBlob, fingerprint };
}

/**
 * Load an existing host key from disk, or generate and persist a new
 * one on first start. The same key is reused on every restart.
 *
 * @param {string} keyPath
 * @returns {{ privateKey: string, fingerprint: string }}
 */
export function loadOrCreateHostKey(keyPath) {
  if (existsSync(keyPath)) {
    const privateKey = readFileSync(keyPath, "utf8");
    return { privateKey, fingerprint: hostKeyFingerprint(privateKey) };
  }
  const generated = generateEd25519HostKey();
  mkdirSync(dirname(keyPath), { recursive: true });
  writeFileSync(keyPath, generated.privateKey, { mode: 0o600 });
  return { privateKey: generated.privateKey, fingerprint: generated.fingerprint };
}

/**
 * Compute the fingerprint of a stored OpenSSH host key by parsing its
 * public blob out of the key file.
 *
 * @param {string} privateKeyText
 * @returns {string}
 */
export function hostKeyFingerprint(privateKeyText) {
  const base64 = privateKeyText
    .split("\n")
    .filter((line) => line && !line.startsWith("-----"))
    .join("");
  const fileBytes = Buffer.from(base64, "base64");
  let offset = 15;
  const readString = () => {
    const length = fileBytes.readUInt32BE(offset);
    offset += 4;
    const data = fileBytes.subarray(offset, offset + length);
    offset += length;
    return data;
  };
  readString();
  readString();
  readString();
  offset += 4;
  const publicBlob = readString();
  return `SHA256:${createHash("sha256").update(publicBlob).digest("base64").replace(/=+$/, "")}`;
}
