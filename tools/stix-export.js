import { fileURLToPath } from "node:url";

async function stixExport(ip, base) {
  const response = await fetch(`${base}/api/attackers/${encodeURIComponent(ip)}/stix`);
  const text = await response.text();
  if (!response.ok) {
    console.error("STIX_EXPORT_FAILED:" + response.status);
    process.exit(1);
  }
  console.log(text);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const ip = process.argv[2];
  const base = process.argv[3] || "http://127.0.0.1:3001";
  if (!ip) {
    console.error("Usage: node tools/stix-export.js 127.0.0.1");
    process.exit(1);
  }
  stixExport(ip, base).catch(() => {
    console.error("STIX_EXPORT_FAILED");
    process.exit(1);
  });
}
