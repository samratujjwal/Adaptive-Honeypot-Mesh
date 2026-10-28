import { fileURLToPath } from "node:url";

const IDS = ["live-feed", "stats-cards", "timeline", "top-commands", "attack-heatmap", "world-map"];

async function dashboardCheck(base) {
  const response = await fetch(`${base}/dashboard`);
  const html = await response.text();
  console.log(JSON.stringify({ status: response.status, sections: IDS.map((id) => ({ id, present: html.includes(`id="${id}"`) })) }));
  const missing = IDS.filter((id) => !html.includes(`id="${id}"`));
  if (response.status !== 200 || missing.length > 0) {
    console.error("MISSING_SECTIONS:" + missing.join(","));
    process.exit(1);
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const base = process.argv[2] || "http://127.0.0.1:3001";
  dashboardCheck(base).then(() => process.exit(0)).catch(() => {
    console.error("DASHBOARD_CHECK_FAILED");
    process.exit(1);
  });
}
