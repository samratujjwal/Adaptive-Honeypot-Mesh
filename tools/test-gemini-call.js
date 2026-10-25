import { config } from "../packages/shared/src/config.js";

async function main() {
  const apiKey = config.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === "") {
    console.error("No GEMINI_API_KEY found. Copy .env.example to .env, set GEMINI_API_KEY, then run again.");
    process.exit(1);
  }

  const model = config.GEMINI_MODEL;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const start = Date.now();
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: "Reply with the single word: OK" }] }],
      }),
    });
  } catch (error) {
    console.error(`Gemini test call failed: ${error.message}`);
    process.exit(1);
  }
  const latencyMs = Date.now() - start;

  if (!response.ok) {
    if (response.status === 429) {
      console.error(`Gemini test call failed with HTTP 429 (quota/rate limit). Free-tier quota may be exhausted; try again later.`);
    } else {
      console.error(`Gemini test call failed with HTTP ${response.status}.`);
    }
    process.exit(1);
  }

  const data = await response.json();
  const reply = (data.candidates?.[0]?.content?.parts ?? [])
    .map((part) => part.text ?? "")
    .join("");
  console.log(`Model: ${model}`);
  console.log(`HTTP status: ${response.status}`);
  console.log(`Latency: ${latencyMs} ms`);
  console.log(`Reply: ${reply}`);
}

await main();
