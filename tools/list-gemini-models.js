import dotenv from "dotenv";

dotenv.config();

const MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models";

async function main() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === "") {
    console.error("No GEMINI_API_KEY found. Copy .env.example to .env, set GEMINI_API_KEY, then run again.");
    process.exit(1);
  }

  let response;
  try {
    response = await fetch(MODELS_URL, {
      headers: { "x-goog-api-key": apiKey },
    });
  } catch (error) {
    console.error(`Failed to list Gemini models: ${error.message}`);
    process.exit(1);
  }

  if (!response.ok) {
    console.error(`Gemini model list request failed with status ${response.status}.`);
    process.exit(1);
  }

  const data = await response.json();
  const models = Array.isArray(data.models) ? data.models : [];
  const names = models
    .filter((model) => Array.isArray(model.supportedGenerationMethods) && model.supportedGenerationMethods.includes("generateContent"))
    .map((model) => model.name)
    .sort();

  if (names.length === 0) {
    console.log("No models supporting generateContent were returned.");
    return;
  }
  for (const name of names) {
    console.log(name);
  }
}

await main();
