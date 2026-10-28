import { classify } from "../packages/mitre/src/classify.js";

const input = process.argv[2] || "";
const service = process.argv[3] || "ssh";
const event = { service, eventType: "command", payload: { command: input } };
const mitre = classify(event).map((item) => ({ techniqueId: item.techniqueId, tactic: item.tactic, confidence: item.confidence }));
console.log(JSON.stringify({ input, mitre }));
