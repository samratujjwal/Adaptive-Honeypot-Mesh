const STRATEGY_ORDER = ["observe", "engage", "deceive", "contain"];

/**
 * Decide one response strategy for a correlated attacker profile.
 * Rules only, no LLM, no network. The strategy is a name only and
 * never changes a live honeypot response in Day 13.
 *
 * @param {object} attacker
 * @returns {{ name: string, reason: string, crossService: boolean }}
 */
export function decideStrategy(attacker) {
  const safe = attacker && typeof attacker === "object" ? attacker : {};
  const classification = safe.classification && typeof safe.classification === "object" ? safe.classification : {};
  const intent = classification.intent || "unknown";
  const skillLevel = classification.skillLevel || "unknown";
  const actorType = classification.actorType || "unknown";
  const crossService = safe.crossService === true || (typeof safe.serviceCount === "number" && safe.serviceCount >= 2) || (Array.isArray(safe.services) && safe.services.length >= 2);
  let name = "observe";
  let reason = "default";
  if (intent === "persistence" || intent === "exfiltration") {
    name = "contain";
    reason = intent;
  } else if (intent === "exploitation" && (skillLevel === "intermediate" || skillLevel === "advanced")) {
    name = "contain";
    reason = `exploitation+${skillLevel}`;
  } else if (intent === "credential_access" && (skillLevel === "intermediate" || skillLevel === "advanced")) {
    name = "deceive";
    reason = `credential_access+${skillLevel}`;
  } else if (actorType === "bot" && intent === "recon") {
    name = "engage";
    reason = "bot+recon";
  } else if (actorType === "human" && intent === "recon") {
    name = "observe";
    reason = "human+recon";
  }
  const index = STRATEGY_ORDER.indexOf(name);
  if (crossService && index < STRATEGY_ORDER.length - 1) {
    name = STRATEGY_ORDER[index + 1];
    reason = `${reason}+cross-service`;
  }
  return { name, reason, crossService };
}
