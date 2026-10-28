export const ALLOWED_TOOLS = ["nmap", "sqlmap", "hydra", "nikto", "gobuster", "dirb", "curl", "wget", "ssh", "ftp", "nc", "ncat"];

export const TOOL_USER_AGENTS = [
  { tool: "sqlmap", signal: "user-agent contains sqlmap", confidence: 0.9 },
  { tool: "nmap", signal: "user-agent contains nmap", confidence: 0.9 },
  { tool: "nikto", signal: "user-agent contains nikto", confidence: 0.9 },
  { tool: "hydra", signal: "user-agent contains hydra", confidence: 0.9 },
  { tool: "gobuster", signal: "user-agent contains gobuster", confidence: 0.9 },
  { tool: "dirb", signal: "user-agent contains dirb", confidence: 0.9 },
];

export const BOT_RULES = [
  { ruleId: "bot-tool-user-agent", signal: "known tool user-agent", threshold: "user-agent contains a known tool name", confidence: 0.7, description: "A known scanner tool user-agent is a bot signal, medium confidence alone." },
  { ruleId: "bot-tool-user-agent-fast", signal: "known tool user-agent plus fast or rate signal", threshold: "tool user-agent AND (auth rate above 0.5 per second OR typing duration aggregate below 50ms per keystroke)", confidence: 0.9, description: "Tool user-agent combined with a fast or rate signal is a strong bot signal." },
  { ruleId: "bot-auth-rate", signal: "auth attempt rate", threshold: "authAttempts / durationSeconds above 0.5 per second when durationMs > 0", confidence: 0.7, description: "Very fast auth attempts are a bot signal." },
  { ruleId: "bot-repetitive", signal: "repetitive commands", threshold: "unique commandNames / commandCount below 0.3 when commandCount >= 5", confidence: 0.5, description: "Repeating the same few commands is a weak bot signal." },
  { ruleId: "bot-short-burst", signal: "many events in a very short session", threshold: "eventCount >= 20 and durationMs < 10000", confidence: 0.5, description: "A burst of events in under 10 seconds is a weak bot signal." },
];

export const HUMAN_RULES = [
  { ruleId: "human-backspace-pauses", signal: "backspace use plus pauses", threshold: "backspaceCount > 0 AND totalTypingMs / totalKeystrokes above 200ms per keystroke when keystrokes > 0", confidence: 0.7, description: "Backspaces plus slow typing are a human signal." },
  { ruleId: "human-varied", signal: "varied commandNames", threshold: "unique commandNames / commandCount above 0.8 when commandCount >= 5", confidence: 0.5, description: "Varied commands are a weak human signal." },
];

export const SKILL_RULES = [
  { ruleId: "skill-beginner", signal: "only basic discovery", threshold: "commandNames subset of whoami, ls, pwd, id and no intermediate or advanced technique", confidence: 0.7, description: "Basic discovery only means beginner." },
  { ruleId: "skill-intermediate", signal: "credential files, ps, netstat, wget, HTTP login attempts", threshold: "any of cat .env, ps, netstat, wget, wp-login, or T1552.001, without advanced techniques", confidence: 0.7, description: "Credential files or process/network discovery means intermediate." },
  { ruleId: "skill-advanced", signal: "SQLi, traversal, persistence, obfuscation, /etc/shadow, or at least 3 advanced techniqueIds", threshold: "T1190, T1547, T1027, T1003, or at least 3 of the advanced set T1190, T1547, T1027, T1003, T1105, T1046", confidence: 0.7, description: "Advanced techniques mean advanced skill." },
];

export const INTENT_PRIORITY = [
  { intent: "persistence", tactic: "Persistence", description: "Persistence tactic wins first." },
  { intent: "credential_access", tactic: "Credential Access", description: "Credential Access wins second." },
  { intent: "exploitation", tactic: "Initial Access", description: "Initial Access with tool transfer wins third." },
  { intent: "recon", tactic: "Discovery", description: "Discovery wins fourth." },
  { intent: "recon", tactic: "Reconnaissance", description: "Reconnaissance also maps to recon." },
];

export const EXFILTRATION_RULE = {
  ruleId: "intent-exfiltration",
  signal: "data leaving the honeypot to the attacker",
  threshold: "service is ftp AND direction is download (FTP RETR, server sends a file to the client) AND the transferred path is sensitive (.env, wp-config, id_rsa, config.bak, .git/config, notes.txt, backup, shadow, passwd)",
  confidence: 0.7,
  description: "Exfiltration is NOT direction alone. SSH wget/curl download (tool, external URL, savedAs in the honeypot) is data ENTERING the honeypot, so it is ingress/tool transfer (T1105) and intent exploitation, never exfiltration. FTP STOR (upload) is also data entering the honeypot, never exfiltration. FTP RETR is data leaving the honeypot, but it is exfiltration only if the file is sensitive by the path list above; otherwise intent is unknown, not guessed.",
};

export const TECHNIQUE_TACTICS = {
  T1033: "Discovery",
  T1082: "Discovery",
  T1083: "Discovery",
  T1087: "Discovery",
  T1003: "Credential Access",
  "T1552.001": "Credential Access",
  T1057: "Discovery",
  T1016: "Discovery",
  T1046: "Discovery",
  T1105: "Command and Control",
  T1027: "Defense Evasion",
  T1547: "Persistence",
  T1190: "Initial Access",
  "T1110.001": "Credential Access",
  T1078: "Initial Access",
};

export const AUTH_ONLY_TECHNIQUES = ["T1110.001", "T1078"];

export const SKILL_EXCLUDED_COMMANDS = ["exit"];
