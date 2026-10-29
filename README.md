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
