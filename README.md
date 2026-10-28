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
