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
