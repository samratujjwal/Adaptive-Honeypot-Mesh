# Final report: Adaptive Honeypot Mesh, Days 1 to 20

This report closes the 20-day implementation. Code freeze is not deployment: deployment is Ujjwal's decision, and nothing in this report claims the project is deployed. Grafana panels No data remains a separate issue, and this report does not claim Grafana panels show data.

## Stack change

The synopsis stack was Python, Cowrie, Claude, Flask, and Logstash. The synopsis stack was not built. The built stack is Node.js plain JavaScript ESM npm workspaces, a custom SSH honeypot with ssh2, Express fake web apps, a custom FTP honeypot on raw node net with vsftpd 3.0.5 persona, Gemini free API with Flash, Express plus Socket.IO for the API and live feed, a Node consumer instead of Logstash, Kafka plus Elasticsearch plus Grafana in Docker Compose, MITRE mapping by a local JSON rule map, with a Gemini fallback layer only in Day 12 classification. The reason for the change is the agreed changed stack from the project plan.

## 20-day summary

Day 1: monorepo foundation, config, logger, and unified event shape, tests 14.
Day 2: SSH honeypot core with ssh2, file event sink, and allowlist credentials, tests 41.
Day 3: virtual filesystem and command engine, tests 74.
Day 4: Gemini service, not wired into SSH, with persona, prompt, output, cache, and limiter, tests 119 after fix.
Day 5: LLM wired into SSH, static-first, with deadline race and per-session filesystem, tests 170.
Day 6: HTTP honeypot with fake apps and nginx persona, tests 215.
Day 7: shared virtual filesystem package, FTP honeypot, and one-process launcher, tests 265 after fix.
Day 8: per-node persona and honeytokens, tests 310 after fix.
Day 9: Kafka streaming, tests 343.
Day 10: processor with Elasticsearch indexing, enrichment, and sessions, tests 395 after fix.
Day 11: MITRE ATT&CK rules, tests 444 after fix.
Day 12: per-session behavior profiling, observation only, tests 506 after fixes.
Day 13: rules-only adaptive mesh controller, decision only, tests 521.
Day 14: read-only API with live feed, tests 536.
Day 15: dashboard console, tests 559 after fix.
Day 16: attacker page, STIX export, and Grafana provisioning, tests 575.
Day 17: attack simulator and integration tests, tests 591.
Day 18: hardening with isolation, prompt-injection defense, rate limits, and fingerprint resistance, tests 612.
Day 19: evaluation tools for dwell, latency, and ATT&CK coverage, tests 636.
Day 20: spawn-free two-step demo, final report, and code freeze checklist, tests 654.

## Demo
Spawn-free demo usage, two steps, no angle brackets. Step 1: set GF_ADMIN_USER and GF_ADMIN_PASSWORD on the host, then docker compose up -d kafka elasticsearch grafana, wait 60 to 90 seconds, check docker compose ps and ES on 127.0.0.1:9200. Step 2: npm run demo, which starts processor, honeypots, and API in-process, runs simulator basic and mixed, and prints URLs. One-command demo was changed by user decision on 2026-10-29 to a spawn-free two-step demo, because guard.js bans child processes and no guard exception was given, compose is run manually by the user, demo services are in-process only. The demo never starts a process and never runs docker compose itself. Code freeze is not deployment. Grafana panels No data remains a separate issue.

## Evaluation

Day 19 measured evaluation results, exactly as measured live. Dwell: sessions 36, profiles 32, complete 36, incomplete 0, median 0.062 seconds, mean 41.434 seconds, max 845.221 seconds, LLM sessions 1, static sessions 35, LLM median 30.786 seconds, static median 0.056 seconds, difference 30.73 seconds. Caveat: the LLM sample is n=1 only and the mean is skewed by the max outlier. No claim is made that LLM beats static in general. Latency: API health median 16 ms, mean 24 ms, min 5 ms, max 91 ms, HTTP wp-login median 10 ms, mean 12.5 ms, min 3 ms, max 42 ms, SSH banner median 1 ms, mean 1.55 ms, min 0 ms, max 3 ms, all 20 attempts succeeded, all loopback only, not internet latency. ATT&CK: coverage 4 out of 15, 26.67 percent, techniques T1033 Discovery 12, T1078 Initial Access 33, T1083 Discovery 12, T1110.001 Credential Access 33, never observed 11 techniques, unknown none. Caveat: this coverage is for the measured basic traffic only, not for all possible attacks.

## Known limitations

Grafana panels No data is a separate issue, not fixed by Day 20. Rate limits are in-memory only. Fingerprint resistance is persona-level only. Prompt-injection defense is limited to tested patterns. Evaluation results come from loopback and simulator traffic only, not from real internet attackers. The demo script is for a fresh machine with Node and Docker already installed, not for a machine without them. The demo script does not Dockerize Node services. Code freeze is not deployment.
