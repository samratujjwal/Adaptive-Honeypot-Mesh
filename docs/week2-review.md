# Week 2 Review: Days 8-14

## Day 8: Personas and honeytokens
Per-node personas (deterministic from PERSONA_SEED) and five honeytokens planted across services, with token accounts accepted by SSH, FTP, and the web login. Proven live with tests 310/310/0 after the Day 8 fix (HTTP sendResponse used-detection, ETag format, persona database names).

## Day 9: Kafka streaming
A shared bus package with a pinned Kafka client, synchronous sink emit that never throws into honeypots, and backoff reconnect. Proven with tests 343/343/0 and mutations M1-M4.

## Day 10: Processor and Elasticsearch
The processor parses, validates, enriches, aggregates sessions, and bulk-indexes events and sessions, with dead-letter handling and retry only for 429/5xx. Proven with tests 395/395/0 after the Day 10 fix, which found that the sessions template declared three fields as plain objects under strict dynamic mapping, so every session bulk item failed while events succeeded. That fix is live, but the existing honeypot-sessions index still carries the old mapping, so new sessions only index after that index is recreated (a stale note carried from Day 10; sessions still index once recreated).

## Day 11: MITRE ATT&CK rules
A rules package mapping honeypot behaviour to a fixed allowlist of ATT&CK techniques, wired into the processor, with startup resilience. Proven with tests 444/444/0 after the Day 11 fix, which found that URL normalization stripped traversal encodings before classification; the fix preserved the raw target for the classifier.

## Day 12: Per-session behaviour profiles
Rules-first profiles (bot vs human, skill, tools, intent) with LLM only as enhancement for ambiguous sessions, observation only. Proven with tests 506/506/0 after three fixes: FIX wired the real-mode enhancer into the processor start path; FIX-2 found the classification call used the wrong response schema and parsed whole LLM output as JSON, and moved intent and skill to post-auth behaviour; FIX-3 found the primary model returning 404, added a single-attempt fallback model with a 60-second model-unavailable cooldown and limiter release, and filtered the exit command out of skill input.

## Day 13: Adaptive mesh controller, decision only
A rules-only controller that merges closed-session profiles per source IP into one attacker profile and decides one strategy: contain, deceive, engage, or observe, with one-step cross-service escalation capped at contain. The strategy is stored in Elasticsearch and logged; it does not change any live honeypot response, does not block, ban, or firewall any real IP. Proven with tests 521/521/0 and mutations M1-M3, and a file-mode check of the correlation tool. Day 13 live PASS was reported on 2026-10-28: the live processor run wrote attacker documents with strategies, and no honeypot response changed.

## Day 14: Express API and Socket.IO realtime
A read-only Express API on 127.0.0.1:3001 in dev, with Socket.IO live streaming by polling Elasticsearch every API_POLL_MS for documents newer than the last seen timestamp, deduplicated by _id. All documents are sanitized before they leave the server. No dashboard UI is built in Day 14; the API only reads and streams what Days 1-13 already produce.

## Pending
Day 15 dashboard UI, Day 16 attacker page plus STIX export plus Grafana provisioning, Day 17 simulator, Day 18 hardening (including authentication, which Day 14 deliberately does not add; loopback-only binding in dev is the Day 14 control), Day 19 evaluation, Day 20 final integration.

## Risks
- LLM model availability: gemini-2.5-flash-lite returns 404 for this account, while the fallback gemini-2.5-flash works; the Day 12 FIX-3 cooldown and limiter release cover model-not-found, but a generic LLM error still counts against the limiter.
- Burst reprocessing trips the limiter (RPM=8): reprocessing many profiles at once produces limiter errors after the first eight attempts, so live tests must use single spaced sessions.
- HTTP profiles appear only on 30-minute idle eviction, while SSH and FTP profiles appear on session close, so cross-service live tests should use SSH plus FTP for an immediate result.
- In-memory attacker merge across restarts: the default processor wiring merges only profiles seen in the current run unless an existing attacker document is supplied, so correlation resets across restarts in the default wiring.
- Old honeypot-sessions mapping: the live sessions index still carries the pre-fix mapping from Day 10 until it is recreated; this is a stale note, and sessions index once it is recreated.
