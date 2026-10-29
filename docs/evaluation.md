# Evaluation (Day 19)

Evaluation only. This document measures what the system already does. It adds no honeypot service, no dashboard section, no API data route, no STIX field, no Grafana panel or datasource change, no LLM model or provider, and no auth system. Day 20 final integration is still pending, so the project is not complete. Grafana MESH OVERVIEW panels showing data is a separate Day 16 track with its own FIX, and Day 19 does not claim Grafana panels show data.

## Tools and exact usages

All three tools are plain Node with no new dependency. Each takes an API base URL. The default API base is http://127.0.0.1:3001, so the flag may be omitted when the API runs on the default base. Usages use no angle brackets.

Dwell time:

node tools/eval-dwell.js --api-base http://127.0.0.1:3001

Latency:

node tools/eval-latency.js --api-base http://127.0.0.1:3001

ATT&CK coverage:

node tools/eval-attack.js --api-base http://127.0.0.1:3001

Each tool prints plain text first, then a JSON block with the same values. In both outputs, any value that cannot be computed from the fetched data is the word TBD. In JSON, TBD appears as the string TBD. No tool ever prints a guessed number.

## Formulas

### Dwell time

The dwell tool fetches sessions from /api/sessions with limit 200 and profiles from /api/profiles with limit 200, using only existing read routes. Profiles are fetched and counted; the LLM split below comes from session data, not from profile enhancement flags.

For each session, duration seconds = (Date.parse(lastSeen) minus Date.parse(firstSeen)) divided by 1000, using firstSeen and lastSeen only, never invented timestamps. A session is complete only when both fields parse and lastSeen is not earlier than firstSeen. Any other session is incomplete: it is counted separately and excluded from median, mean, and max.

Median is the middle value of sorted durations, or the mean of the two middle values for an even count. Mean is the sum divided by the count. Max is the largest duration. All second values are rounded to 3 decimals.

A complete session counts as an LLM session when its llmResponses count is greater than 0, or, when llmResponses is absent, when its eventTypeCounts llm_response count is greater than 0. Both fields count llm_response events seen by the session aggregator. A complete session with no such count is a static session. LLM median and static median are medians over their own groups. The median difference is LLM median minus static median, in seconds. When a group has no complete session, its median is TBD, and the difference is TBD. LLM and static counts cover complete sessions only, so total sessions equals complete sessions plus incomplete sessions, and complete sessions equals LLM sessions plus static sessions.

### Latency

The latency tool measures with Date.now only, no external timing library. It attempts 20 sequential samples for each target and reports statistics over successful samples, with attempted, succeeded, and failed counts. Mean is rounded to 2 decimals. When a target has zero successful samples, its median, mean, min, and max are TBD.

API health is GET on the API base /api/health, 20 requests, counting any completed HTTP response as a success. Honeypot HTTP is GET on /wp-login.php on the honeypot HTTP port, 20 requests, counting any completed HTTP response as a success. Honeypot SSH banner is 20 TCP connections to the honeypot SSH port, where banner time is time to the first banner line only, never a full login, and nothing is sent. Each connection has a 5 second timeout; a timeout or error counts as a failed sample.

The tool connects only to 127.0.0.1 and only to ports 2222, 8080, 2121, and 3001, with the same allowlist rule as the simulator. Any other host or port is rejected before any connection with a plain error and exit code 1.

### ATT&CK coverage

The ATT&CK tool fetches attackers from /api/attackers with limit 50 and profiles from /api/profiles with limit 200, using only existing read routes. It reads technique tactics from packages/mitre rules: 13 techniques come from rules.json, and 2 more come from the classifier event rules, T1110.001 with tactic Credential Access and T1078 with tactic Initial Access. Together they form the Day 11 allowed list of 15 techniques: T1033, T1057, T1082, T1083, T1087, T1003, T1552.001, T1016, T1046, T1105, T1027, T1547, T1190, T1110.001, T1078.

Each technique count is the number of fetched attacker and profile documents whose mitreTechniqueIds list includes that technique. Observed unique is the count of distinct technique IDs across all fetched documents. Coverage fraction is observed allowed techniques divided by allowed total, which is 15. Coverage percent is the fraction multiplied by 100, rounded to 2 decimals. Allowed techniques never observed are allowed techniques absent from all fetched documents. Any technique outside the allowed list is counted separately as unknown, listed with its count, never silently dropped, and never mapped to an allowed technique. No invented technique ID ever appears in the output.

## Results

Every result cell is TBD until Ujjwal runs the tools live. No measured number is written here before live measurement, and no claim is made that LLM beats static.

| Metric | Result |
| --- | --- |
| Dwell median seconds | TBD |
| Dwell mean seconds | TBD |
| Dwell max seconds | TBD |
| Dwell LLM median seconds | TBD |
| Dwell static median seconds | TBD |
| Dwell median difference seconds | TBD |
| Latency API health median ms | TBD |
| Latency API health mean ms | TBD |
| Latency HTTP wp-login median ms | TBD |
| Latency HTTP wp-login mean ms | TBD |
| Latency SSH banner median ms | TBD |
| Latency SSH banner mean ms | TBD |
| ATT&CK coverage fraction | TBD |
| ATT&CK coverage percent | TBD |

## Screenshots guide

Capture the pages in this order, unedited, with no numbers added by hand:

1. MESH CONSOLE dashboard with live feed newest first.
2. Attacker page for 127.0.0.1.
3. STIX bundle sample with identity and attack-patterns only, no raw observables.
4. Grafana MESH OVERVIEW page only after the separate Grafana FIX lands, never before.
5. The three evaluation tool outputs, dwell, latency, and ATT&CK, as text, not as edited images.

Screenshots must be unedited. No number may be added to a screenshot by hand. Tool outputs are captured as text, not as edited images.

## Limitations

Evaluation tools measure only what the API exposes. Dwell time from firstSeen and lastSeen is not the same as attacker attention time. Latency on loopback is not internet latency. ATT&CK coverage counts techniques observed, not techniques blocked. All results stay TBD until live measurement. Grafana data is a separate issue not fixed by Day 19.
