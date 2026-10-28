/**
 * Pure index templates for events and sessions.
 *
 * @param {string} prefix
 * @returns {{ eventsTemplate: object, sessionsTemplate: object }}
 */
export function buildTemplates(prefix) {
  const settings = {
    number_of_shards: 1,
    number_of_replicas: 0,
    "index.mapping.total_fields.limit": 200,
  };
  const eventsTemplate = {
    index_patterns: [`${prefix}-events-*`],
    template: {
      settings,
      mappings: {
        dynamic: "strict",
        properties: {
          id: { type: "keyword" },
          timestamp: { type: "date" },
          honeypot: { properties: { service: { type: "keyword" }, nodeId: { type: "keyword" } } },
          sessionId: { type: "keyword" },
          source: { properties: { ip: { type: "ip" }, rawIp: { type: "keyword" }, port: { type: "integer" } } },
          eventType: { type: "keyword" },
          payload: { type: "flattened", ignore_above: 1024 },
          llm: { properties: { used: { type: "boolean" }, cached: { type: "boolean" }, fallback: { type: "boolean" }, latencyMs: { type: "integer" }, model: { type: "keyword" } } },
          mitre: { properties: { techniqueId: { type: "keyword" }, tactic: { type: "keyword" }, confidence: { type: "float" } } },
          enrich: { properties: { ipClass: { type: "keyword" }, geo: { properties: { country: { type: "keyword" }, countryName: { type: "keyword" }, region: { type: "keyword" }, city: { type: "keyword" }, location: { type: "geo_point" }, timezone: { type: "keyword" } } } } },
          ingestedAt: { type: "date" },
        },
      },
    },
  };
  const sessionsTemplate = {
    index_patterns: [`${prefix}-sessions`],
    template: {
      settings,
      mappings: {
        dynamic: "strict",
        properties: {
          sessionId: { type: "keyword" },
          service: { type: "keyword" },
          nodeId: { type: "keyword" },
          sourceIp: { type: "keyword" },
          sourceIpClass: { type: "keyword" },
          geo: { properties: { country: { type: "keyword" }, countryName: { type: "keyword" }, region: { type: "keyword" }, city: { type: "keyword" }, location: { type: "geo_point" }, timezone: { type: "keyword" } } },
          firstSeen: { type: "date" },
          lastSeen: { type: "date" },
          durationMs: { type: "integer" },
          closed: { type: "boolean" },
          closeReason: { type: "keyword" },
          eventCount: { type: "integer" },
          eventTypeCounts: { type: "flattened" },
          authAttempts: { type: "integer" },
          authSuccess: { type: "integer" },
          usernames: { type: "keyword" },
          commandCount: { type: "integer" },
          commands: { type: "keyword" },
          httpRequestCount: { type: "integer" },
          httpPaths: { type: "keyword" },
          ftpCommandCount: { type: "integer" },
          filesTransferred: { properties: { direction: { type: "keyword" }, path: { type: "keyword" }, size: { type: "integer" }, sha256: { type: "keyword" } } },
          llmResponses: { type: "integer" },
          honeytokens: { properties: { tokenId: { type: "keyword" }, kind: { type: "keyword" }, action: { type: "keyword" } } },
          seenEventIds: { type: "keyword" },
          updatedAt: { type: "date" },
        },
      },
    },
  };
  return { eventsTemplate, sessionsTemplate };
}
