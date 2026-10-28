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
  const profilesTemplate = {
    index_patterns: [`${prefix}-profiles`],
    template: {
      settings,
      mappings: {
        dynamic: "strict",
        properties: {
          sessionId: { type: "keyword" },
          service: { type: "keyword" },
          nodeId: { type: "keyword" },
          sourceIp: { type: "keyword" },
          firstSeen: { type: "date" },
          lastSeen: { type: "date" },
          durationMs: { type: "integer" },
          closed: { type: "boolean" },
          eventCount: { type: "integer" },
          commandCount: { type: "integer" },
          authAttempts: { type: "integer" },
          authSuccess: { type: "integer" },
          commandNames: { type: "keyword" },
          mitreTechniqueIds: { type: "keyword" },
          mitreTactics: { type: "keyword" },
          classification: { properties: { actorType: { type: "keyword" }, skillLevel: { type: "keyword" }, intent: { type: "keyword" }, tools: { type: "keyword" }, confidence: { type: "float" } } },
          llm: { properties: { used: { type: "boolean" }, cached: { type: "boolean" }, fallback: { type: "boolean" }, model: { type: "keyword" }, latencyMs: { type: "integer" } } },
          updatedAt: { type: "date" },
        },
      },
    },
  };
  const attackersTemplate = {
    index_patterns: [`${prefix}-attackers`],
    template: {
      settings,
      mappings: {
        dynamic: "strict",
        properties: {
          attackerId: { type: "keyword" },
          sourceIp: { type: "keyword" },
          firstSeen: { type: "date" },
          lastSeen: { type: "date" },
          sessionCount: { type: "integer" },
          serviceCount: { type: "integer" },
          services: { type: "keyword" },
          sessionIds: { type: "keyword" },
          mitreTechniqueIds: { type: "keyword" },
          mitreTactics: { type: "keyword" },
          tools: { type: "keyword" },
          commandNames: { type: "keyword" },
          classification: { properties: { actorType: { type: "keyword" }, skillLevel: { type: "keyword" }, intent: { type: "keyword" }, confidence: { type: "float" }, llmIntentMismatch: { type: "boolean" } } },
          strategy: { properties: { name: { type: "keyword" }, reason: { type: "keyword" }, crossService: { type: "boolean" } } },
          updatedAt: { type: "date" },
        },
      },
    },
  };
  return { eventsTemplate, sessionsTemplate, profilesTemplate, attackersTemplate };
}
