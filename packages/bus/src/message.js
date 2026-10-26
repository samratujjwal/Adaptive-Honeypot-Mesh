import { validateEvent } from "../../shared/src/event.js";

/**
 * Convert a validated event to a Kafka message.
 *
 * @param {object} event
 * @returns {{ key: string, value: string, headers: { service: string, eventType: string } }}
 */
export function toMessage(event) {
  const result = validateEvent(event);
  if (!result.ok) throw new Error("Invalid event for Kafka message");
  const data = result.data;
  return {
    key: data.sessionId,
    value: JSON.stringify(data),
    headers: { service: data.honeypot.service, eventType: data.eventType },
  };
}
