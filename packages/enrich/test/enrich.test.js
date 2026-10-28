import assert from "node:assert";
import test from "node:test";
import { classifyIp, normalizeIp } from "../src/ip.js";
import { createGeoip } from "../src/geoip.js";
import { enrichEvent } from "../src/enrich.js";
import { createEvent } from "../../../packages/shared/src/event.js";

function makeEvent(ip) {
  return createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "test-session-12345678",
    source: { ip, port: 1234 },
    eventType: "command",
    payload: { command: "ls" },
  });
}

test("enrich: private, loopback and link-local ips are classified and get no geo", async () => {
  let lookupCalls = 0;
  const geoip = createGeoip({ enabled: true, lookupImpl: async () => { lookupCalls += 1; return { country: "US", region: "CA", city: "X", ll: [1, 2], timezone: "America/Los_Angeles" }; } });
  for (const ip of ["10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "fc00::1", "100.64.0.1"]) {
    const result = await enrichEvent(makeEvent(ip), { geoip });
    assert.notEqual(result.ipClass, "public", ip);
    assert.equal(result.geo, null, ip);
  }
  assert.equal(lookupCalls, 0);
});
test("enrich: public ip gets country and coordinates from the geoip lookup", async () => {
  const geoip = createGeoip({ enabled: true, lookupImpl: async () => ({ country: "DE", region: "BE", city: "Berlin", ll: [52.52, 13.40], timezone: "Europe/Berlin" }) });
  const result = await enrichEvent(makeEvent("8.8.8.8"), { geoip });
  assert.equal(result.ipClass, "public");
  assert.equal(result.geo.country, "DE");
  assert.equal(result.geo.countryName, "Germany");
  assert.equal(result.geo.city, "Berlin");
  assert.deepEqual(result.geo.location, { lat: 52.52, lon: 13.40 });
  assert.equal(result.geo.timezone, "Europe/Berlin");
});
test("enrich: lookup failure never throws and yields no geo", async () => {
  const geoip = createGeoip({ enabled: true, lookupImpl: async () => { throw new Error("geo down"); } });
  const result = await enrichEvent(makeEvent("8.8.8.8"), { geoip });
  assert.equal(result.geo, null);
  const nullGeoip = createGeoip({ enabled: true, lookupImpl: async () => null });
  const result2 = await enrichEvent(makeEvent("8.8.8.8"), { geoip: nullGeoip });
  assert.equal(result2.geo, null);
});
test("enrich: IPv4-mapped IPv6 addresses are normalized", async () => {
  assert.equal(normalizeIp("::ffff:8.8.8.8"), "8.8.8.8");
  assert.equal(normalizeIp("  ::FFFF:10.0.0.1  "), "10.0.0.1");
  const result = await enrichEvent(makeEvent("::ffff:8.8.8.8"), { geoip: createGeoip({ enabled: false }) });
  assert.equal(result.ip, "8.8.8.8");
  assert.equal(result.ipClass, "public");
});
test("enrich: invalid ip strings are handled", async () => {
  for (const ip of ["", "not-an-ip", "999.999.999.999", "0.0.0.0"]) {
    const manual = { honeypot: { service: "ssh", nodeId: "node-01" }, sessionId: "test-session-12345678", source: { ip, port: 1234 }, eventType: "command", payload: { command: "ls" } };
    const result = await enrichEvent(manual, { geoip: createGeoip({ enabled: true, lookupImpl: async () => ({ country: "US", ll: [0, 0] }) }) });
    assert.equal(result.ipClass, "invalid", ip);
    assert.equal(result.geo, null, ip);
  }
  assert.equal(classifyIp("8.8.8.8"), "public");
});
