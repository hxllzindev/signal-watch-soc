import test from "node:test";
import assert from "node:assert/strict";
import { runDetections } from "../src/detection-engine.js";
import { normalizeEvent } from "../src/normalizers.js";
import { detectionRules } from "../src/rules.js";

const at = (seconds) => new Date(Date.UTC(2026, 0, 1, 12, 0, seconds)).toISOString();
const rule = (id) => detectionRules.filter((item) => item.id === id);

test("correlates repeated authentication failures", () => {
  const events = Array.from({ length: 5 }, (_, index) => normalizeEvent("identity", { timestamp: at(index * 20), username: "ana", ip: "203.0.113.5", success: false }));
  const alerts = runDetections(events, rule("rule-brute-force"));
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].techniqueId, "T1110");
  assert.equal(alerts[0].eventIds.length, 5);
});

test("correlates a successful login after failures", () => {
  const events = [0, 10, 20].map((second) => normalizeEvent("identity", { timestamp: at(second), username: "ana", ip: "203.0.113.5", success: false }));
  events.push(normalizeEvent("identity", { timestamp: at(30), username: "ana", ip: "203.0.113.5", success: true }));
  const alerts = runDetections(events, rule("rule-success-after-failures"));
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].severity, "critical");
  assert.match(alerts[0].summary, /after 3 failures/);
});

test("matches encoded PowerShell execution", () => {
  const event = normalizeEvent("endpoint", { timestamp: at(1), hostname: "ws-01", image: "powershell.exe", command_line: "powershell.exe -EncodedCommand SQBFAFgA" });
  const [alert] = runDetections([event], rule("rule-encoded-powershell"));
  assert.equal(alert.techniqueId, "T1059.001");
  assert.equal(alert.host, "ws-01");
});

test("matches traversal attempts in HTTP paths", () => {
  const event = normalizeEvent("web", { timestamp: at(1), remote_addr: "198.51.100.9", path: "/download?file=../../etc/passwd", status: 400, server_name: "portal" });
  const [alert] = runDetections([event], rule("rule-web-exploit"));
  assert.equal(alert.techniqueId, "T1190");
});

test("correlates distinct destination ports as a network scan", () => {
  const events = Array.from({ length: 8 }, (_, index) => normalizeEvent("network", { timestamp: at(index), src_ip: "198.51.100.20", dest_ip: "10.0.0.8", dest_port: 20 + index }));
  const [alert] = runDetections(events, rule("rule-network-scan"));
  assert.equal(alert.techniqueId, "T1046");
  assert.equal(alert.eventIds.length, 8);
});

test("does not emit an existing fingerprint twice", () => {
  const events = Array.from({ length: 5 }, (_, index) => normalizeEvent("identity", { timestamp: at(index), username: "ana", ip: "203.0.113.5", success: false }));
  const first = runDetections(events, rule("rule-brute-force"));
  const second = runDetections(events, rule("rule-brute-force"), new Set([first[0].fingerprint]));
  assert.equal(second.length, 0);
});
