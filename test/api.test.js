import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createApp } from "../src/server.js";

async function request(base, path, options = {}) {
  const response = await fetch(`${base}/api${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", "X-SOC-Role": "analyst", ...(options.headers || {}) }
  });
  return { response, body: await response.json() };
}

test("serves the SOC workflow and enforces roles", async (context) => {
  const { server } = createApp();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  const health = await request(base, "/health");
  assert.equal(health.response.status, 200);
  assert.equal(health.response.headers.get("x-content-type-options"), "nosniff");

  const before = await request(base, "/summary");
  assert.ok(before.body.activeAlerts >= 5);
  assert.equal(before.body.totalSources, 5);

  const simulated = await request(base, "/simulate", { method: "POST", body: "{}" });
  assert.equal(simulated.response.status, 201);
  assert.equal(simulated.body.events, 6);
  assert.equal(simulated.body.alerts.length, 2);

  const alertId = simulated.body.alerts[0].id;
  const denied = await request(base, `/alerts/${alertId}`, { method: "PATCH", headers: { "X-SOC-Role": "viewer" }, body: JSON.stringify({ status: "closed" }) });
  assert.equal(denied.response.status, 403);

  const updated = await request(base, `/alerts/${alertId}`, { method: "PATCH", body: JSON.stringify({ status: "investigating", assignee: "Portfolio Analyst", note: "Validated source telemetry." }) });
  assert.equal(updated.response.status, 200);
  assert.equal(updated.body.alert.assignee, "Portfolio Analyst");
  assert.equal(updated.body.alert.notes.length, 1);

  const created = await request(base, "/cases", { method: "POST", body: JSON.stringify({ title: "Investigate simulated identity compromise", severity: "critical", alertIds: [alertId] }) });
  assert.equal(created.response.status, 201);
  assert.deepEqual(created.body.case.alertIds, [alertId]);

  const ruleDenied = await request(base, "/rules/rule-brute-force", { method: "PATCH", body: JSON.stringify({ threshold: 6 }) });
  assert.equal(ruleDenied.response.status, 403);
  const ruleUpdated = await request(base, "/rules/rule-brute-force", { method: "PATCH", headers: { "X-SOC-Role": "lead" }, body: JSON.stringify({ threshold: 6 }) });
  assert.equal(ruleUpdated.response.status, 200);
  assert.equal(ruleUpdated.body.rule.threshold, 6);

  const ingested = await request(base, "/ingest", { method: "POST", body: JSON.stringify({ source: "endpoint", events: [{ hostname: "ws-test", image: "powershell.exe", command_line: "powershell.exe -enc SQBFAFgA" }] }) });
  assert.equal(ingested.response.status, 201);
  assert.equal(ingested.body.ingested, 1);
  assert.equal(ingested.body.alerts[0].techniqueId, "T1059.001");
});
