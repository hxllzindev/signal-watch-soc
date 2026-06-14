import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createStore, syntheticAttackSequence } from "./data.js";
import { runDetections } from "./detection-engine.js";
import { normalizeBatch } from "./normalizers.js";

const PUBLIC_DIR = fileURLToPath(new URL("./public", import.meta.url));
const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
const roles = new Set(["analyst", "lead", "viewer"]);
const writeRoles = new Set(["analyst", "lead"]);

function sendJson(res, status, payload, headers = {}) {
  const response = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(response);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw Object.assign(new Error("Payload too large."), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Invalid JSON."), { statusCode: 400 }); }
}

function role(req) {
  const value = String(req.headers["x-soc-role"] || "analyst");
  return roles.has(value) ? value : "analyst";
}

function authorize(req, res, allowed) {
  const current = role(req);
  if (!allowed.has(current)) {
    sendJson(res, 403, { error: "Your current SOC role cannot perform this action." });
    return null;
  }
  return current;
}

function audit(store, action, actorRole, details = {}) {
  store.audit.unshift({ id: randomUUID(), action, actorRole, details, createdAt: new Date().toISOString() });
  store.audit.splice(200);
}

function detectNewAlerts(store) {
  const fingerprints = new Set(store.alerts.map((alert) => alert.fingerprint));
  const generated = runDetections([...store.events].reverse(), store.rules, fingerprints);
  store.alerts.unshift(...generated.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen)));
  return generated;
}

function sourceSummary(store) {
  return store.sources.map((source) => ({
    ...source,
    eventCount: store.events.filter((event) => event.sourceType === source.type).length
  }));
}

function summary(store) {
  const active = store.alerts.filter((alert) => alert.status !== "closed");
  const cutoff = Date.now() - 24 * 60 * 60_000;
  const recentEvents = store.events.filter((event) => new Date(event.timestamp).getTime() >= cutoff);
  const tacticCounts = new Map();
  active.forEach((alert) => tacticCounts.set(alert.tactic, (tacticCounts.get(alert.tactic) || 0) + 1));
  return {
    events24h: recentEvents.length,
    activeAlerts: active.length,
    criticalAlerts: active.filter((alert) => alert.severity === "critical").length,
    openCases: store.cases.filter((item) => item.status !== "closed").length,
    healthySources: store.sources.filter((source) => source.status === "healthy").length,
    totalSources: store.sources.length,
    severity: ["critical", "high", "medium", "low"].map((severity) => ({ severity, count: active.filter((alert) => alert.severity === severity).length })),
    tactics: [...tacticCounts.entries()].map(([tactic, count]) => ({ tactic, count })).sort((a, b) => b.count - a.count),
    trend: Array.from({ length: 6 }, (_, index) => {
      const end = Date.now() - (5 - index) * 60 * 60_000;
      const start = end - 60 * 60_000;
      return { label: new Date(end).toLocaleTimeString("en-US", { hour: "2-digit" }), count: store.alerts.filter((alert) => new Date(alert.lastSeen).getTime() > start && new Date(alert.lastSeen).getTime() <= end).length };
    })
  };
}

function filterEvents(store, url) {
  const query = String(url.searchParams.get("q") || "").toLowerCase();
  const sourceType = url.searchParams.get("sourceType");
  const category = url.searchParams.get("category");
  const outcome = url.searchParams.get("outcome");
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 100)));
  return store.events.filter((event) => {
    if (sourceType && event.sourceType !== sourceType) return false;
    if (category && event.category !== category) return false;
    if (outcome && event.outcome !== outcome) return false;
    if (query && ![event.message, event.sourceIp, event.destinationIp, event.user, event.host, event.commandLine, event.httpPath].some((value) => String(value || "").toLowerCase().includes(query))) return false;
    return true;
  }).slice(0, limit);
}

async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const safe = normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  try {
    const file = await readFile(join(PUBLIC_DIR, safe));
    res.writeHead(200, { "Content-Type": contentTypes[extname(safe)] || "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(file);
  } catch { sendJson(res, 404, { error: "Not found." }); }
}

async function api(req, res, url, store) {
  const segments = url.pathname.split("/").filter(Boolean).slice(1);
  const resource = segments[0];

  if (req.method === "GET" && resource === "health") return sendJson(res, 200, { status: "ok" });
  if (req.method === "GET" && resource === "summary") return sendJson(res, 200, summary(store));
  if (req.method === "GET" && resource === "sources") return sendJson(res, 200, { sources: sourceSummary(store) });
  if (req.method === "GET" && resource === "events") return sendJson(res, 200, { events: filterEvents(store, url), total: store.events.length });

  if (req.method === "GET" && resource === "alerts" && segments[1]) {
    const alert = store.alerts.find((item) => item.id === segments[1]);
    if (!alert) return sendJson(res, 404, { error: "Alert not found." });
    return sendJson(res, 200, { alert, evidence: store.events.filter((event) => alert.eventIds.includes(event.id)).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)) });
  }
  if (req.method === "GET" && resource === "alerts") {
    const severity = url.searchParams.get("severity");
    const status = url.searchParams.get("status");
    const alerts = store.alerts.filter((alert) => (!severity || alert.severity === severity) && (!status || alert.status === status));
    return sendJson(res, 200, { alerts });
  }
  if (req.method === "PATCH" && resource === "alerts" && segments[1]) {
    const actorRole = authorize(req, res, writeRoles); if (!actorRole) return;
    const alert = store.alerts.find((item) => item.id === segments[1]);
    if (!alert) return sendJson(res, 404, { error: "Alert not found." });
    const input = await readJson(req);
    if (input.status && !["new", "investigating", "contained", "closed"].includes(input.status)) return sendJson(res, 422, { error: "Invalid alert status." });
    if (input.status) alert.status = input.status;
    if (input.assignee) alert.assignee = String(input.assignee).slice(0, 120);
    if (input.note) alert.notes.push({ id: randomUUID(), author: String(input.author || actorRole).slice(0, 120), text: String(input.note).slice(0, 1000), createdAt: new Date().toISOString() });
    alert.updatedAt = new Date().toISOString();
    audit(store, "alert_updated", actorRole, { alertId: alert.id, status: alert.status, assignee: alert.assignee });
    return sendJson(res, 200, { alert });
  }

  if (req.method === "GET" && resource === "cases" && segments[1]) {
    const caseItem = store.cases.find((item) => item.id === segments[1]);
    if (!caseItem) return sendJson(res, 404, { error: "Case not found." });
    return sendJson(res, 200, { case: caseItem, alerts: store.alerts.filter((alert) => caseItem.alertIds.includes(alert.id)) });
  }
  if (req.method === "GET" && resource === "cases") return sendJson(res, 200, { cases: store.cases });
  if (req.method === "POST" && resource === "cases") {
    const actorRole = authorize(req, res, writeRoles); if (!actorRole) return;
    const input = await readJson(req);
    const alertIds = Array.isArray(input.alertIds) ? [...new Set(input.alertIds)] : [];
    if (!input.title || !alertIds.length || alertIds.some((id) => !store.alerts.some((alert) => alert.id === id))) return sendJson(res, 422, { error: "Title and valid alert IDs are required." });
    const caseItem = {
      id: `case-${randomUUID()}`,
      title: String(input.title).slice(0, 240),
      description: String(input.description || "").slice(0, 1200),
      severity: ["critical", "high", "medium", "low"].includes(input.severity) ? input.severity : "medium",
      status: "open",
      owner: String(input.owner || "Unassigned").slice(0, 120),
      alertIds,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      timeline: [{ id: randomUUID(), type: "created", author: actorRole, text: "Case created from selected alerts.", createdAt: new Date().toISOString() }]
    };
    store.cases.unshift(caseItem);
    audit(store, "case_created", actorRole, { caseId: caseItem.id, alerts: alertIds.length });
    return sendJson(res, 201, { case: caseItem });
  }
  if (req.method === "PATCH" && resource === "cases" && segments[1]) {
    const actorRole = authorize(req, res, writeRoles); if (!actorRole) return;
    const caseItem = store.cases.find((item) => item.id === segments[1]);
    if (!caseItem) return sendJson(res, 404, { error: "Case not found." });
    const input = await readJson(req);
    if (input.status && !["open", "investigating", "contained", "closed"].includes(input.status)) return sendJson(res, 422, { error: "Invalid case status." });
    if (input.status) caseItem.status = input.status;
    if (input.owner) caseItem.owner = String(input.owner).slice(0, 120);
    if (input.note) caseItem.timeline.push({ id: randomUUID(), type: "note", author: String(input.author || actorRole).slice(0, 120), text: String(input.note).slice(0, 1000), createdAt: new Date().toISOString() });
    caseItem.updatedAt = new Date().toISOString();
    audit(store, "case_updated", actorRole, { caseId: caseItem.id, status: caseItem.status });
    return sendJson(res, 200, { case: caseItem });
  }

  if (req.method === "GET" && resource === "rules") return sendJson(res, 200, { rules: store.rules });
  if (req.method === "PATCH" && resource === "rules" && segments[1]) {
    const actorRole = authorize(req, res, new Set(["lead"])); if (!actorRole) return;
    const rule = store.rules.find((item) => item.id === segments[1]);
    if (!rule) return sendJson(res, 404, { error: "Rule not found." });
    const input = await readJson(req);
    if (input.enabled !== undefined) rule.enabled = Boolean(input.enabled);
    if (input.severity && !["critical", "high", "medium", "low"].includes(input.severity)) return sendJson(res, 422, { error: "Invalid rule severity." });
    if (input.severity) rule.severity = input.severity;
    if (input.threshold !== undefined) {
      const threshold = Number(input.threshold);
      if (!Number.isInteger(threshold) || threshold < 1 || threshold > 1000) return sendJson(res, 422, { error: "Threshold must be an integer from 1 to 1000." });
      rule.threshold = threshold;
    }
    audit(store, "rule_updated", actorRole, { ruleId: rule.id, enabled: rule.enabled, severity: rule.severity, threshold: rule.threshold });
    return sendJson(res, 200, { rule });
  }

  if (req.method === "POST" && resource === "ingest") {
    const actorRole = authorize(req, res, writeRoles); if (!actorRole) return;
    const input = await readJson(req);
    const normalized = normalizeBatch(input.source, input.events);
    store.events.unshift(...normalized.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
    store.events.splice(5000);
    const source = store.sources.find((item) => item.type === input.source);
    if (source) { source.lastEventAt = normalized[normalized.length - 1].timestamp; source.status = "healthy"; }
    const alerts = detectNewAlerts(store);
    audit(store, "events_ingested", actorRole, { source: input.source, events: normalized.length, alerts: alerts.length });
    return sendJson(res, 201, { ingested: normalized.length, alerts });
  }

  if (req.method === "POST" && resource === "simulate") {
    const actorRole = authorize(req, res, writeRoles); if (!actorRole) return;
    store.simulationCount += 1;
    const events = syntheticAttackSequence(store.simulationCount);
    store.events.unshift(...events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
    const alerts = detectNewAlerts(store);
    audit(store, "attack_simulated", actorRole, { events: events.length, alerts: alerts.length, simulation: store.simulationCount });
    return sendJson(res, 201, { events: events.length, alerts });
  }

  if (req.method === "GET" && resource === "audit") return sendJson(res, 200, { events: store.audit.slice(0, 100) });
  return sendJson(res, 404, { error: "Endpoint not found." });
}

export function createApp(options = {}) {
  const store = options.store || createStore();
  const server = createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
      if (url.pathname.startsWith("/api/")) await api(req, res, url, store);
      else await serveStatic(res, url.pathname);
    } catch (error) {
      sendJson(res, error.statusCode || 500, { error: error.statusCode ? error.message : "Internal server error." });
    }
  });
  return { server, store };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 5000);
  createApp().server.listen(port, "0.0.0.0", () => console.log(`Signal Watch SOC: http://127.0.0.1:${port}`));
}
