import { randomUUID } from "node:crypto";
import { runDetections } from "./detection-engine.js";
import { normalizeBatch, normalizeEvent } from "./normalizers.js";
import { detectionRules } from "./rules.js";

const ago = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();

function initialEvents() {
  const events = [
    normalizeEvent("identity", { timestamp: ago(320), username: "maria", ip: "10.24.8.18", success: true, application: "vpn-gateway" }),
    normalizeEvent("web", { timestamp: ago(210), remote_addr: "198.51.100.44", server_addr: "10.20.1.14", server_port: 443, method: "GET", path: "/api/health", status: 200, server_name: "payments-api" }),
    normalizeEvent("cloud", { timestamp: ago(180), eventName: "ListBuckets", sourceIPAddress: "10.40.2.9", userIdentity: { arn: "arn:aws:iam::123:user/backup-service" } }),
    normalizeEvent("endpoint", { timestamp: ago(130), hostname: "wkstn-fin-07", username: "joao", image: "chrome.exe", command_line: "chrome.exe --type=renderer" }),
    normalizeEvent("identity", { timestamp: ago(48), username: "carlos", ip: "203.0.113.25", success: false, application: "microsoft-365" }),
    normalizeEvent("identity", { timestamp: ago(47), username: "carlos", ip: "203.0.113.25", success: false, application: "microsoft-365" }),
    normalizeEvent("identity", { timestamp: ago(46), username: "carlos", ip: "203.0.113.25", success: false, application: "microsoft-365" }),
    normalizeEvent("identity", { timestamp: ago(45), username: "carlos", ip: "203.0.113.25", success: false, application: "microsoft-365" }),
    normalizeEvent("identity", { timestamp: ago(44), username: "carlos", ip: "203.0.113.25", success: false, application: "microsoft-365" }),
    normalizeEvent("identity", { timestamp: ago(43), username: "carlos", ip: "203.0.113.25", success: true, application: "microsoft-365" }),
    normalizeEvent("endpoint", { timestamp: ago(37), hostname: "wkstn-hr-04", username: "helena", image: "powershell.exe", command_line: "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA" }),
    normalizeEvent("web", { timestamp: ago(31), remote_addr: "198.51.100.82", server_addr: "10.20.1.19", server_port: 443, method: "GET", path: "/download?file=../../../../etc/passwd", status: 400, server_name: "customer-portal" }),
    normalizeEvent("endpoint", { timestamp: ago(26), hostname: "srv-files-02", username: "svc_backup", image: "schtasks.exe", command_line: "schtasks.exe /create /tn UpdateCheck /tr C:\\ProgramData\\update.exe /sc minute", action: "scheduled_task_created" })
  ];

  const scanPorts = [21, 22, 25, 53, 80, 135, 139, 443, 445, 3389];
  scanPorts.forEach((port, index) => events.push(normalizeEvent("network", {
    timestamp: ago(20 - index * 0.1), src_ip: "198.51.100.109", dest_ip: "10.30.4.20", dest_port: port, outcome: "failure"
  })));
  return events;
}

export function createStore() {
  const events = initialEvents().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const rules = detectionRules.map((rule) => ({ ...rule }));
  const alerts = runDetections([...events].reverse(), rules).sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  const critical = alerts.find((alert) => alert.severity === "critical");
  if (critical) {
    critical.status = "investigating";
    critical.assignee = "Ana SOC";
    critical.notes.push({ id: randomUUID(), author: "Ana SOC", text: "Identity provider logs confirmed the success originated from the same address as the failures.", createdAt: ago(35) });
  }

  const cases = critical ? [{
    id: "case-2026-041",
    title: "Potential account compromise - carlos",
    description: "Investigate successful authentication following repeated failures from an external source.",
    severity: "critical",
    status: "open",
    owner: "Ana SOC",
    alertIds: [critical.id],
    createdAt: ago(34),
    updatedAt: ago(34),
    timeline: [{ id: randomUUID(), type: "created", author: "Ana SOC", text: "Case created from correlated identity alert.", createdAt: ago(34) }]
  }] : [];

  return {
    events,
    alerts,
    rules,
    cases,
    audit: [],
    simulationCount: 0,
    sources: [
      { id: "source-identity", type: "identity", name: "Identity Provider", status: "healthy", lastEventAt: events.find((event) => event.sourceType === "identity")?.timestamp, eventsPerMinute: 42 },
      { id: "source-web", type: "web", name: "Web Gateway", status: "healthy", lastEventAt: events.find((event) => event.sourceType === "web")?.timestamp, eventsPerMinute: 184 },
      { id: "source-endpoint", type: "endpoint", name: "Endpoint Telemetry", status: "healthy", lastEventAt: events.find((event) => event.sourceType === "endpoint")?.timestamp, eventsPerMinute: 96 },
      { id: "source-network", type: "network", name: "Network Sensor", status: "healthy", lastEventAt: events.find((event) => event.sourceType === "network")?.timestamp, eventsPerMinute: 260 },
      { id: "source-cloud", type: "cloud", name: "Cloud Audit", status: "delayed", lastEventAt: events.find((event) => event.sourceType === "cloud")?.timestamp, eventsPerMinute: 18 }
    ]
  };
}

export function syntheticAttackSequence(index = 1) {
  const start = Date.now() - 45_000;
  const sourceIp = `203.0.113.${100 + index}`;
  const user = `demo.user${index}`;
  const raw = [];
  for (let attempt = 0; attempt < 5; attempt += 1) {
    raw.push({ timestamp: new Date(start + attempt * 8_000).toISOString(), username: user, ip: sourceIp, success: false, application: "vpn-gateway" });
  }
  raw.push({ timestamp: new Date(start + 45_000).toISOString(), username: user, ip: sourceIp, success: true, application: "vpn-gateway" });
  return normalizeBatch("identity", raw);
}
