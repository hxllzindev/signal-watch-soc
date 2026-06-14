import { createHash, randomUUID } from "node:crypto";

const severityScore = { critical: 95, high: 75, medium: 50, low: 25, info: 10 };

function fingerprint(ruleId, entities, bucket) {
  return createHash("sha256").update(`${ruleId}:${entities.join(":")}:${bucket}`).digest("hex").slice(0, 20);
}

function alert(rule, events, summary, entities = {}) {
  const first = events[0];
  const last = events[events.length - 1];
  const bucket = new Date(last.timestamp).toISOString().slice(0, 13);
  const entityValues = Object.values(entities).filter(Boolean).map(String).sort();
  return {
    id: `alert-${randomUUID()}`,
    fingerprint: fingerprint(rule.id, entityValues, bucket),
    ruleId: rule.id,
    title: rule.name,
    summary,
    severity: rule.severity,
    riskScore: severityScore[rule.severity],
    status: "new",
    assignee: "Unassigned",
    techniqueId: rule.techniqueId,
    techniqueName: rule.techniqueName,
    tactic: rule.tactic,
    sourceIp: entities.sourceIp || first.sourceIp,
    user: entities.user || first.user,
    host: entities.host || first.host,
    firstSeen: first.timestamp,
    lastSeen: last.timestamp,
    eventIds: events.map((event) => event.id),
    notes: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

function within(events, minutes) {
  if (events.length < 2) return true;
  return new Date(events[events.length - 1].timestamp) - new Date(events[0].timestamp) <= minutes * 60_000;
}

function detectBruteForce(events, rule) {
  const groups = new Map();
  for (const event of events.filter((item) => item.category === "authentication" && item.outcome === "failure")) {
    const key = `${event.sourceIp}:${event.user}`;
    const list = groups.get(key) || [];
    list.push(event); groups.set(key, list);
  }
  const alerts = [];
  for (const list of groups.values()) {
    list.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    for (let index = 0; index <= list.length - rule.threshold; index += 1) {
      const sample = list.slice(index, index + rule.threshold);
      if (within(sample, rule.windowMinutes)) {
        alerts.push(alert(rule, sample, `${sample.length} failed logins for ${sample[0].user} from ${sample[0].sourceIp}.`, { sourceIp: sample[0].sourceIp, user: sample[0].user }));
        break;
      }
    }
  }
  return alerts;
}

function detectSuccessAfterFailures(events, rule) {
  const ordered = [...events].filter((event) => event.category === "authentication").sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const alerts = [];
  for (const success of ordered.filter((event) => event.outcome === "success")) {
    const start = new Date(success.timestamp).getTime() - rule.windowMinutes * 60_000;
    const failures = ordered.filter((event) => event.outcome === "failure" && event.sourceIp === success.sourceIp && event.user === success.user && new Date(event.timestamp).getTime() >= start && new Date(event.timestamp) < new Date(success.timestamp));
    if (failures.length >= rule.threshold) {
      const evidence = [...failures, success];
      alerts.push(alert(rule, evidence, `Successful login for ${success.user} after ${failures.length} failures from ${success.sourceIp}.`, { sourceIp: success.sourceIp, user: success.user }));
    }
  }
  return alerts;
}

function detectPowerShell(events, rule) {
  return events.filter((event) => event.category === "process" && /powershell/i.test(`${event.processName} ${event.commandLine}`) && /(-enc\b|-encodedcommand\b|-windowstyle\s+hidden|frombase64string)/i.test(event.commandLine)).map((event) => alert(rule, [event], `Suspicious PowerShell command on ${event.host}.`, { host: event.host, user: event.user }));
}

function detectWebExploit(events, rule) {
  const pattern = /(\.\.\/|%2e%2e|union(?:\s|%20)+select|<script|%3cscript|\/etc\/passwd|cmd=|powershell)/i;
  return events.filter((event) => event.category === "web" && pattern.test(event.httpPath)).map((event) => alert(rule, [event], `Exploit-like request against ${event.host}: ${event.httpPath.slice(0, 180)}`, { sourceIp: event.sourceIp, host: event.host }));
}

function detectScheduledTask(events, rule) {
  return events.filter((event) => event.action === "scheduled_task_created" || /schtasks(?:\.exe)?\s+\/create/i.test(event.commandLine)).map((event) => alert(rule, [event], `Scheduled task created on ${event.host} by ${event.user}.`, { host: event.host, user: event.user }));
}

function detectNetworkScan(events, rule) {
  const groups = new Map();
  for (const event of events.filter((item) => item.category === "network" && item.sourceIp && item.destinationPort)) {
    const list = groups.get(event.sourceIp) || [];
    list.push(event); groups.set(event.sourceIp, list);
  }
  const alerts = [];
  for (const [sourceIp, list] of groups) {
    list.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    for (let start = 0; start < list.length; start += 1) {
      const windowEnd = new Date(list[start].timestamp).getTime() + rule.windowMinutes * 60_000;
      const sample = list.filter((event) => new Date(event.timestamp).getTime() >= new Date(list[start].timestamp).getTime() && new Date(event.timestamp).getTime() <= windowEnd);
      const ports = new Set(sample.map((event) => event.destinationPort));
      if (ports.size >= rule.threshold) {
        alerts.push(alert(rule, sample, `${sourceIp} contacted ${ports.size} destination ports in ${rule.windowMinutes} minutes.`, { sourceIp }));
        break;
      }
    }
  }
  return alerts;
}

export function runDetections(events, rules, existingFingerprints = new Set()) {
  const detections = [];
  for (const rule of rules.filter((item) => item.enabled)) {
    let generated = [];
    if (rule.id === "rule-brute-force") generated = detectBruteForce(events, rule);
    if (rule.id === "rule-success-after-failures") generated = detectSuccessAfterFailures(events, rule);
    if (rule.id === "rule-encoded-powershell") generated = detectPowerShell(events, rule);
    if (rule.id === "rule-web-exploit") generated = detectWebExploit(events, rule);
    if (rule.id === "rule-scheduled-task") generated = detectScheduledTask(events, rule);
    if (rule.id === "rule-network-scan") generated = detectNetworkScan(events, rule);
    for (const candidate of generated) {
      if (!existingFingerprints.has(candidate.fingerprint)) {
        existingFingerprints.add(candidate.fingerprint);
        detections.push(candidate);
      }
    }
  }
  return detections;
}
