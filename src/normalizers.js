import { randomUUID } from "node:crypto";

const privateRanges = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^::1$/];

export function isPrivateIp(value = "") {
  return privateRanges.some((pattern) => pattern.test(value));
}

function timestamp(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) throw Object.assign(new Error("Event timestamp is invalid."), { statusCode: 422 });
  return date.toISOString();
}

function base(source, input) {
  const user = typeof input.user === "object" ? input.user?.name : input.user;
  const host = typeof input.host === "object" ? input.host?.name : input.host;
  return {
    id: input.id || `event-${randomUUID()}`,
    timestamp: timestamp(input.timestamp || input["@timestamp"]),
    sourceType: source,
    category: input.category || "unknown",
    action: input.action || "unknown",
    outcome: input.outcome || "unknown",
    message: String(input.message || "Normalized security event").slice(0, 1000),
    sourceIp: String(input.sourceIp || input.source?.ip || "").slice(0, 80),
    destinationIp: String(input.destinationIp || input.destination?.ip || "").slice(0, 80),
    destinationPort: Number(input.destinationPort || input.destination?.port || 0),
    user: String(user || "").slice(0, 160),
    host: String(host || "").slice(0, 160),
    processName: String(input.processName || input.process?.name || "").slice(0, 240),
    commandLine: String(input.commandLine || input.process?.command_line || "").slice(0, 2000),
    httpMethod: String(input.httpMethod || input.http?.request?.method || "").slice(0, 20),
    httpPath: String(input.httpPath || input.url?.original || "").slice(0, 2000),
    statusCode: Number(input.statusCode || input.http?.response?.status_code || 0),
    cloudAction: String(input.cloudAction || input.event?.action || "").slice(0, 240),
    raw: input
  };
}

function identity(input) {
  return base("identity", {
    ...input,
    category: "authentication",
    action: input.action || "login",
    outcome: input.outcome || (input.success === true ? "success" : input.success === false ? "failure" : "unknown"),
    user: input.user || input.username,
    sourceIp: input.sourceIp || input.ip,
    host: input.host || input.application,
    message: input.message || `${input.success ? "Successful" : "Failed"} authentication for ${input.user || input.username || "unknown user"}`
  });
}

function web(input) {
  return base("web", {
    ...input,
    category: "web",
    action: input.action || "http_request",
    outcome: input.outcome || (Number(input.statusCode || input.status) >= 400 ? "failure" : "success"),
    sourceIp: input.sourceIp || input.remote_addr,
    destinationIp: input.destinationIp || input.server_addr,
    destinationPort: input.destinationPort || input.server_port,
    httpMethod: input.httpMethod || input.method,
    httpPath: input.httpPath || input.path || input.request,
    statusCode: input.statusCode || input.status,
    host: input.host || input.server_name,
    message: input.message || `${input.method || "GET"} ${input.path || input.request || "/"}`
  });
}

function endpoint(input) {
  return base("endpoint", {
    ...input,
    category: input.category || "process",
    action: input.action || "process_start",
    user: input.user || input.username,
    host: input.host || input.hostname,
    processName: input.processName || input.image,
    commandLine: input.commandLine || input.command_line,
    message: input.message || `${input.processName || input.image || "process"} started on ${input.host || input.hostname || "unknown host"}`
  });
}

function network(input) {
  return base("network", {
    ...input,
    category: "network",
    action: input.action || "connection_attempt",
    sourceIp: input.sourceIp || input.src_ip,
    destinationIp: input.destinationIp || input.dest_ip,
    destinationPort: input.destinationPort || input.dest_port,
    outcome: input.outcome || "unknown",
    message: input.message || `${input.sourceIp || input.src_ip} connected to ${input.destinationIp || input.dest_ip}:${input.destinationPort || input.dest_port}`
  });
}

function cloud(input) {
  return base("cloud", {
    ...input,
    category: "cloud",
    action: input.action || input.eventName || "cloud_api_call",
    cloudAction: input.cloudAction || input.eventName,
    user: input.user || input.userIdentity?.arn,
    sourceIp: input.sourceIp || input.sourceIPAddress,
    outcome: input.outcome || (input.errorCode ? "failure" : "success"),
    message: input.message || `${input.eventName || "Cloud action"} by ${input.user || input.userIdentity?.arn || "unknown principal"}`
  });
}

export function normalizeEvent(source, input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw Object.assign(new Error("Each event must be a JSON object."), { statusCode: 422 });
  if (source === "identity") return identity(input);
  if (source === "web") return web(input);
  if (source === "endpoint") return endpoint(input);
  if (source === "network") return network(input);
  if (source === "cloud") return cloud(input);
  if (source === "generic") return base(input.sourceType || "generic", input);
  throw Object.assign(new Error("Unsupported event source."), { statusCode: 422 });
}

export function normalizeBatch(source, events) {
  if (!Array.isArray(events) || events.length === 0) throw Object.assign(new Error("At least one event is required."), { statusCode: 422 });
  if (events.length > 1000) throw Object.assign(new Error("A batch cannot contain more than 1000 events."), { statusCode: 413 });
  return events.map((event) => normalizeEvent(source, event));
}
