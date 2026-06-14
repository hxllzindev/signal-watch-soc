import test from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp, normalizeBatch, normalizeEvent } from "../src/normalizers.js";

test("normalizes identity provider fields", () => {
  const event = normalizeEvent("identity", { username: "maria", ip: "203.0.113.8", success: false, application: "vpn" });
  assert.equal(event.category, "authentication");
  assert.equal(event.outcome, "failure");
  assert.equal(event.user, "maria");
  assert.equal(event.sourceIp, "203.0.113.8");
});

test("normalizes ECS-style nested user and host values", () => {
  const event = normalizeEvent("generic", { sourceType: "edr", user: { name: "joao" }, host: { name: "ws-03" }, process: { name: "cmd.exe", command_line: "cmd.exe /c whoami" } });
  assert.equal(event.user, "joao");
  assert.equal(event.host, "ws-03");
  assert.equal(event.processName, "cmd.exe");
});

test("rejects unsupported sources and oversized batches", () => {
  assert.throws(() => normalizeEvent("unknown", {}), /Unsupported event source/);
  assert.throws(() => normalizeBatch("identity", Array.from({ length: 1001 }, () => ({}))), /more than 1000/);
});

test("identifies common private IPv4 ranges", () => {
  assert.equal(isPrivateIp("10.10.1.1"), true);
  assert.equal(isPrivateIp("172.31.4.8"), true);
  assert.equal(isPrivateIp("203.0.113.10"), false);
});
