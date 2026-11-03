/**
 * M7 - IP Control Module Tests
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  checkIpAccess,
  parseIpRule,
} from "../src/ip-control.js";

test("ip-control: checkIpAccess allows null/undefined IP", () => {
  const result = checkIpAccess(null, [["192.168.1.0/24"]], []);
  assert.equal(result.allowed, true);
  assert.equal(result.reason, "");
});

test("ip-control: whitelist blocks non-whitelisted IP", () => {
  const rules = [parseIpRule("192.168.1.0/24")];
  const result = checkIpAccess("10.0.0.1", rules, []);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "not_whitelisted");
});

test("ip-control: whitelist allows matching IP", () => {
  const rules = [parseIpRule("192.168.1.0/24")];
  const result = checkIpAccess("192.168.1.50", rules, []);
  assert.equal(result.allowed, true);
  assert.equal(result.reason, "");
});

test("ip-control: blacklist blocks matching IP", () => {
  const rules = [parseIpRule("10.0.0.1/32")];
  const result = checkIpAccess("10.0.0.1", [], rules);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "blacklisted");
});

test("ip-control: blacklist allows non-matching IP", () => {
  const rules = [parseIpRule("10.0.0.1/32")];
  const result = checkIpAccess("192.168.1.1", [], rules);
  assert.equal(result.allowed, true);
  assert.equal(result.reason, "");
});

test("ip-control: blacklist takes precedence over whitelist", () => {
  const whitelist = [parseIpRule("10.0.0.0/8")];
  const blacklist = [parseIpRule("10.0.0.1/32")];
  const result = checkIpAccess("10.0.0.1", whitelist, blacklist);
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "blacklisted");
});

test("ip-control: whitelist normalizes IPv4-mapped IPv6", () => {
  const rules = [parseIpRule("127.0.0.1/32")];
  const result = checkIpAccess("::ffff:127.0.0.1", rules, []);
  assert.equal(result.allowed, true);
  assert.equal(result.reason, "");
});

test("ip-control: parseIpRule validates prefix range", () => {
  let thrown = false;
  try {
    parseIpRule("192.168.1.0/33");
  } catch (e) {
    thrown = true;
    assert.ok(e.code === "invalid_prefix");
  }
  assert.equal(thrown, true);
});

test("ip-control: parseIpRule rejects empty IP", () => {
  let thrown = false;
  try {
    parseIpRule("/24");
  } catch (e) {
    thrown = true;
    assert.ok(e.code === "invalid_ip");
  }
  assert.equal(thrown, true);
});

test("ip-control: checkIpAccess with empty arrays allows all", () => {
  const result = checkIpAccess("1.2.3.4", [], []);
  assert.equal(result.allowed, true);
});
