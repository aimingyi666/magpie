/**
 * M7 - Quota Control Module Tests
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  checkQuotaRemaining,
  createQuotaSnapshot,
  addQuotaUsage,
  resetQuotaWindow,
  EMPTY_QUOTA,
} from "../src/quota-control.js";

test("quota-control: createQuotaSnapshot with no records returns zero usage", () => {
  const snapshot = createQuotaSnapshot("key-1", [], { period: "month", tokens: 1000000, cost: 10 });
  assert.equal(snapshot.usedTokens, 0);
  assert.equal(snapshot.remainingTokens, 1000000);
  assert.equal(snapshot.period, "month");
});

test("quota-control: createQuotaSnapshot with usage records", () => {
  const records = [
    { tokens: 1000, cost: 0.5 },
    { tokens: 500, cost: 0.25 },
  ];
  const snapshot = createQuotaSnapshot("key-1", records, { period: "day", tokens: 5000, cost: 5 });
  assert.equal(snapshot.usedTokens, 1500);
  assert.equal(snapshot.usedCost, 0.75);
  assert.equal(snapshot.remainingTokens, 3500);
});

test("quota-control: createQuotaSnapshot with null config", () => {
  const snapshot = createQuotaSnapshot("key-1", [], null);
  assert.deepEqual(snapshot, { keyId: "key-1", ...EMPTY_QUOTA });
});

test("quota-control: createQuotaSnapshot requires valid keyId", () => {
  assert.throws(
    () => createQuotaSnapshot("", [], {}),
    /keyId is required/,
  );
});

test("quota-control: checkQuotaRemaining allows when under limit", () => {
  const snapshot = { tokens: 1000, usedTokens: 500, cost: 10, usedCost: 5 };
  const result = checkQuotaRemaining(snapshot);
  assert.equal(result.exceeded, false);
  assert.equal(result.reason, "");
});

test("quota-control: checkQuotaRemaining blocks when token limit exceeded", () => {
  const snapshot = { tokens: 1000, usedTokens: 1000, cost: 0, usedCost: 0 };
  const result = checkQuotaRemaining(snapshot);
  assert.equal(result.exceeded, true);
  assert.equal(result.reason, "token_limit_exceeded");
});

test("quota-control: checkQuotaRemaining blocks when cost limit exceeded", () => {
  const snapshot = { tokens: 0, usedTokens: 0, cost: 10, usedCost: 10 };
  const result = checkQuotaRemaining(snapshot);
  assert.equal(result.exceeded, true);
  assert.equal(result.reason, "cost_limit_exceeded");
});

test("quota-control: checkQuotaRemaining allows when limit is 0 (no cap)", () => {
  const snapshot = { tokens: 0, usedTokens: 999999, cost: 0, usedCost: 999999 };
  const result = checkQuotaRemaining(snapshot);
  assert.equal(result.exceeded, false);
});

test("quota-control: addQuotaUsage updates usage correctly", () => {
  const snapshot = { tokens: 1000, usedTokens: 500, cost: 10, usedCost: 5 };
  const updated = addQuotaUsage(snapshot, 200, 2.5);
  assert.equal(updated.usedTokens, 700);
  assert.equal(updated.remainingTokens, 300);
  assert.equal(updated.usedCost, 7.5);
});

test("quota-control: addQuotaUsage throws on null snapshot", () => {
  assert.throws(() => addQuotaUsage(null, 10, 1), /snapshot is required/);
});

test("quota-control: resetQuotaWindow clears usage", () => {
  const snapshot = { tokens: 1000, usedTokens: 800, cost: 10, usedCost: 8, period: "day" };
  const reset = resetQuotaWindow(snapshot, "month");
  assert.equal(reset.usedTokens, 0);
  assert.equal(reset.remainingTokens, 1000);
  assert.equal(reset.period, "month");
});

test("quota-control: resetQuotaWindow preserves period when not provided", () => {
  const snapshot = { tokens: 1000, usedTokens: 800, cost: 10, usedCost: 8, period: "week" };
  const reset = resetQuotaWindow(snapshot);
  assert.equal(reset.period, "week");
  assert.equal(reset.usedTokens, 0);
});

test("quota-control: EMPTY_QUOTA is immutable", () => {
  assert.throws(() => { EMPTY_QUOTA.tokens = 1; });
});
