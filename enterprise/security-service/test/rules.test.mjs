import assert from "node:assert/strict";
import test from "node:test";

import { DETECTION_RULE_CATALOG, createDetectionPolicy } from "../src/rules.js";

test("the rule catalog has stable unique ids and versions", () => {
  assert.equal(DETECTION_RULE_CATALOG.length, 8);
  assert.equal(new Set(DETECTION_RULE_CATALOG.map((rule) => rule.ruleId)).size, 8);
  for (const rule of DETECTION_RULE_CATALOG) {
    assert.match(rule.ruleId, /^sec\.[a-z0-9._-]+$/);
    assert.equal(rule.ruleVersion, 1);
    assert.match(rule.ruleKind, /^[a-z][a-z0-9._-]+$/);
    assert.ok(["warning", "high", "critical"].includes(rule.defaultSeverity));
    assert.ok(rule.title.length > 0);
  }
});

test("detection policy accepts zero as disabling suppression", () => {
  const policy = createDetectionPolicy({
    suppressionWindowSeconds: 0,
    trustedRegions: ["cn-beijing", "cn-beijing"],
    trustedSourceIpHashes: [`sha256:${"a".repeat(64)}`],
  });
  assert.equal(policy.suppressionWindowSeconds, 0);
  assert.deepEqual(policy.trustedRegions, ["cn-beijing"]);
  assert.equal(policy.trustedSourceIpHashes.length, 1);
  assert.equal(Object.isFrozen(policy), true);
});

test("detection policy rejects invalid suppression and budget bounds", () => {
  assert.throws(
    () => createDetectionPolicy({ suppressionWindowSeconds: -1 }),
    /suppressionWindowSeconds/,
  );
  assert.throws(
    () => createDetectionPolicy({
      budgetWarningRatio: 0.95,
      budgetCriticalRatio: 0.9,
    }),
    /budgetCriticalRatio/,
  );
});
