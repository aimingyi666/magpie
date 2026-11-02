import assert from "node:assert/strict";
import test from "node:test";

import {
  REDACTION_RULE_VERSION,
  redactContent,
} from "../src/redaction.js";

function syntheticBankCard() {
  const digits = "400000000000000";
  let sum = 0;
  let double = true;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = Number(digits[index]);
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return `${digits}${(10 - (sum % 10)) % 10}`;
}

test("redacts credentials, identifiers and secrets without retaining raw values", () => {
  const passwordName = "PASSWORD";
  const passwordValue = ["synthetic", passwordName, "p".repeat(16)].join("-");
  const urlPassword = ["synthetic-url", passwordName, "u".repeat(12)].join("-");
  const values = {
    privateKey: "-----BEGIN " + "PRIVATE KEY-----\n"
      + "A".repeat(32)
      + "\n-----END " + "PRIVATE KEY-----",
    credentialValue: passwordValue,
    bearer: `Bearer ${"b".repeat(24)}`,
    jwt: `eyJ${"a".repeat(12)}.${"c".repeat(12)}.${"d".repeat(12)}`,
    aws: `AKIA${"A".repeat(16)}`,
    github: `ghp_${"h".repeat(24)}`,
    slack: `xoxb-${"s".repeat(12)}`,
    google: `AIza${"g".repeat(35)}`,
    apiKey: `sk-${"z".repeat(24)}`,
    urlPassword,
    email: "alice.employee@example.com",
    phone: "13800138000",
    nationalId: "11010519491231002X",
    bankCard: syntheticBankCard(),
  };
  const text = [
    values.privateKey,
    `${passwordName}=${values.credentialValue}`,
    values.bearer,
    values.jwt,
    values.aws,
    values.github,
    values.slack,
    values.google,
    values.apiKey,
    `https://user:${values.urlPassword}@example.com/path`,
    values.email,
    values.phone,
    values.nationalId,
    values.bankCard,
  ].join("\n");

  const result = redactContent(text);

  for (const [name, value] of Object.entries(values)) {
    assert.equal(result.text.includes(value), false, `raw value remained: ${name}`);
  }
  assert.equal(
    result.text.includes(`${passwordName}=[REDACTED:credential_assignment]`),
    true,
  );
  assert.equal(
    result.text.includes("https://user:[REDACTED:url_credential]@example.com/path"),
    true,
  );
  assert.equal(result.text.includes("$1"), false);
  assert.equal(result.text.includes("$3"), false);
  assert.equal(result.summary.ruleVersion, REDACTION_RULE_VERSION);
  assert.ok(result.summary.replacements >= Object.keys(values).length);
  for (const category of [
    "private_key",
    "credential_assignment",
    "bearer_token",
    "jwt",
    "aws_access_key",
    "github_token",
    "slack_token",
    "google_api_key",
    "api_key",
    "url_credential",
    "email",
    "mobile_phone",
    "national_id",
    "bank_card",
  ]) {
    assert.ok(result.summary.categories[category] >= 1, `missing category ${category}`);
  }
});

test("does not redact numbers that fail the bank-card checksum", () => {
  const result = redactContent("reference 1234567890123456");
  assert.equal(result.text, "reference 1234567890123456");
  assert.equal(result.summary.replacements, 0);
});

test("fails closed when redaction expands output past the configured byte limit", () => {
  assert.throws(
    () => redactContent("employee@example.com", { maxOutputBytes: 8 }),
    (error) => error?.code === "content_redaction_output_too_large",
  );
});
