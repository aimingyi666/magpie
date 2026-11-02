export const REDACTION_RULE_VERSION = "m4b-redaction-v1";

const MARKER = (category) => `[REDACTED:${category}]`;

function increments(summary, category, count = 1) {
  if (count === 0) return;
  summary.categories[category] = (summary.categories[category] || 0) + count;
  summary.replacements += count;
}

function replaceAll(text, pattern, category, summary, replacement = MARKER(category)) {
  let count = 0;
  const output = text.replace(pattern, (...args) => {
    count += 1;
    return typeof replacement === "function"
      ? replacement(...args)
      : replacement;
  });
  increments(summary, category, count);
  return output;
}

function replacePasswordValues(text, summary) {
  const pattern = /(\b(?:passw(?:or)?d|pwd|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret)\b\s*[:=]\s*)(?!"?\[REDACTED:)(?:"[^"\r\n]{1,}"|'[^'\r\n]{1,}'|[^\s,;}\]]+)/gi;
  return replaceAll(
    text,
    pattern,
    "credential_assignment",
    summary,
    (_match, prefix) => `${prefix}${MARKER("credential_assignment")}`,
  );
}

function luhnValid(candidate) {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = Number(digits[index]);
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

function replaceBankCards(text, summary) {
  let count = 0;
  const output = text.replace(
    /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g,
    (candidate) => {
      if (!luhnValid(candidate)) return candidate;
      count += 1;
      return MARKER("bank_card");
    },
  );
  increments(summary, "bank_card", count);
  return output;
}

export function redactContent(text, options = {}) {
  if (typeof text !== "string") throw new TypeError("content must be a string");
  let output = text;
  const summary = {
    ruleVersion: REDACTION_RULE_VERSION,
    replacements: 0,
    categories: {},
  };

  output = replaceAll(
    output,
    /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----|$)/g,
    "private_key",
    summary,
  );
  output = replacePasswordValues(output, summary);
  output = replaceAll(
    output,
    /\bBearer\s+[A-Za-z0-9._~+\/=-]{16,}/gi,
    "bearer_token",
    summary,
  );
  output = replaceAll(
    output,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    "jwt",
    summary,
  );
  output = replaceAll(
    output,
    /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    "aws_access_key",
    summary,
  );
  output = replaceAll(
    output,
    /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    "github_token",
    summary,
  );
  output = replaceAll(
    output,
    /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    "slack_token",
    summary,
  );
  output = replaceAll(
    output,
    /\bAIza[0-9A-Za-z_-]{35}\b/g,
    "google_api_key",
    summary,
  );
  output = replaceAll(
    output,
    /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/g,
    "api_key",
    summary,
  );
  output = replaceAll(
    output,
    /\b([a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s/]+)(@)/gi,
    "url_credential",
    summary,
    (_match, prefix, _credential, suffix) => `${prefix}${MARKER("url_credential")}${suffix}`,
  );
  output = replaceAll(
    output,
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    "email",
    summary,
  );
  output = replaceAll(
    output,
    /(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)/g,
    "mobile_phone",
    summary,
  );
  output = replaceAll(
    output,
    /(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
    "national_id",
    summary,
  );
  output = replaceBankCards(output, summary);

  const maximumBytes = options.maxOutputBytes;
  if (maximumBytes != null
      && Number.isSafeInteger(maximumBytes)
      && Buffer.byteLength(output, "utf8") > maximumBytes) {
    const error = new Error("Redacted content exceeds the configured limit");
    error.code = "content_redaction_output_too_large";
    throw error;
  }
  return { text: output, summary };
}
