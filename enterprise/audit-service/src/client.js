import crypto from "node:crypto";

const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const ERROR_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeError(code, message, retryable) {
  const error = new Error(message);
  error.code = code;
  error.retryable = retryable;
  return error;
}

async function readLimited(response, maximumBytes) {
  const declared = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw safeError("audit_response_too_large", "Audit service response exceeded the configured limit", false);
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maximumBytes) {
      await reader.cancel();
      throw safeError("audit_response_too_large", "Audit service response exceeded the configured limit", false);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createAuditEventClient(config, options = {}) {
  if (!config?.baseUrl) throw new Error("baseUrl is required");
  if (typeof config.token !== "string"
      || !/^[\u0021-\u007e]{32,512}$/.test(config.token)) {
    throw new Error("A service token of 32-512 printable characters is required");
  }
  const baseUrl = new URL(config.baseUrl);
  if (!["http:", "https:"].includes(baseUrl.protocol)) throw new Error("baseUrl must use HTTP or HTTPS");
  if (baseUrl.username || baseUrl.password) throw new Error("baseUrl must not contain credentials");
  const fetchImpl = options.fetch || fetch;
  const sleepImpl = options.sleep || sleep;
  const maxAttempts = options.maxAttempts || 4;
  const timeoutMs = options.timeoutMs || 5000;
  const maxResponseBytes = options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;

  return {
    async emit(event, options = {}) {
      const idempotencyKey = options.idempotencyKey || `audit-${crypto.randomUUID()}`;
      let lastError;
      let attemptsMade = 0;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        attemptsMade = attempt;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        timeout.unref?.();
        try {
          const response = await fetchImpl(new URL("/api/v1/internal/audit/events", baseUrl), {
            method: "POST",
            headers: {
              authorization: `Bearer ${config.token}`,
              "content-type": "application/json",
              "idempotency-key": idempotencyKey,
            },
            body: JSON.stringify(event),
            redirect: "error",
            signal: controller.signal,
          });
          const text = await readLimited(response, maxResponseBytes);
          let body = {};
          try {
            body = text ? JSON.parse(text) : {};
          } catch {
            throw safeError("invalid_audit_response", "Audit service returned invalid JSON", response.status >= 500);
          }
          if (response.ok) {
            return body;
          }
          const retryable = response.status === 408 || response.status === 429 || response.status >= 500;
          const errorCode = typeof body?.error?.code === "string"
            && ERROR_CODE_PATTERN.test(body.error.code)
            ? body.error.code
            : "audit_emit_failed";
          throw safeError(
            errorCode,
            `Audit service returned HTTP ${response.status}`,
            retryable,
          );
        } catch (error) {
          lastError = error;
          const retryable = error.retryable ?? true;
          if (!retryable || attempt === maxAttempts) break;
          await sleepImpl(Math.min(2000, 100 * (2 ** (attempt - 1))));
        } finally {
          clearTimeout(timeout);
        }
      }
      const error = safeError(
        lastError?.code || "audit_emit_failed",
        "Audit event delivery failed",
        lastError?.retryable ?? true,
      );
      error.attempts = attemptsMade;
      throw error;
    },
  };
}
