import assert from "node:assert/strict";
import test from "node:test";

import { createAuditEventClient } from "../src/client.js";

const TOKEN = ["audit", "client", "test", "token", "not", "real", "123456789"].join("-");
const EVENT = Object.freeze({
  schemaVersion: 1,
  eventId: "evt_client_test_0001",
});

function client(overrides = {}, options = {}) {
  return createAuditEventClient({
    baseUrl: "http://127.0.0.1:3449",
    token: TOKEN,
    ...overrides,
  }, {
    sleep: async () => {},
    ...options,
  });
}

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

test("timeouts retry with a stable idempotency key", async () => {
  const requests = [];
  const result = await client({}, {
    timeoutMs: 5,
    maxAttempts: 2,
    fetch: async (_url, init) => {
      requests.push(init.headers["idempotency-key"]);
      if (requests.length === 1) {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          }, { once: true });
        });
      }
      return jsonResponse(202, { ok: true, eventId: EVENT.eventId });
    },
  }).emit(EVENT, { idempotencyKey: "client-test-idempotency-key" });

  assert.deepEqual(result, { ok: true, eventId: EVENT.eventId });
  assert.equal(requests.length, 2);
  assert.deepEqual(requests, [
    "client-test-idempotency-key",
    "client-test-idempotency-key",
  ]);
});

test("retryable 5xx responses retry and preserve the server error code on exhaustion", async () => {
  let calls = 0;
  const recovered = await client({}, {
    maxAttempts: 2,
    fetch: async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse(503, {
          ok: false,
          error: { code: "audit_queue_full", retryable: true },
        });
      }
      return jsonResponse(202, { ok: true, eventId: EVENT.eventId });
    },
  }).emit(EVENT);
  assert.equal(recovered.ok, true);
  assert.equal(calls, 2);

  calls = 0;
  await assert.rejects(client({}, {
    maxAttempts: 2,
    fetch: async () => {
      calls += 1;
      return jsonResponse(503, {
        ok: false,
        error: { code: "audit_unavailable", retryable: true },
      });
    },
  }).emit(EVENT), (error) => {
    assert.equal(error.code, "audit_unavailable");
    assert.equal(error.retryable, true);
    assert.equal(error.attempts, 2);
    return true;
  });
  assert.equal(calls, 2);
});

test("permanent 4xx responses are not retried", async () => {
  let calls = 0;
  await assert.rejects(client({}, {
    maxAttempts: 4,
    fetch: async () => {
      calls += 1;
      return jsonResponse(409, {
        ok: false,
        error: { code: "idempotency_conflict", retryable: false },
      });
    },
  }).emit(EVENT), (error) => {
    assert.equal(error.code, "idempotency_conflict");
    assert.equal(error.retryable, false);
    assert.equal(error.attempts, 1);
    return true;
  });
  assert.equal(calls, 1);
});

test("oversized responses fail without retry or response-body leakage", async () => {
  let calls = 0;
  await assert.rejects(client({}, {
    maxResponseBytes: 32,
    maxAttempts: 3,
    fetch: async () => {
      calls += 1;
      return jsonResponse(202, {
        ok: true,
        padding: "x".repeat(1024),
      }, {
        "content-length": "2048",
      });
    },
  }).emit(EVENT), (error) => {
    assert.equal(error.code, "audit_response_too_large");
    assert.equal(error.retryable, false);
    assert.equal(error.attempts, 1);
    assert.equal(error.message.includes(TOKEN), false);
    return true;
  });
  assert.equal(calls, 1);
});

test("invalid client configuration and malformed base URLs fail closed", () => {
  const credentialUrl = ["https://user", ":", "not-a-real-secret", "@example.invalid"].join("");
  assert.throws(
    () => createAuditEventClient({ baseUrl: "http://127.0.0.1:3449", token: "short" }),
    /32-512 printable characters/,
  );
  assert.throws(
    () => createAuditEventClient({
      baseUrl: credentialUrl,
      token: TOKEN,
    }),
    /must not contain credentials/,
  );
});
