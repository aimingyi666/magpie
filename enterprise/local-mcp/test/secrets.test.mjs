import assert from "node:assert/strict";
import test from "node:test";

import {
  LocalMcpError,
  createEnterpriseSecretBroker,
} from "../src/index.js";

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

test("secret broker uses HTTPS, bearer auth and a bounded lease", async () => {
  let request;
  const broker = createEnterpriseSecretBroker({
    endpoint: "https://broker.corp.example/v1/secrets/resolve",
    tokenProvider: async () => "device-token",
    fetchImpl: async (url, options) => {
      request = { url: String(url), options };
      return jsonResponse({
        value: "short-lived-secret",
        leaseId: "lease_abc-1",
        expiresAt: "2026-11-02T00:10:00.000Z",
      });
    },
  });

  const lease = await broker.resolve({
    reference: "secret://corp/api-token",
    packageId: "local-echo",
    releaseId: "2026.11.1",
    toolName: "echo",
  });
  assert.equal(lease.value, "short-lived-secret");
  assert.equal(lease.leaseId, "lease_abc-1");
  assert.equal(request.url, "https://broker.corp.example/v1/secrets/resolve");
  assert.equal(request.options.headers.authorization, "Bearer device-token");
  assert.deepEqual(JSON.parse(request.options.body), {
    reference: "secret://corp/api-token",
    packageId: "local-echo",
    releaseId: "2026.11.1",
    toolName: "echo",
  });
});

test("secret broker rejects insecure endpoints and invalid leases", async () => {
  assert.throws(
    () => createEnterpriseSecretBroker({
      endpoint: "http://broker.corp.example/secrets",
      tokenProvider: async () => "token",
      fetchImpl: async () => jsonResponse({}),
    }),
    (error) => error instanceof LocalMcpError && error.code === "invalid_config",
  );
  assert.doesNotThrow(() => createEnterpriseSecretBroker({
    endpoint: "http://127.0.0.1:3444/secrets",
    tokenProvider: async () => "token",
    fetchImpl: async () => jsonResponse({}),
    allowLoopbackHttp: true,
  }));

  for (const body of [
    { value: "", leaseId: "lease_1", expiresAt: "2026-11-02T00:10:00.000Z" },
    { value: "secret", leaseId: "bad lease", expiresAt: "2026-11-02T00:10:00.000Z" },
    { value: "secret", leaseId: "lease_1", expiresAt: "not-a-date" },
  ]) {
    const broker = createEnterpriseSecretBroker({
      endpoint: "https://broker.corp.example/secrets",
      tokenProvider: async () => "token",
      fetchImpl: async () => jsonResponse(body),
    });
    await assert.rejects(
      () => broker.resolve({
        reference: "secret://corp/test",
        packageId: "local-echo",
        releaseId: "2026.11.1",
        toolName: "echo",
      }),
      (error) => error instanceof LocalMcpError && error.code === "secret_unavailable",
    );
  }
});

test("secret broker bounds declared and actual response sizes", async () => {
  const tooLarge = JSON.stringify({
    value: "x".repeat(129 * 1024),
    leaseId: "lease_large",
    expiresAt: "2026-11-02T00:10:00.000Z",
  });
  for (const response of [
    jsonResponse({ ok: true }, 200, { "content-length": String(129 * 1024) }),
    new Response(tooLarge, {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
    new Response("not-json", {
      status: 200,
      headers: { "content-type": "text/plain" },
    }),
  ]) {
    const broker = createEnterpriseSecretBroker({
      endpoint: "https://broker.corp.example/secrets",
      tokenProvider: async () => "token",
      fetchImpl: async () => response,
    });
    await assert.rejects(
      () => broker.resolve({
        reference: "secret://corp/test",
        packageId: "local-echo",
        releaseId: "2026.11.1",
        toolName: "echo",
      }),
      (error) => error instanceof LocalMcpError && error.code === "secret_unavailable",
    );
  }
});
