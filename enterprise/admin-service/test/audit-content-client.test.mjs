import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  AuditContentServiceClient,
  AuditContentServiceError,
} from "../src/audit-content-client.js";

const CONTENT_REF = `ct_${"a".repeat(43)}`;
const STREAM_ID = `str_${"b".repeat(43)}`;
const EXPORT_ID = `exp_${"c".repeat(43)}`;
const GRANT = `mcg1_${"d".repeat(32)}.${"e".repeat(43)}`;
const EXPORT_TOKEN = `${"f".repeat(32)}.${"g".repeat(43)}`;
const ADMIN_TOKEN = ["test", "audit", "admin", "service", "token", "fixture"].join("-");
const GOVERNANCE_TOKEN = [
  "test",
  "audit",
  "governance",
  "service",
  "token",
  "fixture",
].join("-");
const ORGANIZATION_ID = "org-enterprise";
const IDENTITY = {
  adminId: "adm_aaaaaaaaaaaaaaaaaaaaaaaa",
  sessionHash: "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function json(res, status, value, headers = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

function client(base, overrides = {}) {
  return new AuditContentServiceClient({
    enabled: true,
    url: base,
    adminToken: ADMIN_TOKEN,
    governanceToken: GOVERNANCE_TOKEN,
    organizationId: ORGANIZATION_ID,
    timeoutMs: 300,
    maxResponseBytes: 1024,
    maxExportBytes: 2048,
    ...overrides,
  });
}

test("audit content client sends separated tokens and reads content once", async () => {
  const seen = [];
  let readCount = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const requestAuthorization = String(req.headers["authorization"] || "");
    seen.push({
      method: req.method,
      pathname: url.pathname,
      authorization: requestAuthorization,
      adminId: req.headers["x-audit-admin-id"],
      organizationId: req.headers["x-audit-organization-id"],
      session: req.headers["x-audit-admin-session"],
      grant: req.headers["x-audit-content-grant"],
    });
    if (req.method === "POST" && url.pathname.endsWith("/grants")) {
      json(res, 201, {
        schemaVersion: 1,
        ok: true,
        grant: GRANT,
        grantId: `grt_${"h".repeat(43)}`,
        contentRef: CONTENT_REF,
        issuedAt: "2026-11-03T00:00:00.000Z",
        expiresAt: "2026-11-03T00:02:00.000Z",
      });
      return;
    }
    if (req.method === "GET" && url.pathname.endsWith(CONTENT_REF)) {
      readCount += 1;
      json(res, 200, {
        schemaVersion: 1,
        ok: true,
        contentRef: CONTENT_REF,
        streamId: STREAM_ID,
        requestId: "req_content_client_test",
        sessionId: "ses_content_client_test",
        contentKind: "prompt",
        mediaType: "text/plain",
        auditLevel: "L2",
        content: "redacted prompt",
        accessedAt: "2026-11-03T00:00:01.000Z",
      });
      return;
    }
    json(res, 404, { ok: false });
  });
  const base = await listen(server);
  try {
    const service = client(base);
    const issued = await service.issueGrant(IDENTITY, CONTENT_REF, {
      purpose: "security_investigation",
      reason: "review a security incident",
      approvalId: "apr_12345678",
      ttlSeconds: 60,
    });
    assert.equal(issued.grant, GRANT);
    const content = await service.readContent(IDENTITY, CONTENT_REF, issued.grant);
    assert.equal(content.content, "redacted prompt");
    assert.equal(readCount, 1);
    assert.equal(seen[0].authorization, `Bearer ${ADMIN_TOKEN}`);
    assert.equal(seen[0].adminId, IDENTITY.adminId);
    assert.equal(seen[0].organizationId, ORGANIZATION_ID);
    assert.equal(seen[0].session, IDENTITY.sessionHash);
    assert.equal(seen[1].grant, GRANT);
  } finally {
    await close(server);
  }
});

test("audit content client uses the governance token for governance operations", async () => {
  let authorization = "";
  let idempotencyKey = "";
  const server = http.createServer(async (req, res) => {
    authorization = req.headers.authorization;
    idempotencyKey = req.headers["idempotency-key"];
    for await (const chunk of req) void chunk;
    json(res, 201, {
      schemaVersion: 1,
      ok: true,
      duplicate: false,
      export: {
        exportId: EXPORT_ID,
        status: "active",
      },
      token: EXPORT_TOKEN,
    });
  });
  const base = await listen(server);
  try {
    const service = client(base);
    const created = await service.createExport(IDENTITY, {
      scope: { contentRefs: [CONTENT_REF] },
      purpose: "legal_investigation",
      reason: "preserve content for legal review",
      approvalId: "apr_12345678",
      ttlSeconds: 60,
    }, "export-test-key");
    assert.equal(created.token, EXPORT_TOKEN);
    assert.equal(authorization, `Bearer ${GOVERNANCE_TOKEN}`);
    assert.equal(idempotencyKey, "export-test-key");
  } finally {
    await close(server);
  }
});

test("audit content client maps 404, 5xx, invalid JSON, oversized and timeout failures", async () => {
  let mode = "404";
  const server = http.createServer(async (req, res) => {
    if (mode === "404") {
      json(res, 404, { ok: false });
      return;
    }
    if (mode === "500") {
      json(res, 500, { ok: false });
      return;
    }
    if (mode === "bad-json") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{not-json");
      return;
    }
    if (mode === "large") {
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": "2048",
      });
      res.end("x".repeat(2048));
      return;
    }
    if (mode === "timeout") {
      await new Promise((resolve) => setTimeout(resolve, 600));
      json(res, 200, { schemaVersion: 1, ok: true, streams: [] });
    }
  });
  const base = await listen(server);
  try {
    const service = client(base);
    for (const [nextMode, code] of [
      ["404", "not_found"],
      ["500", "audit_content_unavailable"],
      ["bad-json", "audit_content_invalid_response"],
      ["large", "audit_content_response_too_large"],
      ["timeout", "audit_content_timeout"],
    ]) {
      mode = nextMode;
      await assert.rejects(
        () => service.listStreams(IDENTITY),
        (error) => error instanceof AuditContentServiceError && error.code === code,
      );
    }
  } finally {
    await close(server);
  }
});

test("audit content client rejects redirects without leaking a download token", async () => {
  const server = http.createServer((req, res) => {
    if (req.url.includes("/exports/")) {
      res.writeHead(302, { location: "https://evil.example/export" });
      res.end();
      return;
    }
    res.writeHead(302, { location: "https://evil.example/streams" });
    res.end();
  });
  const base = await listen(server);
  try {
    const service = client(base);
    await assert.rejects(
      () => service.listStreams(IDENTITY),
      (error) => error instanceof AuditContentServiceError
        && error.code === "audit_content_redirect_rejected",
    );
    await assert.rejects(
      () => service.downloadExport(IDENTITY, EXPORT_ID, EXPORT_TOKEN),
      (error) => {
        assert.equal(error.code, "audit_content_redirect_rejected");
        assert.equal(JSON.stringify(error).includes(EXPORT_TOKEN), false);
        return true;
      },
    );
  } finally {
    await close(server);
  }
});

test("audit content client returns export bytes without retaining the token", async () => {
  let receivedToken = "";
  const server = http.createServer((req, res) => {
    receivedToken = String(req.headers["x-audit-export-token"] || "");
    res.writeHead(200, {
      "content-type": "application/octet-stream",
      "content-length": "4",
      "x-audit-watermark": "MAGPIE-AUDIT-EXPORT",
      "x-request-id": "req_export_test",
    });
    res.end(Buffer.from("mge1"));
  });
  const base = await listen(server);
  try {
    const service = client(base);
    const result = await service.downloadExport(IDENTITY, EXPORT_ID, EXPORT_TOKEN);
    assert.equal(result.bytes.toString(), "mge1");
    assert.equal(result.watermark, "MAGPIE-AUDIT-EXPORT");
    assert.equal(receivedToken, EXPORT_TOKEN);
    assert.equal(JSON.stringify(result).includes(EXPORT_TOKEN), false);
  } finally {
    await close(server);
  }
});
