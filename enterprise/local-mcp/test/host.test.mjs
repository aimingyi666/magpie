import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  FileAuditSink,
  LocalMcpError,
  LocalMcpHealthStore,
} from "../src/index.js";
import {
  createHost,
  createIdentity,
  createPackage,
  readJsonLines,
  temporaryRoot,
} from "./helpers.mjs";

function assertError(code) {
  return (error) => error instanceof LocalMcpError && error.code === code;
}

test("installs are atomic, idempotent and immutable", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const host = createHost(identity, root);
  const signed = createPackage(identity);

  assert.deepEqual(await host.install(signed), {
    status: "installed",
    packageId: "local-echo",
    releaseId: "2026.11.1",
    packageDigest: signed.manifest.packageDigest,
  });
  assert.deepEqual(await host.install(signed), {
    status: "already_installed",
    packageId: "local-echo",
    releaseId: "2026.11.1",
    packageDigest: signed.manifest.packageDigest,
  });

  const installedServer = path.join(
    root,
    "packages",
    "local-echo",
    "2026.11.1",
    "server.mjs",
  );
  assert.equal(
    fs.readFileSync(installedServer, "utf8"),
    Buffer.from(signed.files["server.mjs"].slice("base64:".length), "base64").toString("utf8"),
  );

  const changed = createPackage(identity, {}, {
    "server.mjs": "process.stdout.write('different');\n",
  });
  await assert.rejects(
    () => host.install(changed),
    assertError("package_conflict"),
  );
  const events = await readJsonLines(path.join(root, "audit.jsonl"));
  assert.deepEqual(events.map((event) => event.event), [
    "local_mcp.install_started",
    "local_mcp.install_completed",
  ]);
});

test("install lock rejects overlapping writers and recovers after release", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const host = createHost(identity, root);
  const release = await host.acquireInstallLock("local-echo", "2026.11.1");
  try {
    await assert.rejects(
      () => host.install(createPackage(identity)),
      assertError("install_locked"),
    );
  } finally {
    await release();
  }
  assert.equal((await host.install(createPackage(identity))).status, "installed");
});

test("publisher, capability, network, secret and compatibility policy deny packages", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const cases = [
    {
      signed: createPackage(identity, { publisher: "untrusted-publisher" }),
      code: "publisher_denied",
      host: {},
    },
    {
      signed: createPackage(identity, {
        permissions: { capabilities: ["fs.read"], networkHosts: [] },
      }),
      code: "policy_denied",
      host: {},
    },
    {
      signed: createPackage(identity, {
        permissions: { capabilities: ["network.connect"], networkHosts: ["evil.example"] },
      }),
      code: "policy_denied",
      host: { allowedCapabilities: ["network.connect"], allowedNetworkHosts: ["api.corp.example"] },
    },
    {
      signed: createPackage(identity, {
        secrets: [{ name: "CORP_TOKEN", reference: "secret://other/token", required: true }],
      }),
      code: "policy_denied",
      host: { allowedSecretPrefixes: ["secret://corp/"] },
    },
    {
      signed: createPackage(identity, {
        compatibility: {
          minClientVersion: "2.0.0",
          platforms: [process.platform],
          architectures: [process.arch],
        },
      }),
      code: "client_version_incompatible",
      host: {},
    },
  ];
  for (const item of cases) {
    const host = createHost(identity, root, item.host);
    await assert.rejects(() => host.install(item.signed), assertError(item.code));
  }
});

test("tool visibility applies allow, deny, risk and capability policy", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const signed = createPackage(identity, {
    permissions: { capabilities: ["fs.read"], networkHosts: [] },
    tools: [
      { name: "echo", description: "Allowed", risk: "low", capabilities: ["fs.read"] },
      { name: "danger", description: "High risk", risk: "high", capabilities: ["fs.read"] },
    ],
  });
  const host = createHost(identity, root, {
    allowedCapabilities: ["fs.read"],
    allowedTools: ["*"],
    deniedTools: ["danger"],
    maxRisk: "medium",
  });
  await host.install(signed);
  assert.deepEqual((await host.listTools("local-echo", "2026.11.1")).map((item) => item.name), [
    "echo",
  ]);

  const riskyHost = createHost(identity, temporaryRoot(t, "magpie-local-mcp-risk-"), {
    allowedCapabilities: ["fs.read"],
    maxRisk: "medium",
  });
  await riskyHost.install(signed);
  assert.deepEqual((await riskyHost.listTools("local-echo", "2026.11.1")).map((item) => item.name), [
    "echo",
  ]);
});

test("high-risk calls require an approval bound to package and tool", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const signed = createPackage(identity, {
    tools: [{
      name: "echo",
      description: "Approved echo",
      risk: "high",
      capabilities: [],
    }],
  });
  let calls = 0;
  const host = createHost(identity, root, {
    approvalAtOrAbove: "high",
    approvalVerifier: async ({ packageDigest, toolName, approval }) => {
      calls += 1;
      return approval?.token === "approved"
        && packageDigest === signed.manifest.packageDigest
        && toolName === "echo";
    },
  });
  await host.install(signed);

  await assert.rejects(
    () => host.callTool("local-echo", "2026.11.1", "echo", { echo: "x" }),
    assertError("approval_required"),
  );
  await assert.rejects(
    () => host.callTool("local-echo", "2026.11.1", "echo", { echo: "x" }, {
      approval: { token: "denied" },
    }),
    assertError("approval_invalid"),
  );
  const result = await host.callTool("local-echo", "2026.11.1", "echo", { echo: "yes" }, {
    approval: { token: "approved" },
  });
  assert.equal(result.status, "succeeded");
  assert.equal(result.result.structuredContent.echo, "yes");
  assert.equal(calls, 2);
});

test("required secrets are injected for one call and expired leases fail closed", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const signed = createPackage(identity, {
    secrets: [{ name: "CORP_TOKEN", reference: "secret://corp/token", required: true }],
  });
  let expiresAt = "2026-11-02T00:10:00.000Z";
  const host = createHost(identity, root, {
    allowedSecretPrefixes: ["secret://corp/"],
    now: () => Date.parse("2026-11-02T00:00:00.000Z"),
    secretBroker: {
      resolve: async (context) => {
        assert.equal(context.reference, "secret://corp/token");
        assert.equal(context.toolName, "echo");
        return { value: "broker-secret", leaseId: "lease_1", expiresAt };
      },
    },
  });
  await host.install(signed);
  const result = await host.callTool("local-echo", "2026.11.1", "echo", { echo: "secret" });
  assert.equal(result.result.structuredContent.secret, "broker-secret");

  expiresAt = "2026-11-01T23:59:59.000Z";
  await assert.rejects(
    () => host.callTool("local-echo", "2026.11.1", "echo", { echo: "expired" }),
    assertError("secret_expired"),
  );
  assert.doesNotMatch(fs.readFileSync(path.join(root, "audit.jsonl"), "utf8"), /broker-secret/);
});

test("tool success records audit events and bounded health counters", async (t) => {
  const root = temporaryRoot(t);
  const identity = createIdentity();
  const host = createHost(identity, root);
  await host.install(createPackage(identity));
  const result = await host.callTool("local-echo", "2026.11.1", "echo", { echo: "hello" });
  assert.equal(result.status, "succeeded");
  assert.equal(result.result.structuredContent.echo, "hello");

  const health = await host.health();
  const record = health.packages.find(
    (item) => item.packageId === "local-echo" && item.releaseId === "2026.11.1",
  );
  assert.equal(record.runtimeStatus, "stopped");
  assert.equal(record.health, "healthy");
  assert.equal(record.tools[0].calls, 1);
  assert.equal(record.tools[0].successes, 1);
  assert.equal(record.tools[0].failures, 0);

  const events = await readJsonLines(path.join(root, "audit.jsonl"));
  assert.deepEqual(events.map((event) => event.event), [
    "local_mcp.install_started",
    "local_mcp.install_completed",
    "local_mcp.tool_started",
    "local_mcp.tool_finished",
  ]);
  assert.doesNotMatch(JSON.stringify(events), /hello/);
});

test("JSON-RPC errors, tool errors, catalog mismatch and malformed output fail closed", async (t) => {
  const identity = createIdentity();
  const cases = [
    ["rpc-error", "tool_failed"],
    ["result-error", "tool_error"],
    ["mismatch", "protocol_invalid"],
    ["malformed", "protocol_invalid"],
  ];
  for (const [mode, code] of cases) {
    const host = createHost(identity, temporaryRoot(t, `magpie-local-mcp-${mode}-`));
    await host.install(createPackage(identity, { runtime: { args: [mode] } }));
    if (code === "tool_error") {
      const result = await host.callTool("local-echo", "2026.11.1", "echo", { echo: mode });
      assert.equal(result.status, "tool_error");
    } else {
      await assert.rejects(
        () => host.callTool("local-echo", "2026.11.1", "echo", { echo: mode }),
        assertError(code),
      );
    }
  }
});

test("tool timeouts and oversized responses are stopped and reported", async (t) => {
  const identity = createIdentity();
  for (const [mode, maxResponseBytes, code] of [
    ["timeout", 1024, "process_timeout"],
    ["large-response", 1024, "protocol_too_large"],
  ]) {
    const host = createHost(identity, temporaryRoot(t, `magpie-local-mcp-${mode}-`), {
      maxProcessMs: 150,
      maxResponseBytes,
    });
    await host.install(createPackage(identity, { runtime: { args: [mode] } }));
    await assert.rejects(
      () => host.callTool("local-echo", "2026.11.1", "echo", { echo: mode }),
      assertError(code),
    );
    const record = (await host.health()).packages[0];
    assert.equal(record.tools[0].failures, 1);
    assert.ok(["failed", "timeout"].includes(record.runtimeStatus));
  }
});

test("audit and health write failures prevent or stop execution", async (t) => {
  const identity = createIdentity();
  const auditRoot = temporaryRoot(t, "magpie-local-mcp-audit-");
  const auditHost = createHost(identity, auditRoot);
  await auditHost.install(createPackage(identity));
  auditHost.auditSink = { write: async () => { throw new Error("disk full"); } };
  await assert.rejects(
    () => auditHost.callTool("local-echo", "2026.11.1", "echo", { echo: "blocked" }),
    assertError("audit_unavailable"),
  );

  const healthRoot = temporaryRoot(t, "magpie-local-mcp-health-");
  const healthHost = createHost(identity, healthRoot);
  await healthHost.install(createPackage(identity));
  const realHealth = healthHost.healthStore;
  healthHost.healthStore = {
    report: () => realHealth.report(),
    recordInstalled: (manifest) => realHealth.recordInstalled(manifest),
    recordRuntime: (...args) => realHealth.recordRuntime(...args),
    recordTool: async () => { throw new Error("health unavailable"); },
  };
  await assert.rejects(
    () => healthHost.callTool("local-echo", "2026.11.1", "echo", { echo: "blocked" }),
    assertError("health_write_failed"),
  );
});

test("health state corruption fails closed and audit files are append-only", async (t) => {
  const root = temporaryRoot(t, "magpie-local-mcp-state-");
  const store = new LocalMcpHealthStore(path.join(root, "state"));
  await fs.promises.mkdir(path.join(root, "state"), { recursive: true });
  await fs.promises.writeFile(path.join(root, "state", "health.json"), '{"broken":true}\n');
  await assert.rejects(() => store.read(), assertError("invalid_health"));

  const sink = new FileAuditSink(root);
  await sink.write({ event: "first" });
  await sink.write({ event: "second" });
  assert.deepEqual((await readJsonLines(path.join(root, "audit.jsonl"))).map((item) => item.event), [
    "first",
    "second",
  ]);
});
