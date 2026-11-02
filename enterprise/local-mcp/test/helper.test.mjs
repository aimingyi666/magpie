import assert from "node:assert/strict";
import test from "node:test";

import {
  LocalMcpError,
  LocalMcpHelper,
} from "../src/index.js";

const RESOURCE_ID = "res_local_echo";
const RELEASE_ID = "rel_local_echo_1";
const PACKAGE_ID = "local-echo";
const PACKAGE_RELEASE_ID = "2026.11.1";

function assertError(code) {
  return (error) => error instanceof LocalMcpError && error.code === code;
}

function packageContent(packageId = PACKAGE_ID, releaseId = PACKAGE_RELEASE_ID) {
  return Buffer.from(JSON.stringify({
    manifest: {
      packageId,
      releaseId,
      packageVersion: "1.0.0",
      packageDigest: `sha256:${"a".repeat(64)}`,
      publisher: "enterprise-platform",
      signingKeyId: "enterprise-local-mcp-test-v1",
    },
  }));
}

function activeResource({
  resourceId = RESOURCE_ID,
  releaseId = RELEASE_ID,
  kind = "mcp",
  resourceVersion = "1.0.0",
  deliveryMode = "forced",
  content = packageContent(),
  packageId = PACKAGE_ID,
  packageReleaseId = PACKAGE_RELEASE_ID,
} = {}) {
  return {
    active: {
      manifest: {
        resourceId,
        releaseId,
        resourceVersion,
        kind,
        deliveryMode,
        packageId,
        packageReleaseId,
        publisher: "enterprise-platform",
        signingKeyId: "enterprise-local-mcp-test-v1",
        packageDigest: `sha256:${"a".repeat(64)}`,
      },
      content,
    },
    record: {
      resourceId,
      releaseId,
      resourceVersion,
      kind,
      deliveryMode,
    },
  };
}

function inspectState({
  resources = [],
  drift = [],
  status = "in_sync",
  revision = "desired-1",
} = {}) {
  return {
    status,
    revision,
    resources,
    drift,
  };
}

function fakeClientSync({
  inspection = inspectState(),
  active = {},
  syncResult = {
    status: "up_to_date",
    revision: "desired-1",
    installed: [],
    unchanged: [],
    skipped: [],
    drift: [],
  },
  syncError = null,
} = {}) {
  return {
    async inspect() {
      return inspection;
    },
    async readActiveResource(resourceId) {
      if (!active[resourceId]) {
        throw new LocalMcpError("resource_not_installed", "resource is not active");
      }
      return active[resourceId];
    },
    async syncOnce() {
      if (syncError) throw syncError;
      return syncResult;
    },
  };
}

function fakeHost({
  verifyError = null,
  health = { packages: [] },
} = {}) {
  const installed = new Set();
  const installs = [];
  const loaded = [];
  const calls = [];
  return {
    installed,
    installs,
    loaded,
    calls,
    async verifyPackage(content) {
      if (verifyError) throw verifyError;
      const parsed = JSON.parse(Buffer.from(content).toString("utf8"));
      return parsed;
    },
    async install(content) {
      const parsed = JSON.parse(Buffer.from(content).toString("utf8"));
      const identity = `${parsed.manifest.packageId}\0${parsed.manifest.releaseId}`;
      installs.push(identity);
      const status = installed.has(identity) ? "already_installed" : "installed";
      installed.add(identity);
      return {
        status,
        packageId: parsed.manifest.packageId,
        releaseId: parsed.manifest.releaseId,
        packageDigest: parsed.manifest.packageDigest,
      };
    },
    async loadInstalled(packageId, releaseId) {
      loaded.push(`${packageId}\0${releaseId}`);
      return { manifest: { packageId, releaseId } };
    },
    async listTools(packageId, releaseId) {
      return [{
        name: "echo",
        description: `Echo from ${packageId}@${releaseId}`,
        risk: "low",
        capabilities: [],
      }];
    },
    async callTool(packageId, releaseId, toolName, args, options) {
      calls.push({ packageId, releaseId, toolName, args, options });
      return {
        status: "succeeded",
        packageId,
        releaseId,
        toolName,
        result: { structuredContent: { echo: args.echo } },
      };
    },
    async health() {
      return health;
    },
  };
}

function helperFor(clientSync, host, now = () => Date.parse("2026-11-02T00:00:00.000Z")) {
  return new LocalMcpHelper({ clientSync, host, now });
}

test("validateClientResource installs only signed MCP client resources", async () => {
  const host = fakeHost();
  const helper = helperFor(fakeClientSync(), host);
  const content = packageContent();

  await helper.validateClientResource({
    manifest: { resourceId: RESOURCE_ID, kind: "instructions" },
    content: Buffer.from("# instructions"),
  });
  assert.deepEqual(host.installs, []);

  await helper.validateClientResource({
    manifest: { resourceId: RESOURCE_ID, kind: "mcp" },
    content,
  });
  assert.deepEqual(host.installs, [`${PACKAGE_ID}\0${PACKAGE_RELEASE_ID}`]);
});

test("reconcile installs active MCP resources and reports idempotent updates", async () => {
  const mcp = activeResource();
  const instructions = activeResource({
    resourceId: "res_instructions",
    kind: "instructions",
    content: Buffer.from("# instructions"),
  });
  const inspection = inspectState({
    resources: [mcp.record, instructions.record],
  });
  const host = fakeHost();
  const helper = helperFor(fakeClientSync({
    inspection,
    active: {
      [mcp.record.resourceId]: mcp.active,
      [instructions.record.resourceId]: instructions.active,
    },
  }), host);

  const first = await helper.reconcile();
  assert.equal(first.status, "ready");
  assert.deepEqual(first.installed, [RESOURCE_ID]);
  assert.deepEqual(first.unchanged, []);
  assert.deepEqual(first.blocked, []);
  assert.deepEqual(host.installs, [`${PACKAGE_ID}\0${PACKAGE_RELEASE_ID}`]);

  const second = await helper.reconcile();
  assert.equal(second.status, "ready");
  assert.deepEqual(second.installed, []);
  assert.deepEqual(second.unchanged, [RESOURCE_ID]);
});

test("reconcile fails closed for drift and invalid package content", async () => {
  const drifted = activeResource();
  const driftState = inspectState({
    resources: [drifted.record],
    drift: [{
      resourceId: RESOURCE_ID,
      expectedReleaseId: RELEASE_ID,
      actualReleaseId: RELEASE_ID,
      state: "content_invalid",
    }],
  });
  const host = fakeHost();
  const helper = helperFor(fakeClientSync({
    inspection: driftState,
    active: { [RESOURCE_ID]: drifted.active },
  }), host);

  const drift = await helper.reconcile();
  assert.equal(drift.status, "degraded");
  assert.deepEqual(drift.installed, []);
  assert.equal(drift.blocked[0].error.code, "resource_drift");
  assert.deepEqual(host.installs, []);

  const active = activeResource();
  const invalidHost = fakeHost({
    verifyError: new LocalMcpError("signature_invalid", "bad package signature"),
  });
  const invalid = await helperFor(fakeClientSync({
    inspection: inspectState({ resources: [active.record] }),
    active: { [RESOURCE_ID]: active.active },
  }), invalidHost).reconcile();
  assert.equal(invalid.status, "degraded");
  assert.equal(invalid.blocked[0].error.code, "signature_invalid");
});

test("read paths reject inactive, drifted and non-MCP resources", async () => {
  const mcp = activeResource();
  const inactive = helperFor(fakeClientSync({
    inspection: inspectState(),
  }), fakeHost());
  await assert.rejects(
    () => inactive.listTools(RESOURCE_ID),
    assertError("resource_not_active"),
  );
  await assert.rejects(
    () => inactive.callTool(RESOURCE_ID, "echo", {}),
    assertError("resource_not_active"),
  );
  await assert.rejects(
    () => inactive.listTools("../escape"),
    assertError("invalid_resource_id"),
  );

  const driftedHelper = helperFor(fakeClientSync({
    inspection: inspectState({
      resources: [mcp.record],
      drift: [{
        resourceId: RESOURCE_ID,
        expectedReleaseId: RELEASE_ID,
        actualReleaseId: RELEASE_ID,
        state: "content_invalid",
      }],
    }),
    active: { [RESOURCE_ID]: mcp.active },
  }), fakeHost());
  await assert.rejects(
    () => driftedHelper.listTools(RESOURCE_ID),
    assertError("resource_drift"),
  );

  const instructions = activeResource({
    kind: "instructions",
    content: Buffer.from("# instructions"),
  });
  const nonMcp = helperFor(fakeClientSync({
    inspection: inspectState({ resources: [instructions.record] }),
    active: { [RESOURCE_ID]: instructions.active },
  }), fakeHost());
  await assert.rejects(
    () => nonMcp.listTools(RESOURCE_ID),
    assertError("resource_not_mcp"),
  );

  const mismatched = activeResource();
  mismatched.active.manifest.resourceId = "res_other";
  const mismatchHelper = helperFor(fakeClientSync({
    inspection: inspectState({ resources: [mismatched.record] }),
    active: { [RESOURCE_ID]: mismatched.active },
  }), fakeHost());
  await assert.rejects(
    () => mismatchHelper.listTools(RESOURCE_ID),
    assertError("resource_invalid"),
  );
});

test("listTools and callTool use the verified package identity", async () => {
  const active = activeResource({
    packageId: "signed-package",
    packageReleaseId: "signed-release",
    content: packageContent("signed-package", "signed-release"),
  });
  const host = fakeHost();
  const helper = helperFor(fakeClientSync({
    inspection: inspectState({ resources: [active.record] }),
    active: { [RESOURCE_ID]: active.active },
  }), host);

  const tools = await helper.listTools(RESOURCE_ID);
  assert.equal(tools.resourceId, RESOURCE_ID);
  assert.equal(tools.packageId, "signed-package");
  assert.equal(tools.packageReleaseId, "signed-release");
  assert.deepEqual(tools.tools.map((tool) => tool.name), ["echo"]);
  assert.deepEqual(host.loaded, ["signed-package\0signed-release"]);

  const result = await helper.callTool(RESOURCE_ID, "echo", {
    echo: "hello",
    packageId: "attacker-package",
  }, {
    approval: { token: "approval-test-token" },
  });
  assert.equal(result.packageId, "signed-package");
  assert.deepEqual(host.calls, [{
    packageId: "signed-package",
    releaseId: "signed-release",
    toolName: "echo",
    args: {
      echo: "hello",
      packageId: "attacker-package",
    },
    options: {
      approval: { token: "approval-test-token" },
    },
  }]);
  await assert.rejects(
    () => helper.callTool(RESOURCE_ID, "../echo", {}),
    assertError("invalid_tool_name"),
  );
});

test("synchronize degrades when sync or local MCP reconciliation fails", async () => {
  const active = activeResource();
  const baseClientSync = fakeClientSync({
    inspection: inspectState({ resources: [active.record] }),
    active: { [RESOURCE_ID]: active.active },
  });
  const ready = await helperFor(baseClientSync, fakeHost()).synchronize();
  assert.equal(ready.status, "ready");
  assert.equal(ready.sync.status, "up_to_date");

  const offlineSync = fakeClientSync({
    inspection: inspectState({ resources: [active.record] }),
    active: { [RESOURCE_ID]: active.active },
    syncResult: {
      status: "offline",
      revision: "desired-1",
      installed: [],
      unchanged: [],
      skipped: [],
      drift: [],
      error: { code: "desired_state_unavailable" },
    },
  });
  const offline = await helperFor(offlineSync, fakeHost()).synchronize();
  assert.equal(offline.status, "degraded");
  assert.equal(offline.localMcp.status, "ready");
  assert.equal(offline.sync.error.code, "desired_state_unavailable");

  const failed = await helperFor(baseClientSync, fakeHost({
    verifyError: new LocalMcpError("signature_invalid", "bad signature"),
  })).synchronize();
  assert.equal(failed.status, "degraded");
  assert.equal(failed.localMcp.blocked[0].error.code, "signature_invalid");

  const thrown = await helperFor(fakeClientSync({
    syncError: new Error("network path C:\\secret\\token"),
  }), fakeHost()).synchronize();
  assert.equal(thrown.status, "degraded");
  assert.equal(thrown.sync.status, "failed");
  assert.equal(JSON.stringify(thrown).includes("secret"), false);
});

test("snapshot is sanitized and reports drift as degraded", async () => {
  const active = activeResource();
  const host = fakeHost({
    health: {
      packages: [{
        packageId: PACKAGE_ID,
        releaseId: PACKAGE_RELEASE_ID,
        runtimeStatus: "running",
        health: "healthy",
        lastErrorCode: null,
        tools: [{
          name: "echo",
          risk: "low",
          calls: 4,
          successes: 3,
          failures: 1,
          denied: 0,
          lastStatus: "succeeded",
          lastErrorCode: null,
          lastCalledAt: "2026-11-02T00:00:00.000Z",
          content: "TOP-SECRET-CONTENT",
          absolutePath: "C:\\Users\\secret",
        }],
      }],
    },
  });
  const helper = helperFor(fakeClientSync({
    inspection: inspectState({ resources: [active.record] }),
    active: { [RESOURCE_ID]: active.active },
  }), host);
  const snapshot = await helper.snapshot();
  assert.equal(snapshot.status, "ready");
  assert.equal(snapshot.packages[0].resourceId, RESOURCE_ID);
  assert.equal(snapshot.packages[0].packageId, PACKAGE_ID);
  assert.equal(snapshot.packages[0].tools[0].calls, 4);
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes("TOP-SECRET-CONTENT"), false);
  assert.equal(serialized.includes("C:\\Users\\secret"), false);
  assert.equal(serialized.includes("PRIVATE KEY"), false);

  const drifted = helperFor(fakeClientSync({
    inspection: inspectState({
      status: "drift",
      resources: [active.record],
      drift: [{
        resourceId: RESOURCE_ID,
        expectedReleaseId: RELEASE_ID,
        actualReleaseId: RELEASE_ID,
        state: "content_invalid",
      }],
    }),
    active: { [RESOURCE_ID]: active.active },
  }), fakeHost());
  const degraded = await drifted.snapshot();
  assert.equal(degraded.status, "degraded");
  assert.equal(degraded.blocked[0].error.code, "resource_drift");
});
