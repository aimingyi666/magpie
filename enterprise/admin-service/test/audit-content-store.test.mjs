import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  contentExportAad,
  decryptContentExport,
  encryptContentExport,
} from "../src/audit-content-governance.js";
import { JsonStore } from "../src/store.js";

const CONTENT_REF = `ct_${"a".repeat(43)}`;
const EXPORT_ID = `cexp_${"b".repeat(43)}`;
const NOW = "2026-11-03T00:00:00.000Z";
const LATER = "2026-11-03T00:05:00.000Z";
const RETENTION_EXPIRES = "2026-12-03T00:00:00.000Z";
const EXPORT_KEY = Buffer.from("44".repeat(32), "hex");

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function approval(actorSubjectId = "adm_test") {
  return {
    id: "apr_test",
    status: "approved",
    environmentId: "env_test",
    policyVersion: "APR-01a-v1",
    requesterSubjectId: actorSubjectId,
    action: "audit.content.delete",
    targetType: "content",
    targetId: CONTENT_REF,
    targetOrgUnitId: "*",
    riskLevel: "C",
    reason: "Retain the approval while testing persisted content metadata",
    payloadDigest: "1".repeat(64),
    bindingDigest: "2".repeat(64),
    createdAt: NOW,
    updatedAt: NOW,
    expiresAt: LATER,
    approvedAt: NOW,
    approvedBySubjectId: "adm_approver",
    rejectedAt: "",
    rejectedBySubjectId: "",
    revokedAt: "",
    withdrawnAt: "",
    withdrawnBySubjectId: "",
    operationId: "",
    consumedAt: "",
    workflowVersion: 1,
    workflowKind: "serial",
    steps: [{
      stepId: "stp_1",
      mode: "serial",
      requiredApprovers: 1,
      quorum: 1,
      order: 1,
      status: "approved",
      eligibleSubjectIds: [],
      eligibleRoles: [],
      ineligibleSubjectIds: [],
      decidedBySubjectIds: ["adm_approver"],
      transferHistory: [],
    }],
    stateHistory: [{
      status: "requested",
      at: NOW,
      actorSubjectId,
      reason: "requested",
    }],
  };
}

function exportRecord(overrides = {}) {
  const record = {
    id: EXPORT_ID,
    exportId: EXPORT_ID,
    actorSubjectId: "adm_test",
    actorEmail: "admin@corp.example",
    sessionHash: hash("session"),
    organizationId: "org-enterprise",
    upstreamExportId: `exp_${"c".repeat(43)}`,
    fileName: `${EXPORT_ID}.mge.enc`,
    contentType: "application/octet-stream",
    byteLength: 0,
    objectCount: 2,
    ciphertext: "",
    iv: "",
    tag: "",
    digest: "",
    status: "ready",
    createdAt: NOW,
    updatedAt: NOW,
    expiresAt: LATER,
    consumedAt: "",
    ...overrides,
  };
  return Object.assign(
    record,
    encryptContentExport(EXPORT_KEY, Buffer.from("encrypted audit export"), contentExportAad(record)),
  );
}

function deletionResult(overrides = {}) {
  return {
    deletionId: `del_${"e".repeat(43)}`,
    contentRef: CONTENT_REF,
    streamId: `str_${"f".repeat(43)}`,
    deletedAt: NOW,
    plaintextSha256: "3".repeat(64),
    objectBytes: 4096,
    retentionExpiresAt: RETENTION_EXPIRES,
    actorType: "manual",
    actorId: "adm_test",
    organizationId: "org-enterprise",
    requestId: "req_content_store_test",
    reason: "Delete content after an approved investigation",
    approvalId: "apr_test",
    policyVersion: "CONTENT-RETENTION-v1",
    ...overrides,
  };
}

function governanceRequest(result, overrides = {}) {
  const requestHash = hash("content-governance-request");
  return {
    id: `gcr_${requestHash.slice(0, 32)}`,
    requestHash,
    requestFingerprint: hash("fingerprint"),
    action: "audit.content.delete",
    targetType: "content",
    targetId: CONTENT_REF,
    approvalId: "apr_test",
    actorSubjectId: "adm_test",
    sessionHash: hash("session"),
    status: "succeeded",
    result,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function tokenRecord(record, overrides = {}) {
  const tokenHash = hash("download-token");
  return {
    tokenHash,
    exportId: record.id,
    actorSubjectId: record.actorSubjectId,
    actorEmail: record.actorEmail,
    sessionHash: record.sessionHash,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    consumedAt: "",
    ...overrides,
  };
}

async function loadStore(mutator) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-content-store-"));
  const file = path.join(directory, "admin-store.json");
  try {
    const initial = new JsonStore(file);
    await initial.load();
    const raw = JSON.parse(await fs.readFile(file, "utf8"));
    mutator(raw);
    await fs.writeFile(file, `${JSON.stringify(raw, null, 2)}\n`, "utf8");
    return await new JsonStore(file).load();
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

async function rejectsStore(mutator, pattern) {
  await assert.rejects(() => loadStore(mutator), pattern);
}

test("audit content store accepts a matching encrypted export and token", async () => {
  const record = exportRecord();
  const token = tokenRecord(record);
  const loaded = await loadStore((data) => {
    data.adminContentExports[record.id] = record;
    data.adminContentExportTokens[token.tokenHash] = token;
  });
  assert.equal(loaded.adminContentExports[record.id].digest, record.digest);
  assert.equal(
    loaded.adminContentExportTokens[token.tokenHash].exportId,
    record.id,
  );
});

test("audit content store rejects altered export bytes and authentication fields", async () => {
  const cases = [
    ["ciphertext", (record) => {
      record.ciphertext = Buffer.from("tampered ciphertext").toString("base64");
    }],
    ["iv", (record) => {
      record.iv = Buffer.alloc(11, 1).toString("base64");
    }],
    ["tag", (record) => {
      record.tag = Buffer.alloc(15, 2).toString("base64");
    }],
    ["digest", (record) => {
      record.digest = "0".repeat(64);
    }],
  ];
  for (const [name, mutate] of cases) {
    await rejectsStore((data) => {
      const record = exportRecord();
      mutate(record);
      const token = tokenRecord(record);
      data.adminContentExports[record.id] = record;
      data.adminContentExportTokens[token.tokenHash] = token;
    }, /encrypted payload|invalid export/i);
    assert.ok(name);
  }
});

test("audit content export decryption rejects authenticated byte or context changes", () => {
  const record = exportRecord();
  const aad = contentExportAad(record);
  assert.equal(
    decryptContentExport(EXPORT_KEY, record, aad).toString(),
    "encrypted audit export",
  );
  for (const mutate of [
    (copy) => {
      copy.ciphertext = Buffer.from("tampered ciphertext").toString("base64");
    },
    (copy) => {
      copy.iv = Buffer.alloc(12, 1).toString("base64");
    },
    (copy) => {
      copy.tag = Buffer.alloc(16, 2).toString("base64");
    },
  ]) {
    const copy = structuredClone(record);
    mutate(copy);
    assert.throws(() => decryptContentExport(EXPORT_KEY, copy, aad));
  }
  assert.throws(() => decryptContentExport(
    EXPORT_KEY,
    record,
    contentExportAad({ ...record, organizationId: "org-other" }),
  ));
});

test("audit content store rejects open URLs and export token mismatches", async () => {
  const record = exportRecord();
  await rejectsStore((data) => {
    data.adminContentExports[record.id] = {
      ...record,
      result: { url: "https://attacker.example/token" },
    };
  }, /adminContentExports contains an invalid export/);

  await rejectsStore((data) => {
    data.adminContentExports[record.id] = {
      ...record,
      unexpected: "safe-looking",
    };
  }, /adminContentExports contains an invalid export/);

  const other = exportRecord({
    id: `cexp_${"d".repeat(43)}`,
    exportId: `cexp_${"d".repeat(43)}`,
    fileName: `cexp_${"d".repeat(43)}.mge.enc`,
    actorEmail: "other-admin@corp.example",
  });
  const token = tokenRecord(record, { exportId: other.id });
  await rejectsStore((data) => {
    data.adminContentExports[record.id] = record;
    data.adminContentExports[other.id] = other;
    data.adminContentExportTokens[token.tokenHash] = token;
  }, /content export token does not match its export/);
});

test("audit content store rejects persisted content, bearer tokens, and unstable request IDs", async () => {
  const actorSubjectId = "adm_test";
  const baseRequest = governanceRequest({
    duplicate: false,
    deletion: deletionResult(),
  });
  const requestHash = baseRequest.requestHash;

  await rejectsStore((data) => {
    data.approvalRequests.apr_test = approval(actorSubjectId);
    data.adminContentGovernanceRequests[requestHash] = {
      ...baseRequest,
      result: {
        ...baseRequest.result,
        content: "sensitive conversation body",
      },
    };
  }, /adminContentGovernanceRequests contains an invalid request/);

  await rejectsStore((data) => {
    data.approvalRequests.apr_test = approval(actorSubjectId);
    data.adminContentGovernanceRequests[requestHash] = {
      ...baseRequest,
      result: {
        ...baseRequest.result,
        token: "leaked bearer credential",
      },
    };
  }, /adminContentGovernanceRequests contains an invalid request/);

  await rejectsStore((data) => {
    data.approvalRequests.apr_test = approval(actorSubjectId);
    data.adminContentGovernanceRequests[requestHash] = {
      ...baseRequest,
      result: {
        ...baseRequest.result,
        unexpected: "safe-looking",
      },
    };
  }, /adminContentGovernanceRequests contains an invalid request/);

  await rejectsStore((data) => {
    data.approvalRequests.apr_test = approval(actorSubjectId);
    data.adminContentGovernanceRequests[requestHash] = {
      ...baseRequest,
      id: `gcr_${"0".repeat(32)}`,
    };
  }, /adminContentGovernanceRequests contains an invalid request/);

  await rejectsStore((data) => {
    data.approvalRequests.apr_test = approval(actorSubjectId);
    data.adminContentGovernanceRequests[requestHash] = {
      ...baseRequest,
      targetId: `ct_${"f".repeat(43)}`,
    };
  }, /adminContentGovernanceRequests contains an invalid request/);
});
