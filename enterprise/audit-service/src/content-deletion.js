import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  ContentStoreError,
  contentDeletionProofMac,
  contentSessionHash,
} from "./content-store.js";
import { canonicalJson, sha256Text } from "./events.js";

const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@_-]{7,127}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const SOURCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const DELETE_FIELDS = new Set(["reason", "approvalId", "force"]);
const POLICY_VERSION = "m4d-retention-v1";

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function invalid(message, code = "invalid_content_governance_request") {
  throw new ContentStoreError(400, code, message);
}

function validText(value, minimum, maximum) {
  return typeof value === "string"
    && value.length >= minimum
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateDeleteRequest(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !DELETE_FIELDS.has(key))) {
    invalid("The deletion request contains an unknown field");
  }
  if (!validText(value.reason, 8, 1024)) {
    invalid("reason must be from 8 to 1024 characters");
  }
  if (!AUTHORIZATION_ID_PATTERN.test(value.approvalId || "")) {
    invalid("approvalId is invalid");
  }
  if (value.force !== undefined && typeof value.force !== "boolean") {
    invalid("force must be a boolean");
  }
  return {
    reason: value.reason,
    approvalId: value.approvalId,
    force: value.force === true,
  };
}

function proofFields(proof) {
  return {
    deletionId: proof.deletionId,
    contentRef: proof.contentRef,
    streamId: proof.streamId,
    deletedAt: proof.deletedAt,
    plaintextSha256: proof.plaintextSha256,
    objectBytes: proof.objectBytes,
    retentionExpiresAt: proof.retentionExpiresAt,
    actorType: proof.actorType,
    actorId: proof.actorId,
    organizationId: proof.organizationId,
    sessionHash: proof.sessionHash,
    requestId: proof.requestId,
    sourceHash: proof.sourceHash,
    reason: proof.reason,
    approvalId: proof.approvalId,
    policyVersion: proof.policyVersion,
  };
}

function publicProof(proof) {
  return {
    deletionId: proof.deletionId,
    contentRef: proof.contentRef,
    streamId: proof.streamId,
    deletedAt: proof.deletedAt,
    plaintextSha256: proof.plaintextSha256,
    objectBytes: proof.objectBytes,
    retentionExpiresAt: proof.retentionExpiresAt,
    actorType: proof.actorType,
    actorId: proof.actorId,
    organizationId: proof.organizationId,
    requestId: proof.requestId,
    reason: proof.reason,
    approvalId: proof.approvalId,
    policyVersion: proof.policyVersion,
  };
}

function deletionKeyHash(key) {
  return sha256Text(`content_delete\u0000${key}`);
}

export class ContentDeletionManager {
  constructor(store, options = {}) {
    if (!store) throw new Error("ContentDeletionManager store is required");
    if (!validText(options.proofSecret, 32, 4096)) {
      throw new Error("ContentDeletionManager proofSecret is invalid");
    }
    this.store = store;
    this.proofSecret = options.proofSecret;
    this.legalHolds = options.legalHolds;
    this.now = options.now || Date.now;
  }

  nowMs() {
    const value = this.now();
    return value instanceof Date ? value.getTime() : Number(value);
  }

  privateContext(administrator, request, auditContext, actorType = "manual") {
    if (!SAFE_ID_PATTERN.test(administrator.adminId || "")
        || !SAFE_ID_PATTERN.test(administrator.organizationId || "")
        || !validText(administrator.sessionId, 8, 256)
        || !SOURCE_HASH_PATTERN.test(auditContext.sourceHash || "")
        || !validText(auditContext.requestId, 1, 136)) {
      invalid("The deletion audit context is invalid");
    }
    return {
      actorType,
      actorId: administrator.adminId,
      organizationId: administrator.organizationId,
      sessionHash: contentSessionHash(
        this.proofSecret,
        administrator.adminId,
        administrator.organizationId,
        administrator.sessionId,
      ),
      requestId: auditContext.requestId,
      sourceHash: auditContext.sourceHash,
      reason: request.reason,
      approvalId: request.approvalId,
      force: request.force === true,
    };
  }

  async delete(contentRef, administrator, request, idempotencyKey, auditContext) {
    if (!CONTENT_REF_PATTERN.test(contentRef || "")) {
      throw new ContentStoreError(400, "invalid_content_ref", "contentRef is invalid");
    }
    if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey || "")) {
      invalid("A valid Idempotency-Key is required");
    }
    const validated = validateDeleteRequest(request);
    const context = this.privateContext(administrator, validated, auditContext);
    const fingerprint = sha256Text(canonicalJson({
      operation: "content_delete",
      contentRef,
      actorId: context.actorId,
      organizationId: context.organizationId,
      sessionHash: context.sessionHash,
      reason: context.reason,
      approvalId: context.approvalId,
      force: context.force,
    }));
    return this.executeDelete(contentRef, context, {
      keyHash: deletionKeyHash(idempotencyKey),
      fingerprint,
    });
  }

  async deleteExpired(contentRef, options) {
    if (!CONTENT_REF_PATTERN.test(contentRef || "")) {
      throw new ContentStoreError(400, "invalid_content_ref", "contentRef is invalid");
    }
    const administrator = {
      adminId: "system_retention",
      organizationId: options.organizationId,
      sessionId: "system_retention_session",
    };
    const context = this.privateContext(administrator, {
      reason: "retention_policy_expired",
      approvalId: "system_retention_policy",
      force: false,
    }, {
      requestId: options.requestId || "req_system_retention",
      sourceHash: options.sourceHash,
    }, "system");
    return this.executeDelete(contentRef, context, null);
  }

  async executeDelete(contentRef, context, idempotency) {
    return this.store.withMutation(async () => {
      if (idempotency) {
        const previous = this.store.index.governanceIdempotency[idempotency.keyHash];
        if (previous) {
          if (previous.operation !== "content_delete"
              || previous.fingerprint !== idempotency.fingerprint) {
            throw new ContentStoreError(
              409,
              "content_deletion_idempotency_conflict",
              "The idempotency key conflicts with an existing deletion",
            );
          }
          const proof = this.store.index.deletionProofs[previous.resultId];
          if (!proof) {
            throw new ContentStoreError(
              500,
              "content_store_corrupt",
              "The deletion idempotency index points to a missing proof",
            );
          }
          return { duplicate: true, proof: publicProof(proof) };
        }
      }

      const object = this.store.index.objects[contentRef];
      if (!object) {
        throw new ContentStoreError(
          404,
          "content_object_not_found",
          "Content object not found",
        );
      }
      const stream = this.store.index.streams[object.streamId];
      if (!stream) {
        throw new ContentStoreError(
          500,
          "content_store_corrupt",
          "The content object points to a missing stream",
        );
      }
      const expiresMs = new Date(object.contentRetentionExpiresAt).getTime();
      if (!Number.isFinite(expiresMs)) {
        throw new ContentStoreError(
          500,
          "content_store_corrupt",
          "Content retention expiry is invalid",
        );
      }
      if (!context.force && this.nowMs() < expiresMs) {
        throw new ContentStoreError(
          409,
          "content_object_not_expired",
          "Content object has not reached its retention expiry",
        );
      }
      const request = stream.request;
      const candidate = {
        contentRef,
        streamId: stream.streamId,
        userId: request.userId,
        departmentId: request.departmentId,
        deviceId: request.deviceId,
        agentId: request.agentId,
      };
      if (this.legalHolds?.activeFor(candidate)) {
        throw new ContentStoreError(
          409,
          "content_legal_hold_active",
          "An active legal hold prevents content deletion",
        );
      }

      const deletionId = `del_${crypto.randomBytes(32).toString("base64url")}`;
      const deletedAt = new Date(this.nowMs()).toISOString();
      const proof = {
        deletionId,
        contentRef,
        streamId: stream.streamId,
        deletedAt,
        plaintextSha256: object.plaintextSha256,
        objectBytes: object.bytes,
        retentionExpiresAt: object.contentRetentionExpiresAt,
        actorType: context.actorType,
        actorId: context.actorId,
        organizationId: context.organizationId,
        sessionHash: context.sessionHash,
        requestId: context.requestId,
        sourceHash: context.sourceHash,
        reason: context.reason,
        approvalId: context.approvalId,
        policyVersion: POLICY_VERSION,
      };
      proof.proofMac = contentDeletionProofMac(this.proofSecret, proof);

      const objectPath = path.join(this.store.objectsDirectory, object.objectFile);
      const stagingPath = path.join(
        this.store.objectsDirectory,
        `.staging-${contentRef}-${deletionId}.bin`,
      );
      const previousStream = structuredClone(stream);
      let staged = false;
      try {
        await fs.rename(objectPath, stagingPath);
        staged = true;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }

      delete this.store.index.objects[contentRef];
      stream.status = "deleted";
      stream.deletedAt = deletedAt;
      stream.deletionId = deletionId;
      stream.updatedAt = deletedAt;
      this.store.index.deletionProofs[deletionId] = proof;
      this.store.index.stats.contentDeleted += 1;
      if (idempotency) {
        this.store.index.governanceIdempotency[idempotency.keyHash] = {
          operation: "content_delete",
          fingerprint: idempotency.fingerprint,
          resultId: deletionId,
        };
      }
      try {
        await this.store.persist();
      } catch (error) {
        this.store.index.streams[stream.streamId] = previousStream;
        this.store.index.objects[contentRef] = object;
        delete this.store.index.deletionProofs[deletionId];
        this.store.index.stats.contentDeleted -= 1;
        if (idempotency) {
          delete this.store.index.governanceIdempotency[idempotency.keyHash];
        }
        if (staged) {
          await fs.rename(stagingPath, objectPath).catch(() => {});
        }
        throw error;
      }
      if (staged) await fs.unlink(stagingPath).catch(() => {});
      return { duplicate: false, proof: publicProof(proof) };
    });
  }

  async list(options = {}) {
    this.store.assertLoaded();
    const limit = options.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      invalid("limit must be from 1 to 500");
    }
    return Object.values(this.store.index.deletionProofs)
      .filter((proof) => !options.organizationId
        || proof.organizationId === options.organizationId)
      .filter((proof) => !options.contentRef
        || proof.contentRef === options.contentRef)
      .filter((proof) => !options.from || proof.deletedAt >= options.from)
      .filter((proof) => !options.to || proof.deletedAt <= options.to)
      .sort((left, right) => right.deletedAt.localeCompare(left.deletedAt)
        || right.deletionId.localeCompare(left.deletionId))
      .slice(0, limit)
      .map(publicProof);
  }

  async get(deletionId) {
    this.store.assertLoaded();
    if (!DELETION_ID_PATTERN.test(deletionId || "")) {
      invalid("deletionId is invalid");
    }
    const proof = this.store.index.deletionProofs[deletionId];
    if (!proof) {
      throw new ContentStoreError(
        404,
        "content_deletion_not_found",
        "Content deletion proof not found",
      );
    }
    return publicProof(proof);
  }

  async verify(deletionId) {
    this.store.assertLoaded();
    if (!DELETION_ID_PATTERN.test(deletionId || "")) {
      invalid("deletionId is invalid");
    }
    const proof = this.store.index.deletionProofs[deletionId];
    if (!proof) {
      throw new ContentStoreError(
        404,
        "content_deletion_not_found",
        "Content deletion proof not found",
      );
    }
    let valid = false;
    try {
      valid = proof.proofMac === contentDeletionProofMac(this.proofSecret, proof);
    } catch {
      valid = false;
    }
    return {
      valid,
      deletionId,
      contentRef: proof.contentRef,
      deletedAt: proof.deletedAt,
      proofDigest: sha256Text(canonicalJson(proofFields(proof))),
    };
  }
}
