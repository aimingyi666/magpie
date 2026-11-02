import crypto from "node:crypto";
import { safeEqual } from "./security.js";

const SIGNATURE_PATTERN = /^sha256=([a-f0-9]{64})$/i;
const NONCE_PATTERN = /^[A-Za-z0-9._:-]+$/;
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+$/;

export class ApprovalCallbackError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.name = "ApprovalCallbackError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

function callbackError(statusCode, code, message = "Approval callback validation failed") {
  return new ApprovalCallbackError(statusCode, code, message);
}

function singleHeader(headers, name) {
  const value = headers[name];
  if (typeof value !== "string" || !value) {
    throw callbackError(400, "approval_callback_invalid", `${name} is required`);
  }
  return value;
}

function boundedText(value, name, maxLength, options = {}) {
  const text = String(value ?? "").trim();
  if (!text) {
    if (options.optional) return "";
    throw callbackError(400, "approval_callback_invalid", `${name} is required`);
  }
  if ([...text].length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) {
    throw callbackError(400, "approval_callback_invalid", `${name} is invalid`);
  }
  return text;
}

function callbackJson(rawBody) {
  let value;
  try {
    value = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw callbackError(400, "approval_callback_invalid", "Callback body must be valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw callbackError(400, "approval_callback_invalid", "Callback body must be a JSON object");
  }
  return value;
}

export function signApprovalCallback(secret, timestamp, nonce, rawBody) {
  return crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${nonce}.`)
    .update(rawBody)
    .digest("hex");
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function parseApprovalCallback(config, headers, rawBody, nowMs = Date.now()) {
  const settings = config?.approvalCallback;
  if (!settings?.enabled || !settings.secret) {
    throw callbackError(
      503,
      "approval_callback_unavailable",
      "External approval callbacks are not configured",
    );
  }

  const timestampText = singleHeader(headers, "x-magpie-timestamp");
  if (!/^[0-9]{1,12}$/.test(timestampText)) {
    throw callbackError(400, "approval_callback_invalid", "Callback timestamp is invalid");
  }
  const timestamp = Number(timestampText);
  const nowSeconds = Math.floor(nowMs / 1000);
  if (!Number.isSafeInteger(timestamp)
      || Math.abs(nowSeconds - timestamp) > settings.maxSkewSeconds) {
    throw callbackError(
      401,
      "approval_callback_timestamp_invalid",
      "Callback timestamp is outside the accepted window",
    );
  }

  const nonce = singleHeader(headers, "x-magpie-nonce");
  if ([...nonce].length < 8 || [...nonce].length > 128 || !NONCE_PATTERN.test(nonce)) {
    throw callbackError(400, "approval_callback_invalid", "Callback nonce is invalid");
  }

  const signatureText = singleHeader(headers, "x-magpie-signature");
  const signatureMatch = SIGNATURE_PATTERN.exec(signatureText);
  if (!signatureMatch) {
    throw callbackError(
      401,
      "approval_callback_signature_invalid",
      "Callback signature is invalid",
    );
  }
  const expectedSignature = signApprovalCallback(
    settings.secret,
    timestampText,
    nonce,
    rawBody,
  );
  if (!safeEqual(signatureMatch[1].toLowerCase(), expectedSignature)) {
    throw callbackError(
      401,
      "approval_callback_signature_invalid",
      "Callback signature is invalid",
    );
  }

  const body = callbackJson(rawBody);
  if (body.schemaVersion !== 1) {
    throw callbackError(
      400,
      "approval_callback_invalid",
      "schemaVersion must be 1",
    );
  }
  const eventId = boundedText(body.eventId, "eventId", 128);
  const issuer = boundedText(body.issuer, "issuer", 256);
  const audience = boundedText(body.audience, "audience", 256);
  const approvalId = boundedText(body.approvalId, "approvalId", 128);
  const decision = boundedText(body.decision, "decision", 16);
  const actorSubjectId = boundedText(body.actorSubjectId, "actorSubjectId", 128);
  const actorEmail = boundedText(body.actorEmail, "actorEmail", 320, { optional: true });
  const externalReference = boundedText(body.externalReference, "externalReference", 500);
  const reason = boundedText(body.reason, "reason", 500);
  const stepId = boundedText(body.stepId, "stepId", 64, { optional: true });

  if (decision !== "approve" && decision !== "reject") {
    throw callbackError(
      400,
      "approval_callback_invalid",
      "decision must be approve or reject",
    );
  }
  if (!issuer || !safeEqual(issuer, settings.issuer)) {
    throw callbackError(
      403,
      "approval_callback_issuer_invalid",
      "Callback issuer is not trusted",
    );
  }
  if (!audience || !safeEqual(audience, settings.audience)) {
    throw callbackError(
      403,
      "approval_callback_audience_invalid",
      "Callback audience is not trusted",
    );
  }
  if (actorEmail && !EMAIL_PATTERN.test(actorEmail)) {
    throw callbackError(400, "approval_callback_invalid", "actorEmail is invalid");
  }
  if (stepId && !/^stp_[A-Za-z0-9_-]{1,60}$/.test(stepId)) {
    throw callbackError(400, "approval_callback_invalid", "stepId is invalid");
  }

  return {
    body: {
      schemaVersion: 1,
      eventId,
      issuer,
      audience,
      approvalId,
      decision,
      actorSubjectId,
      actorEmail: actorEmail.toLowerCase(),
      externalReference,
      reason,
      stepId,
    },
    eventDigest: digest(rawBody),
    nonceDigest: digest(nonce),
    receivedAt: new Date(nowMs).toISOString(),
  };
}
