import crypto from "node:crypto";

const TOKEN_PATTERN = /^([A-Za-z0-9_-]{1,8192})\.([A-Za-z0-9_-]{43})$/;
const TOKEN_ENCODING = "base" + "64url";
const PAYLOAD_FIELDS = new Set([
  "approvalId",
  "clientId",
  "serverId",
  "tool",
  "iat",
  "exp",
  "nonce",
]);

export class ApprovalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ApprovalError";
    this.code = code;
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function safeText(value, maximum = 128) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function encode(value) {
  return Buffer.from(value, "utf8").toString(TOKEN_ENCODING);
}

function decode(value) {
  return Buffer.from(value, TOKEN_ENCODING).toString("utf8");
}

function signature(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest();
}

export function issueApprovalToken(secret, payload) {
  if (!secret) throw new ApprovalError("approval_unavailable", "Approval signing is not configured");
  const encoded = encode(JSON.stringify(payload));
  return `${encoded}.${signature(encoded, secret).toString(TOKEN_ENCODING)}`;
}

export class ApprovalVerifier {
  constructor({ secret, maximumTtlSeconds, now = () => Date.now() }) {
    this.secret = secret;
    this.maximumTtlSeconds = maximumTtlSeconds;
    this.now = now;
    this.nonces = new Map();
  }

  verify(token, binding) {
    if (!this.secret) {
      throw new ApprovalError("approval_unavailable", "Approval signing is not configured");
    }
    const match = TOKEN_PATTERN.exec(String(token || ""));
    if (!match) {
      throw new ApprovalError("invalid_approval", "The approval token is invalid");
    }
    const [, encoded, suppliedSignature] = match;
    const expected = signature(encoded, this.secret);
    const supplied = Buffer.from(suppliedSignature, TOKEN_ENCODING);
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      throw new ApprovalError("invalid_approval", "The approval token is invalid");
    }
    let payload;
    try {
      payload = JSON.parse(decode(encoded));
    } catch {
      throw new ApprovalError("invalid_approval", "The approval token is invalid");
    }
    const nowSeconds = Math.floor(this.now() / 1000);
    if (!plainObject(payload)
        || Object.keys(payload).length !== PAYLOAD_FIELDS.size
        || Object.keys(payload).some((key) => !PAYLOAD_FIELDS.has(key))
        || !safeText(payload.approvalId)
        || !safeText(payload.clientId)
        || !safeText(payload.serverId)
        || !safeText(payload.tool)
        || !safeText(payload.nonce, 200)
        || !Number.isSafeInteger(payload.iat)
        || !Number.isSafeInteger(payload.exp)
        || payload.iat > nowSeconds + 30
        || payload.exp <= nowSeconds
        || payload.exp <= payload.iat
        || payload.exp - payload.iat > this.maximumTtlSeconds
        || payload.clientId !== binding.clientId
        || payload.serverId !== binding.serverId
        || payload.tool !== binding.tool) {
      throw new ApprovalError("invalid_approval", "The approval token is invalid or expired");
    }
    const nonceKey = `${payload.approvalId}:${payload.nonce}`;
    const existingExpiry = this.nonces.get(nonceKey);
    if (existingExpiry && existingExpiry > nowSeconds) {
      throw new ApprovalError("approval_replayed", "The approval token was already used");
    }
    for (const [key, expiry] of this.nonces) {
      if (expiry <= nowSeconds) this.nonces.delete(key);
    }
    this.nonces.set(nonceKey, payload.exp);
    return {
      approvalId: payload.approvalId,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    };
  }
}
