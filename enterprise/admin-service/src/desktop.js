// Desktop administrator sign-in.
//
// The native Magpie page can't hold an OIDC secret or a management cookie,
// so the browser does the sign-in and hands the desktop a one-time ticket
// over a loopback redirect. The desktop then exchanges ticket + its own
// PKCE verifier for a short-lived bearer token held in that machine's
// process memory.
//
// The token is not a management session: it has its own store, its own
// expiry (8 hours at most, 30 idle minutes) and no CSRF cookie, because a
// bearer token in a header is not sent by a browser on its own.

import crypto from "node:crypto";
import { randomToken, sha256 } from "./security.js";

export const DESKTOP_PERMISSION_PREFIX = "desktop.";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

// desktopCallbackUrl accepts only a loopback http callback, and only the
// path this project's plugin serves: a ticket put in any other place is a
// ticket someone else can read.
export function desktopCallbackUrl(raw, config) {
  let url;
  try {
    url = new URL(String(raw || "").trim());
  } catch {
    return { error: "invalid_callback", message: "callbackUrl must be an absolute URL" };
  }
  if (url.protocol !== "http:") {
    return { error: "invalid_callback", message: "callbackUrl must use http on loopback" };
  }
  const host = url.hostname.toLowerCase();
  if (!LOOPBACK_HOSTS.has(host)) {
    return { error: "invalid_callback", message: "callbackUrl must be on loopback" };
  }
  const allowedHosts = config.allowedCallbackHosts || [];
  if (allowedHosts.length > 0 && !allowedHosts.includes(host)) {
    return { error: "invalid_callback", message: "callbackUrl host is not allowed" };
  }
  if (url.username || url.password || url.search || url.hash) {
    return { error: "invalid_callback", message: "callbackUrl must not carry credentials, a query or a fragment" };
  }
  if (url.pathname !== "/v1/admin/login/callback") {
    return { error: "invalid_callback", message: "callbackUrl path is not the enterprise plugin's" };
  }
  if (config.allowedCallbackPorts?.length && !config.allowedCallbackPorts.includes(Number(url.port))) {
    return { error: "invalid_callback", message: "callbackUrl port is not allowed" };
  }
  return { url };
}

// desktopPkce is the challenge the desktop sends with the login and the
// verifier it later proves the token request with. It is written into the
// stored transaction, never the URL.
export function desktopPkce() {
  const verifier = randomToken(48);
  return {
    verifier,
    challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
  };
}

export function newDesktopTicket(transaction, identity, now = Date.now()) {
  const ticket = randomToken(32);
  return {
    ticket,
    hash: sha256(ticket),
    record: {
      state: transaction.state,
      nonce: transaction.nonce,
      challenge: transaction.challenge,
      callbackUrl: transaction.callbackUrl,
      subjectId: identity.id,
      subject: identity.subject,
      email: identity.email,
      name: identity.name,
      // The sign-in's own authentication context, when the provider gave
      // one. It becomes the desktop token's step-up assertion, so a token
      // minted by a sign-in that proved MFA can make medium-risk writes
      // without another browser round-trip. Absent means "no step-up":
      // those writes are refused rather than assumed.
      stepUp: transaction.stepUp || null,
      stepUpError: String(transaction.stepUpError || ""),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + transaction.ticketTtlSeconds * 1000).toISOString(),
      consumedAt: "",
    },
  };
}

export function desktopTicketState(record, now = Date.now()) {
  if (!record) return { ok: false, code: "desktop_ticket_invalid" };
  if (record.consumedAt) return { ok: false, code: "desktop_ticket_consumed" };
  const expires = Date.parse(record.expiresAt);
  if (!Number.isFinite(expires) || expires <= now) {
    return { ok: false, code: "desktop_ticket_expired" };
  }
  return { ok: true };
}

// newDesktopToken makes the bearer token and what is kept of it: a hash,
// never the token. It follows the management session's expiry rules so a
// desktop cannot outlive a browser console.
export function newDesktopToken(ticket, config, now = Date.now()) {
  const token = `adm_desktop_${randomToken(38)}`;
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + config.tokenTtlSeconds * 1000).toISOString();
  return {
    token,
    hash: sha256(token),
    record: {
      subjectId: ticket.subjectId,
      subject: ticket.subject,
      email: ticket.email,
      name: ticket.name,
      createdAt,
      lastSeenAt: createdAt,
      expiresAt,
      idleTimeoutSeconds: config.idleTimeoutSeconds,
      idempotencySafe: true,
      origin: "desktop",
      stepUp: ticket.stepUp || null,
      revokedAt: "",
    },
  };
}

export function desktopTokenState(record, config, now = Date.now()) {
  if (!record) return { ok: false, code: "desktop_token_invalid" };
  if (record.revokedAt) return { ok: false, code: "desktop_token_revoked" };
  const expires = Date.parse(record.expiresAt);
  if (!Number.isFinite(expires) || expires <= now) {
    return { ok: false, code: "desktop_token_expired" };
  }
  const lastSeen = Date.parse(record.lastSeenAt);
  const idle = Number.isFinite(record.idleTimeoutSeconds)
    ? record.idleTimeoutSeconds
    : config.idleTimeoutSeconds;
  if (!Number.isFinite(lastSeen) || now - lastSeen > idle * 1000) {
    return { ok: false, code: "desktop_token_idle" };
  }
  return { ok: true };
}

// bearerToken reads "Authorization: Bearer …". Anything else is no token.
export function bearerToken(req) {
  const value = String(req.headers.authorization || "").trim();
  const match = /^Bearer ([A-Za-z0-9_.-]{20,512})$/.exec(value);
  return match ? match[1] : "";
}

export function isDesktopRequest(req) {
  return Boolean(bearerToken(req));
}

export { LOOPBACK_HOSTS, plainObject };
