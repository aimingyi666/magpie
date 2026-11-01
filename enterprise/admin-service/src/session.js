import { clientIp, ipMatches } from "./ip.js";
import {
  parseCookies,
  randomToken,
  safeEqual,
  sha256,
  signCookie,
  verifyCookie,
} from "./security.js";

export function cookieHeader(config, name, value, maxAge, options = {}) {
  const secure = config.secureCookie ? "; Secure" : "";
  const httpOnly = options.httpOnly === false ? "" : "; HttpOnly";
  const path = options.path || "/";
  return `${name}=${encodeURIComponent(value)}; Path=${path}${httpOnly}; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function requestAllowed(req, config) {
  const ip = clientIp(req);
  return config.allowedIps.some((rule) => ipMatches(rule, ip));
}

export function sessionCookie(req, config) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyCookie(cookies[config.sessionCookieName], config.sessionSecret);
}

export function csrfCookie(req, config) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyCookie(cookies[config.csrfCookieName], config.sessionSecret);
}

export function userAgentHash(req) {
  return sha256(String(req.headers["user-agent"] || ""));
}

export function newSession(identity, req, config) {
  const sid = `asess_${randomToken(32)}`;
  const csrfToken = randomToken(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + config.sessionTtlSeconds * 1000);
  return {
    sid,
    csrfToken,
    session: {
      subjectId: identity.id,
      subject: identity.subject,
      email: identity.email,
      name: identity.name,
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      ip: clientIp(req),
      userAgentHash: userAgentHash(req),
      csrfHash: sha256(csrfToken),
      revokedAt: "",
    },
  };
}

export function sessionState(session, req, config, now = Date.now()) {
  if (!session) return { ok: false, code: "not_signed_in" };
  if (session.revokedAt) return { ok: false, code: "session_revoked" };
  const expires = Date.parse(session.expiresAt);
  if (!Number.isFinite(expires) || expires <= now) return { ok: false, code: "session_expired" };
  const lastSeen = Date.parse(session.lastSeenAt);
  if (!Number.isFinite(lastSeen) || now - lastSeen > config.idleTimeoutSeconds * 1000) {
    return { ok: false, code: "session_idle" };
  }
  if (session.ip !== clientIp(req) || session.userAgentHash !== userAgentHash(req)) {
    return { ok: false, code: "session_binding_mismatch" };
  }
  return { ok: true };
}

export function validCsrf(session, token) {
  return Boolean(session?.csrfHash)
    && safeEqual(sha256(String(token || "")), session.csrfHash);
}
