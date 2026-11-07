// A tiny development OIDC provider for the local enterprise stack.
//
// It is NOT an identity system: it signs in as a fixed account per client
// and approves every request. It exists so the management console's login
// and the employee portal's OIDC flow can be exercised on one machine.
// Never expose it beyond 127.0.0.1.

import crypto from "node:crypto";
import http from "node:http";

const PORT = Number(process.env.DEV_OIDC_PORT || 3999);
const ISSUER = `http://127.0.0.1:${PORT}`;
const KEY_ID = "dev-oidc-key";

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: KEY_ID, use: "sig", alg: "RS256" };

// Which fixed person a client is. The admin console's own client is the
// administrator; the employee login client is an employee.
function identityFor(clientId) {
  const admin = String(clientId || "").includes("admin");
  return admin
    ? { sub: "dev-admin", email: "admin@corp.example", name: "Dev Admin" }
    : { sub: "dev-employee", email: "employee@corp.example", name: "Dev Employee" };
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signJwt(claims) {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KEY_ID }));
  const payload = base64url(JSON.stringify(claims));
  const signature = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey);
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

const codes = new Map(); // code -> entry
const tokens = new Map(); // access token -> { claims, expiresAt }

function json(res, status, value) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}

function html(res, status, text) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  res.end(text);
}

async function readForm(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function pkceMatches(verifier, challenge) {
  if (!verifier || !challenge) return false;
  return crypto.createHash("sha256").update(verifier).digest("base64url") === challenge;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", ISSUER);

  if (url.pathname === "/.well-known/openid-configuration") {
    return json(res, 200, {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      end_session_endpoint: `${ISSUER}/logout`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      claims_supported: ["sub", "email", "email_verified", "name", "acr", "amr", "auth_time"],
    });
  }

  if (url.pathname === "/jwks") {
    return json(res, 200, { keys: [jwk] });
  }

  if (url.pathname === "/authorize" && req.method === "GET") {
    const clientId = String(url.searchParams.get("client_id") || "");
    const redirectUri = String(url.searchParams.get("redirect_uri") || "");
    const state = String(url.searchParams.get("state") || "");
    const nonce = String(url.searchParams.get("nonce") || "");
    const challenge = String(url.searchParams.get("code_challenge") || "");
    const method = String(url.searchParams.get("code_challenge_method") || "").toUpperCase();
    if (!clientId || !redirectUri) return html(res, 400, "client_id and redirect_uri are required");
    let target;
    try {
      target = new URL(redirectUri);
    } catch {
      return html(res, 400, "redirect_uri is not a URL");
    }
    if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(target.hostname.toLowerCase())) {
      return html(res, 400, "this dev provider only redirects to loopback");
    }
    if (challenge && method && method !== "S256") {
      return html(res, 400, "only S256 PKCE is supported");
    }
    const code = crypto.randomBytes(24).toString("base64url");
    codes.set(code, {
      clientId,
      redirectUri,
      nonce,
      challenge,
      identity: identityFor(clientId),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    target.searchParams.set("code", code);
    if (state) target.searchParams.set("state", state);
    res.writeHead(302, { location: target.toString(), "cache-control": "no-store" });
    res.end();
    return;
  }

  if (url.pathname === "/token" && req.method === "POST") {
    const form = await readForm(req);
    if (form.get("grant_type") !== "authorization_code") {
      return json(res, 400, { error: "unsupported_grant_type" });
    }
    const entry = codes.get(String(form.get("code") || ""));
    if (!entry || entry.expiresAt <= Date.now()) {
      return json(res, 400, { error: "invalid_grant" });
    }
    codes.delete(String(form.get("code") || ""));
    if (String(form.get("redirect_uri") || "") !== entry.redirectUri) {
      return json(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
    }
    if (entry.challenge && !pkceMatches(String(form.get("code_verifier") || ""), entry.challenge)) {
      return json(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
    }
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: ISSUER,
      aud: entry.clientId,
      sub: entry.identity.sub,
      email: entry.identity.email,
      email_verified: true,
      name: entry.identity.name,
      ...(entry.nonce ? { nonce: entry.nonce } : {}),
      iat: now,
      exp: now + 3600,
      auth_time: now,
      acr: "urn:dev:acr:mfa",
      amr: ["pwd", "mfa"],
    };
    const accessToken = crypto.randomBytes(24).toString("base64url");
    tokens.set(accessToken, { claims, expiresAt: now + 3600 });
    return json(res, 200, {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      id_token: signJwt(claims),
    });
  }

  if (url.pathname === "/userinfo") {
    const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const entry = tokens.get(token);
    if (!entry || entry.expiresAt <= Math.floor(Date.now() / 1000)) {
      return json(res, 401, { error: "invalid_token" });
    }
    return json(res, 200, {
      sub: entry.claims.sub,
      email: entry.claims.email,
      email_verified: true,
      name: entry.claims.name,
    });
  }

  if (url.pathname === "/logout") {
    res.writeHead(302, { location: String(url.searchParams.get("post_logout_redirect_uri") || "/") });
    res.end();
    return;
  }

  if (url.pathname === "/healthz") {
    return json(res, 200, { ok: true, service: "dev-oidc", issuer: ISSUER });
  }

  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`dev OIDC on ${ISSUER}`);
});
