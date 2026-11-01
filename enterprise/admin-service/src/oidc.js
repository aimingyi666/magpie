import { pkceChallenge, randomToken, verifyJwt } from "./security.js";

function endpoint(base, path) {
  return new URL(path, `${base.replace(/\/+$/, "")}/`).toString();
}

export class OidcClient {
  constructor(config) {
    this.config = config;
    this.discovery = null;
    this.jwks = null;
    this.jwksFetchedAt = 0;
  }

  async loadDiscovery() {
    if (this.discovery) return this.discovery;
    const response = await fetch(endpoint(this.config.issuer, ".well-known/openid-configuration"), {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`OIDC discovery returned HTTP ${response.status}`);
    const discovery = await response.json();
    if (discovery.issuer !== this.config.issuer) throw new Error("OIDC discovery issuer does not match");
    for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
      if (!discovery[field]) throw new Error(`OIDC discovery is missing ${field}`);
    }
    this.discovery = discovery;
    return discovery;
  }

  async loadJwks(force = false) {
    if (this.jwks && !force && Date.now() - this.jwksFetchedAt < 5 * 60 * 1000) return this.jwks;
    const discovery = await this.loadDiscovery();
    const response = await fetch(discovery.jwks_uri, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`OIDC JWKS returned HTTP ${response.status}`);
    this.jwks = await response.json();
    this.jwksFetchedAt = Date.now();
    return this.jwks;
  }

  async begin(options = {}) {
    const discovery = await this.loadDiscovery();
    const nonce = randomToken(24);
    const state = randomToken(24);
    const verifier = randomToken(48);
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("scope", this.config.scopes.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", pkceChallenge(verifier));
    url.searchParams.set("code_challenge_method", "S256");
    if (options.promptLogin) url.searchParams.set("prompt", "login");
    if (options.maxAgeSeconds != null) {
      url.searchParams.set("max_age", String(options.maxAgeSeconds));
    }
    const requestedClaims = {};
    if (this.config.allowedAcrValues?.length) {
      url.searchParams.set("acr_values", this.config.allowedAcrValues.join(" "));
      requestedClaims.acr = {
        essential: true,
        values: this.config.allowedAcrValues,
      };
    }
    if (options.requireAuthTime) {
      requestedClaims.auth_time = { essential: true };
    }
    if (Object.keys(requestedClaims).length > 0) {
      url.searchParams.set("claims", JSON.stringify({ id_token: requestedClaims }));
    }
    return {
      url: url.toString(),
      transaction: {
        state,
        nonce,
        verifier,
        createdAt: Date.now(),
      },
    };
  }

  async complete(code, transaction) {
    if (!code) throw new Error("OIDC callback has no code");
    if (!transaction || Date.now() - transaction.createdAt > 10 * 60 * 1000) {
      throw new Error("OIDC login transaction expired");
    }
    const discovery = await this.loadDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: transaction.verifier,
      client_id: this.config.clientId,
    });
    const headers = {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    };
    if (this.config.tokenAuthMethod === "client_secret_basic") {
      headers.authorization = `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64")}`;
    } else {
      body.set("client_secret", this.config.clientSecret);
    }
    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(15000),
    });
    const tokens = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`OIDC token exchange returned HTTP ${response.status}`);
    if (!tokens.id_token) throw new Error("OIDC token response has no id_token");

    let claims;
    try {
      claims = verifyJwt(tokens.id_token, await this.loadJwks(), {
        issuer: this.config.issuer,
        audience: this.config.clientId,
        nonce: transaction.nonce,
      });
    } catch {
      claims = verifyJwt(tokens.id_token, await this.loadJwks(true), {
        issuer: this.config.issuer,
        audience: this.config.clientId,
        nonce: transaction.nonce,
      });
    }
    return { claims, tokens };
  }
}

export function authenticationMethods(claims) {
  const raw = claims.amr;
  if (Array.isArray(raw)) return raw.map((value) => String(value).toLowerCase());
  if (typeof raw === "string") return raw.split(/[\s,]+/).filter(Boolean).map((value) => value.toLowerCase());
  return [];
}

function strongAuthentication(claims) {
  const methods = authenticationMethods(claims);
  const acr = String(claims.acr || "");
  return methods.some((method) => ["mfa", "otp", "hwk", "swk"].includes(method))
    || acr.toLowerCase().includes("mfa");
}

export function validateStepUpAuthentication(claims, config, now = Date.now()) {
  const authTime = Number(claims?.auth_time);
  const nowSeconds = Math.floor(now / 1000);
  if (!Number.isSafeInteger(authTime) || authTime <= 0) {
    throw new Error("step-up authentication has no valid auth_time");
  }
  if (authTime > nowSeconds + 30) {
    throw new Error("step-up auth_time is in the future");
  }
  if (nowSeconds - authTime > config.authTimeMaxAgeSeconds) {
    throw new Error("step-up authentication is not fresh");
  }
  const acr = String(claims.acr || "");
  if (config.allowedAcrValues?.length) {
    if (!config.allowedAcrValues.includes(acr)) {
      throw new Error("step-up authentication context is not allowed");
    }
  } else if (!strongAuthentication(claims)) {
    throw new Error("step-up authentication did not use multi-factor authentication");
  }
  return {
    acr,
    amr: authenticationMethods(claims),
    authTime,
  };
}

export function normalizeAdminIdentity(claims, config) {
  const subject = String(claims.sub || "").trim();
  const email = String(claims[config.emailClaim] || claims.email || "").trim().toLowerCase();
  const name = String(claims[config.nameClaim] || claims.name || email || subject).trim();
  if (!subject) throw new Error("OIDC identity has no sub claim");
  if (!email) throw new Error("OIDC identity has no email claim");
  if (name.length > 200) throw new Error("OIDC name claim is too long");

  if (config.allowedEmailDomains.length > 0) {
    const domain = email.split("@").pop();
    if (!config.allowedEmailDomains.includes(domain)) {
      const error = new Error("This email domain is not allowed for the management console");
      error.statusCode = 403;
      error.code = "email_domain_not_allowed";
      throw error;
    }
  }

  if (config.requireVerifiedEmail && claims.email_verified !== true) {
    const error = new Error("The management console requires a verified email address");
    error.statusCode = 403;
    error.code = "email_not_verified";
    throw error;
  }

  if (config.allowedAcrValues.length > 0) {
    if (!config.allowedAcrValues.includes(String(claims.acr || ""))) {
      const error = new Error("The management console requires an approved authentication context");
      error.statusCode = 403;
      error.code = "mfa_required";
      throw error;
    }
  } else if (config.requireMfa) {
    if (!strongAuthentication(claims)) {
      const error = new Error("The management console requires multi-factor authentication");
      error.statusCode = 403;
      error.code = "mfa_required";
      throw error;
    }
  }

  return { subject, email, name };
}
