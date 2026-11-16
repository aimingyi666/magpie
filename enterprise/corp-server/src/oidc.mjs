// Verifying an OIDC id_token against the provider's keys.
//
// An id_token is a JWS: a header naming the algorithm and key id, a payload
// of claims, and a signature. Anyone can make one, so a service that trusts
// the payload without checking the signature trusts whoever sent it. This
// fetches the provider's published keys, checks the signature with the one
// the header names, and checks the claims that say who the token is about
// and that it was made for this sign-in.
//
// The algorithms a sign-in can use are the asymmetric ones: RSA (RS256,
// RS384, RS512) and ECDSA (ES256, ES384, ES512). HS* is symmetric, keyed by
// the client secret, and EdDSA needs a key type Node reads differently, so
// neither is taken here; a provider that offers only those is a provider
// this service has to be taught, not a token it should guess at.
import crypto from "node:crypto";

const ALGORITHMS = {
  RS256: { kind: "rsa", hash: "sha256" },
  RS384: { kind: "rsa", hash: "sha384" },
  RS512: { kind: "rsa", hash: "sha512" },
  ES256: { kind: "ec", hash: "sha256", crv: "P-256", dsaEncoding: "ieee-p1363" },
  ES384: { kind: "ec", hash: "sha384", crv: "P-384", dsaEncoding: "ieee-p1363" },
  ES512: { kind: "ec", hash: "sha512", crv: "P-521", dsaEncoding: "ieee-p1363" },
};

export class TokenError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TokenError";
    this.code = code;
  }
}

function b64url(value) {
  return Buffer.from(String(value).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function decodeJSON(part, what) {
  try {
    return JSON.parse(b64url(part).toString("utf8"));
  } catch {
    throw new TokenError("id_token_malformed", `the id_token's ${what} is not JSON`);
  }
}

// ---- the provider's keys --------------------------------------------------

// jwks is fetched once and kept for a while: a sign-in must not cost a
// round trip to the provider every time. A kid this cache doesn't hold
// asks once more, since a provider rotates keys and the first a service
// sees may be the one after the list it kept.
export function createKeySet({ issuer, fetchFn = fetch, now = Date.now, ttlMs = 60 * 60 * 1000 } = {}) {
  let keys = null;
  let fetchedAt = 0;
  let pending = null;

  async function load(force = false) {
    if (!force && keys && now() - fetchedAt < ttlMs) return keys;
    if (pending) return pending;
    pending = (async () => {
      let response;
      try {
        response = await fetchFn(new URL("/.well-known/jwks.json", issuer), {
          headers: { accept: "application/json" },
          redirect: "error",
          signal: AbortSignal.timeout(10000),
        });
      } catch (error) {
        throw new TokenError("jwks_unreachable", `the identity provider's keys are unreachable: ${error?.message || error}`);
      }
      if (!response.ok) {
        throw new TokenError("jwks_unreachable", `the identity provider answered ${response.status} for its keys`);
      }
      const body = await response.json().catch(() => null);
      if (!body || !Array.isArray(body.keys) || body.keys.length === 0) {
        throw new TokenError("jwks_empty", "the identity provider published no keys");
      }
      keys = body.keys;
      fetchedAt = now();
      return keys;
    })().finally(() => {
      pending = null;
    });
    return pending;
  }

  return {
    async find(kid) {
      let found = (await load()).find((k) => k.kid === kid);
      if (!found) found = (await load(true)).find((k) => k.kid === kid);
      return found || null;
    },
  };
}

// keyOf turns a JWK into the key Node verifies with, of the algorithm the
// token names. A key whose type doesn't match the algorithm is refused
// rather than tried: an RSA key under ES256 is a token to distrust.
function keyOf(jwk, alg) {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new TokenError("id_token_alg_unsupported", `the id_token's algorithm ${alg} is not one this service verifies`);
  if (jwk.kty !== (spec.kind === "rsa" ? "RSA" : "EC")) {
    throw new TokenError("id_token_key_mismatch", `the id_token's algorithm ${alg} does not fit its key type ${jwk.kty}`);
  }
  if (spec.crv && jwk.crv !== spec.crv) {
    throw new TokenError("id_token_key_mismatch", `${alg} needs a ${spec.crv} key, the token's is ${jwk.crv}`);
  }
  try {
    return spec.kind === "rsa" ? crypto.createPublicKey({ key: jwk, format: "jwk" }) : crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (error) {
    throw new TokenError("id_token_key_invalid", `the identity provider's key ${jwk.kid} can't be read: ${error?.message || error}`);
  }
}

// ---- verifying one token --------------------------------------------------

// verifyIdToken answers the claims of token, once its signature is proved
// and its claims say it is this service's, for this sign-in, now.
//
// expected: { issuer, audience, nonce, clockToleranceSeconds }
export async function verifyIdToken(token, expected, { keySet, now = Date.now, clockToleranceSeconds = 60 } = {}) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new TokenError("id_token_malformed", "an id_token has three parts");

  const header = decodeJSON(parts[0], "header");
  const alg = String(header.alg || "");
  const spec = ALGORITHMS[alg];
  if (!spec) throw new TokenError("id_token_alg_unsupported", `the id_token's algorithm ${alg || "(none)"} is not one this service verifies`);
  if (header.crit) throw new TokenError("id_token_crit", "the id_token names critical parameters this service doesn't handle");

  const jwk = await keySet.find(String(header.kid || ""));
  if (!jwk) throw new TokenError("id_token_key_unknown", `no key ${header.kid || "(none)"} is published by the identity provider`);

  const key = keyOf(jwk, alg);
  const signing = Buffer.from(`${parts[0]}.${parts[1]}`, "utf8");
  const signature = b64url(parts[2]);
  const verified = crypto.verify(
    spec.hash,
    signing,
    spec.kind === "rsa" ? key : { key, dsaEncoding: spec.dsaEncoding },
    signature,
  );
  if (!verified) throw new TokenError("id_token_signature", "the id_token's signature does not match the identity provider's key");

  const claims = decodeJSON(parts[1], "payload");

  // who it is about, and who it was made for
  if (expected.issuer && claims.iss !== expected.issuer) {
    throw new TokenError("id_token_issuer", `the id_token is from ${claims.iss}, not ${expected.issuer}`);
  }
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (expected.audience && !audience.includes(expected.audience)) {
    throw new TokenError("id_token_audience", "the id_token was not made for this service");
  }
  // an azp, when there is one, says which of several audiences asked
  if (claims.azp && expected.audience && claims.azp !== expected.audience) {
    throw new TokenError("id_token_authorized_party", `the id_token was authorized for ${claims.azp}`);
  }

  // now, within a small tolerance for two clocks that don't agree
  const skew = Math.max(0, Number(clockToleranceSeconds) || 0) * 1000;
  const at = now();
  if (typeof claims.exp !== "number") throw new TokenError("id_token_no_expiry", "the id_token has no expiry");
  if (claims.exp * 1000 + skew < at) throw new TokenError("id_token_expired", "the id_token has expired");
  if (typeof claims.iat === "number" && claims.iat * 1000 - skew > at) {
    throw new TokenError("id_token_not_yet", "the id_token was made in the future");
  }
  if (typeof claims.nbf === "number" && claims.nbf * 1000 - skew > at) {
    throw new TokenError("id_token_not_yet", "the id_token is not valid yet");
  }

  // the nonce the sign-in started with: without it, a token made for one
  // sign-in could be replayed into another
  if (expected.nonce !== undefined) {
    if (typeof claims.nonce !== "string" || claims.nonce !== expected.nonce) {
      throw new TokenError("id_token_nonce", "the id_token answers a sign-in that isn't this one");
    }
  }

  return claims;
}
