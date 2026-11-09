// Verifying an id_token, checked against tokens this test signs itself with
// keys it also makes: an RSA key and an EC key, so both families the service
// takes are exercised, and every way a token can be wrong is refused.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { createKeySet, verifyIdToken, TokenError } from "../src/oidc.mjs";

const ISSUER = "https://sso.test.example";
const AUDIENCE = "magpie-corp";
const NONCE = "the-nonce-of-this-sign-in";

function base64url(value) {
  return Buffer.from(value).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jwkOf(key, kid, alg) {
  const jwk = key.export({ format: "jwk" });
  return { ...jwk, kid, alg, use: "sig" };
}

// sign makes a token: header + claims, signed with key by alg.
function sign({ key, kid, alg, claims, hash = "sha256", dsaEncoding }) {
  const header = base64url(JSON.stringify({ alg, kid, typ: "JWT" }));
  const body = base64url(JSON.stringify(claims));
  const signing = Buffer.from(`${header}.${body}`, "utf8");
  const signature = alg.startsWith("ES")
    ? crypto.sign(hash, signing, { key, dsaEncoding })
    : crypto.sign(hash, signing, key);
  return `${header}.${body}.${base64url(signature)}`;
}

function goodClaims(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER, aud: AUDIENCE, sub: "user-1", email: "unit@corp.example",
    name: "Unit", groups: ["engineering"], nonce: NONCE,
    iat: now - 10, exp: now + 300, ...overrides,
  };
}

const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsaJWK = jwkOf(rsa.publicKey, "rsa-1", "RS256");
const ecJWK = jwkOf(ec.publicKey, "ec-1", "ES256");

// a key set that answers from these, or fails, as a test says
function keysetFrom(keys, { fail = null, onFetch } = {}) {
  const fetchFn = async () => {
    onFetch?.();
    if (fail) throw fail;
    return { ok: true, status: 200, json: async () => ({ keys }) };
  };
  return createKeySet({ issuer: ISSUER, fetchFn, ttlMs: 0 });
}

const expected = { issuer: ISSUER, audience: AUDIENCE, nonce: NONCE, clockToleranceSeconds: 0 };

test("a token signed with the provider's RSA key is believed", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims() });
  const claims = await verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) });
  assert.equal(claims.email, "unit@corp.example");
});

test("a token signed with the provider's EC key is believed", async () => {
  const token = sign({ key: ec.privateKey, kid: "ec-1", alg: "ES256", claims: goodClaims(), dsaEncoding: "ieee-p1363" });
  const claims = await verifyIdToken(token, expected, { keySet: keysetFrom([ecJWK]) });
  assert.equal(claims.sub, "user-1");
});

test("a token signed with another key is refused", async () => {
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const token = sign({ key: other.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims() });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e instanceof TokenError && e.code === "id_token_signature",
  );
});

test("the payload being editable is why the signature matters", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims() });
  const [header, , signature] = token.split(".");
  const forged = base64url(JSON.stringify(goodClaims({ email: "admin@corp.example", groups: ["admin"] })));
  await assert.rejects(
    verifyIdToken(`${header}.${forged}.${signature}`, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_signature",
  );
});

test("the algorithm none is refused, not read as unsigned", async () => {
  const header = base64url(JSON.stringify({ alg: "none", kid: "rsa-1", typ: "JWT" }));
  const body = base64url(JSON.stringify(goodClaims()));
  await assert.rejects(
    verifyIdToken(`${header}.${body}.`, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_alg_unsupported",
  );
});

test("HS256 is refused: it is keyed by a secret, not a published key", async () => {
  const header = base64url(JSON.stringify({ alg: "HS256", kid: "rsa-1", typ: "JWT" }));
  const body = base64url(JSON.stringify(goodClaims()));
  const mac = crypto.createHmac("sha256", "the-client-secret").update(`${header}.${body}`).digest();
  await assert.rejects(
    verifyIdToken(`${header}.${body}.${base64url(mac)}`, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_alg_unsupported",
  );
});

test("a token from another issuer is refused", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims({ iss: "https://evil.example" }) });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_issuer",
  );
});

test("a token made for another service is refused", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims({ aud: "another-app" }) });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_audience",
  );
});

test("an expired token is refused", async () => {
  // the default clock tolerance is a minute, so this must be past it
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims({ exp: Math.floor(Date.now() / 1000) - 120 }) });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_expired",
  );
});

test("a token inside the clock tolerance is still taken", async () => {
  // a second or two past expiry, with a minute of tolerance: two clocks
  // that don't quite agree are not a reason to refuse a sign-in
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims({ exp: Math.floor(Date.now() / 1000) - 2 }) });
  const claims = await verifyIdToken(token, { ...expected, clockToleranceSeconds: 60 }, { keySet: keysetFrom([rsaJWK]) });
  assert.equal(claims.sub, "user-1");
});

test("a nonce for another sign-in is refused", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims({ nonce: "some-other-sign-in" }) });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_nonce",
  );
});

test("a token with no nonce is refused when one was asked for", async () => {
  const claims = goodClaims();
  delete claims.nonce;
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_nonce",
  );
});

test("a key id the provider doesn't publish is refused", async () => {
  const token = sign({ key: rsa.privateKey, kid: "nope", alg: "RS256", claims: goodClaims() });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_key_unknown",
  );
});

test("an unreachable provider is an error, not a token believed", async () => {
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims() });
  await assert.rejects(
    verifyIdToken(token, expected, { keySet: keysetFrom([], { fail: new Error("offline") }) }),
    (e) => e.code === "jwks_unreachable",
  );
});

test("an RSA key under an EC algorithm is refused", async () => {
  // the header says ES256 and names the RSA key: a token to distrust
  const header = base64url(JSON.stringify({ alg: "ES256", kid: "rsa-1", typ: "JWT" }));
  const body = base64url(JSON.stringify(goodClaims()));
  const signature = base64url(crypto.randomBytes(64));
  await assert.rejects(
    verifyIdToken(`${header}.${body}.${signature}`, expected, { keySet: keysetFrom([rsaJWK]) }),
    (e) => e.code === "id_token_key_mismatch",
  );
});

test("the keys are fetched once and kept, not on every sign-in", async () => {
  let fetches = 0;
  const set = keysetFrom([rsaJWK], { onFetch: () => {
    fetches += 1;
  } });
  // a set with a real ttl, unlike the others here
  const kept = createKeySet({
    issuer: ISSUER,
    fetchFn: async () => {
      fetches += 1;
      return { ok: true, status: 200, json: async () => ({ keys: [rsaJWK] }) };
    },
  });
  const token = sign({ key: rsa.privateKey, kid: "rsa-1", alg: "RS256", claims: goodClaims() });
  await verifyIdToken(token, expected, { keySet: kept });
  await verifyIdToken(token, expected, { keySet: kept });
  assert.equal(fetches, 1, "the second sign-in took the keys from memory");
  void set;
});
