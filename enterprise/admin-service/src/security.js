import crypto from "node:crypto";

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function fromBase64url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

export function pkceChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function signCookie(value, secret) {
  const payload = base64url(value);
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function verifyCookie(signed, secret) {
  if (!signed || !signed.includes(".")) return "";
  const [payload, signature] = signed.split(".", 2);
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  if (!safeEqual(signature, expected)) return "";
  try {
    return fromBase64url(payload);
  } catch {
    return "";
  }
}

export function parseCookies(header) {
  const out = Object.create(null);
  for (const part of String(header || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

function jwtAlgorithmName(alg) {
  const names = {
    RS256: "RSA-SHA256",
    PS256: "sha256",
    ES256: "sha256",
  };
  const name = names[alg];
  if (!name) throw new Error(`unsupported JWT algorithm ${alg}`);
  return name;
}

export function verifyJwt(token, jwks, options = {}) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("id_token is not a JWT");
  const [header64, payload64, signature64] = parts;
  const header = JSON.parse(fromBase64url(header64));
  const claims = JSON.parse(fromBase64url(payload64));
  const allowed = options.algorithms || ["RS256", "PS256", "ES256"];
  if (!allowed.includes(header.alg)) throw new Error(`id_token algorithm ${header.alg} is not allowed`);

  const candidates = (jwks.keys || []).filter((key) => {
    if (key.use && key.use !== "sig") return false;
    if (header.kid) return key.kid === header.kid;
    return key.kty === "RSA" || key.kty === "EC";
  });
  if (candidates.length === 0) throw new Error("no JWKS key matches the id_token");

  const signed = Buffer.from(`${header64}.${payload64}`);
  const signature = Buffer.from(signature64, "base64url");
  let verified = false;
  for (const jwk of candidates) {
    try {
      const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
      const verifier = crypto.createVerify(jwtAlgorithmName(header.alg));
      verifier.update(signed);
      verifier.end();
      if (header.alg === "RS256") {
        verified = verifier.verify(key, signature);
      } else if (header.alg === "PS256") {
        verified = verifier.verify(
          { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
          signature,
        );
      } else {
        verified = verifier.verify({ key, dsaEncoding: "ieee-p1363" }, signature);
      }
      if (verified) break;
    } catch {
      // Try the next matching key.
    }
  }
  if (!verified) throw new Error("id_token signature is invalid");

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== options.issuer) throw new Error("id_token issuer does not match");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(options.audience)) throw new Error("id_token audience does not match");
  if (audiences.length > 1 && claims.azp && claims.azp !== options.audience) {
    throw new Error("id_token authorized party does not match");
  }
  if (!Number.isFinite(claims.exp) || claims.exp <= now - 30) throw new Error("id_token is expired");
  if (Number.isFinite(claims.nbf) && claims.nbf > now + 30) throw new Error("id_token is not active yet");
  if (options.nonce && claims.nonce !== options.nonce) throw new Error("id_token nonce does not match");
  return claims;
}
