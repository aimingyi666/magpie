// Minimal OIDC provider for the enterprise auth M1 end-to-end test.
// It signs a real RS256 id_token, but only for the fixed employee in env.
import crypto from "node:crypto";
import http from "node:http";

const port = Number(process.env.PORT || 3731);
const clientId = process.env.CLIENT_ID || "magpie-enterprise-e2e";
const clientSecret = process.env.CLIENT_SECRET || "";
const employeeSub = process.env.EMPLOYEE_SUB || "employee-alice";
const employeeEmail = process.env.EMPLOYEE_EMAIL || "alice@corp.example";
const employeeName = process.env.EMPLOYEE_NAME || "Alice Zhang";

if (!clientSecret) throw new Error("CLIENT_SECRET is required");

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = publicKey.export({ format: "jwk" });
jwk.kid = "enterprise-e2e-key";
jwk.use = "sig";
jwk.alg = "RS256";

const codes = new Map();
let base = `http://127.0.0.1:${port}`;

function token(claims) {
  const header = Buffer.from(JSON.stringify({
    alg: "RS256",
    typ: "JWT",
    kid: jwk.kid,
  })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.sign(
    "RSA-SHA256",
    Buffer.from(`${header}.${payload}`),
    privateKey,
  ).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

function challenge(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, base);
  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/jwks`,
    }));
    return;
  }

  if (req.method === "GET" && url.pathname === "/jwks") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [jwk] }));
    return;
  }

  if (req.method === "GET" && url.pathname === "/authorize") {
    const redirectUri = url.searchParams.get("redirect_uri");
    if (!redirectUri) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "missing_redirect_uri" }));
      return;
    }
    const code = `oidc_${crypto.randomBytes(24).toString("base64url")}`;
    codes.set(code, {
      redirectUri,
      nonce: url.searchParams.get("nonce"),
      codeChallenge: url.searchParams.get("code_challenge"),
      createdAt: Date.now(),
    });
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    target.searchParams.set("state", url.searchParams.get("state") || "");
    res.writeHead(302, { location: target.toString() });
    res.end();
    return;
  }

  if (req.method === "POST" && url.pathname === "/token") {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const form = new URLSearchParams(raw);
    const basic = /^Basic\s+(.+)$/i.exec(String(req.headers.authorization || ""));
    const supplied = basic ? Buffer.from(basic[1], "base64").toString("utf8") : "";
    const code = codes.get(form.get("code"));
    const verifier = form.get("code_verifier") || "";
    const pkceOk = code
      && code.codeChallenge
      && challenge(verifier) === code.codeChallenge
      && Date.now() - code.createdAt <= 60000;
    if (!code || !pkceOk || supplied !== `${clientId}:${clientSecret}`) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }
    codes.delete(form.get("code"));
    const now = Math.floor(Date.now() / 1000);
    const idToken = token({
      iss: base,
      aud: clientId,
      sub: employeeSub,
      email: employeeEmail,
      name: employeeName,
      nonce: code.nonce,
      iat: now,
      exp: now + 300,
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      access_token: "mock-access-token",
      token_type: "Bearer",
      expires_in: 300,
      id_token: idToken,
    }));
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`mock OIDC on 127.0.0.1:${port}`);
});
