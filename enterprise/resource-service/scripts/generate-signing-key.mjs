import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const output = path.resolve(process.argv[2] || "");
if (!process.argv[2]) {
  console.error("usage: node scripts/generate-signing-key.mjs <private-key-output.pem>");
  process.exit(2);
}

const publicOutput = `${output}.pub.pem`;
fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicPem = publicKey.export({ type: "spki", format: "pem" });

try {
  fs.writeFileSync(output, privatePem, { flag: "wx", mode: 0o600 });
} catch (error) {
  if (error.code === "EEXIST") {
    console.error("refusing to overwrite an existing signing key");
    process.exit(1);
  }
  throw error;
}

try {
  fs.writeFileSync(publicOutput, publicPem, { flag: "wx", mode: 0o644 });
} catch (error) {
  fs.rmSync(output, { force: true });
  throw error;
}

const der = publicKey.export({ type: "spki", format: "der" });
const fingerprint = crypto.createHash("sha256").update(der).digest("hex");
console.log(JSON.stringify({
  privateKey: output,
  publicKey: publicOutput,
  fingerprint: `sha256:${fingerprint}`,
}, null, 2));
