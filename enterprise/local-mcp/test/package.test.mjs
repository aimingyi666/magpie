import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  LocalMcpError,
  assertSafePackagePath,
  buildSignedPackage,
  canonicalJson,
  verifySignedPackage,
} from "../src/index.js";
import {
  KEY_ID,
  MCP_SERVER_SOURCE,
  createHost,
  createIdentity,
  createPackage,
  packageFields,
  temporaryRoot,
} from "./helpers.mjs";

test("signed packages verify their canonical manifest and file table", () => {
  const identity = createIdentity();
  const signed = createPackage(identity, {
    permissions: { capabilities: ["fs.read"], networkHosts: [] },
    tools: [{
      name: "echo",
      description: "Read-only echo",
      risk: "low",
      capabilities: ["fs.read"],
    }],
  });

  const verified = verifySignedPackage(identity.publicKey, signed);
  assert.equal(verified.manifest.packageId, "local-echo");
  assert.equal(verified.manifest.signingKeyId, KEY_ID);
  assert.equal(verified.manifest.packageDigest, signed.manifest.packageDigest);
  assert.match(verified.manifest.signature, /^base64:[A-Za-z0-9+/]+={0,2}$/);
  assert.equal(verified.files.get("server.mjs").toString("utf8"), MCP_SERVER_SOURCE);
  assert.equal(canonicalJson({ z: 1, a: { d: 2, b: 3 } }), '{"a":{"b":3,"d":2},"z":1}');
});

test("file and signature tampering are rejected", () => {
  const identity = createIdentity();
  const signed = structuredClone(createPackage(identity));
  const original = Buffer.from(signed.files["server.mjs"].slice(7), "base64");
  const changed = Buffer.from(original);
  changed[changed.length - 2] ^= 1;
  signed.files["server.mjs"] = `base64:${changed.toString("base64")}`;
  assert.throws(
    () => verifySignedPackage(identity.publicKey, signed),
    (error) => error instanceof LocalMcpError && error.code === "package_tampered",
  );

  const manifestTamper = structuredClone(createPackage(identity));
  manifestTamper.manifest.publisher = "other-publisher";
  assert.throws(
    () => verifySignedPackage(identity.publicKey, manifestTamper),
    (error) => error instanceof LocalMcpError && error.code === "package_tampered",
  );

  const other = createIdentity();
  assert.throws(
    () => verifySignedPackage(other.publicKey, createPackage(identity)),
    (error) => error instanceof LocalMcpError && error.code === "signature_invalid",
  );
});

test("unsafe, duplicate and Windows-reserved package paths are rejected", () => {
  const identity = createIdentity();
  for (const unsafe of ["../escape.mjs", "dir\\file.mjs", "/absolute.mjs", "CON.js", "dir/name. "]) {
    assert.throws(
      () => assertSafePackagePath(unsafe),
      (error) => error instanceof LocalMcpError && error.code === "path_traversal",
    );
  }
  assert.throws(
    () => buildSignedPackage(
      packageFields(),
      { "A.js": "one", "a.js": "two" },
      identity.privateKey,
    ),
    (error) => error instanceof LocalMcpError && error.code === "duplicate_file",
  );
});

test("unknown keys and pinned fingerprint mismatches fail before execution", async (t) => {
  const identity = createIdentity();
  const root = temporaryRoot(t);
  const unknownHost = createHost(identity, root, {
    publicKeys: { "different-key": identity.publicKeys[KEY_ID] },
  });
  await assert.rejects(
    unknownHost.install(createPackage(identity)),
    (error) => error instanceof LocalMcpError && error.code === "key_unknown",
  );

  assert.throws(
    () => createHost(identity, root, {
      keyFingerprints: {
        [KEY_ID]: `sha256:${crypto.randomBytes(32).toString("hex")}`,
      },
    }),
    (error) => error instanceof LocalMcpError && error.code === "invalid_config",
  );
});
