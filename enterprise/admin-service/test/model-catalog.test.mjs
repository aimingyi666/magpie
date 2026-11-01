import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  legacyModelCatalog,
  loadModelCatalog,
  MAX_MODEL_CATALOG_BYTES,
  modelCatalogStartupAudit,
  publicModelCatalog,
} from "../src/model-catalog.js";

function validCatalog() {
  return {
    schemaVersion: 1,
    models: [
      {
        id: "openai/gpt-5.2",
        provider: "openai",
        displayName: "GPT-5.2",
      },
      {
        id: "anthropic/claude-sonnet-5",
        provider: "anthropic",
        displayName: "Claude Sonnet 5",
      },
    ],
    providerWildcards: ["company-model"],
    groups: {
      "engineering-approved": [
        "openai/gpt-5.2",
        "anthropic/claude-sonnet-5",
      ],
    },
  };
}

async function withTempDir(fn) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-model-catalog-"));
  try {
    return await fn(directory);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

async function loadValue(value, options = {}) {
  return withTempDir(async (directory) => {
    const filePath = path.join(directory, "catalog.json");
    await fs.writeFile(filePath, options.raw ?? JSON.stringify(value), "utf8");
    return loadModelCatalog({ filePath, expectedDigest: options.expectedDigest });
  });
}

async function expectCode(operation, code) {
  await assert.rejects(async () => operation(), (error) => {
    assert.equal(error.code, code);
    return true;
  });
}

test("model catalog loads schema v1, exposes safe status, and expands groups once", async () => {
  await withTempDir(async (directory) => {
    const filePath = path.join(directory, "catalog.json");
    const source = JSON.stringify(validCatalog());
    const digest = `sha256:${crypto.createHash("sha256").update(source).digest("hex")}`;
    await fs.writeFile(filePath, source, "utf8");

    const catalog = await loadModelCatalog({ filePath, expectedDigest: digest });
    assert.equal(catalog.status.source, "file");
    assert.equal(catalog.status.authorizationReady, true);
    assert.equal(catalog.status.catalogVersion, 1);
    assert.equal(catalog.status.catalogDigest, digest);
    assert.equal(catalog.status.modelCount, 2);
    assert.equal(catalog.status.groupCount, 1);
    assert.equal(catalog.status.providerWildcardCount, 1);
    assert.ok(catalog.status.loadedAt);

    assert.deepEqual(
      catalog.expandSelectors([
        "group/engineering-approved",
        "openai/gpt-5.2",
        "company-model/*",
      ]),
      ["openai/gpt-5.2", "anthropic/claude-sonnet-5", "company-model/*"],
    );
    assert.deepEqual(
      catalog.expandSelectors(["group/engineering-approved"]),
      ["openai/gpt-5.2", "anthropic/claude-sonnet-5"],
    );

    const publicValue = publicModelCatalog(catalog);
    assert.deepEqual(publicValue.models, [
      { id: "openai/gpt-5.2" },
      { id: "anthropic/claude-sonnet-5" },
    ]);
    assert.deepEqual(publicValue.providerWildcards, ["company-model"]);
    assert.deepEqual(publicValue.groups, [{
      name: "engineering-approved",
      models: ["openai/gpt-5.2", "anthropic/claude-sonnet-5"],
    }]);
    assert.equal(publicValue.catalog.source, "file");
    assert.ok(!JSON.stringify(publicValue).includes(directory));

    const audit = modelCatalogStartupAudit(catalog);
    assert.equal(audit.action, "model_catalog.load");
    assert.equal(audit.result, "succeeded");
    assert.equal(audit.catalogVersion, 1);
    assert.equal(audit.catalogDigest, digest);
    assert.ok(!JSON.stringify(audit).includes(directory));
  });
});

test("model catalog fails closed for unavailable, malformed, and trailing JSON", async () => {
  await expectCode(
    () => loadModelCatalog({ filePath: path.join(os.tmpdir(), "missing-magpie-catalog.json") }),
    "model_catalog_unavailable",
  );

  await withTempDir(async (directory) => {
    const asDirectory = path.join(directory, "catalog");
    await fs.mkdir(asDirectory);
    await expectCode(
      () => loadModelCatalog({ filePath: asDirectory }),
      "model_catalog_unavailable",
    );
  });

  await expectCode(
    () => loadValue(null, { raw: "{\"schemaVersion\":1,\"models\":[" }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue(null, { raw: `${JSON.stringify(validCatalog())} trailing` }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue(null, { raw: "{\"schemaVersion\":1,\"schemaVersion\":1,\"models\":[]}" }),
    "model_catalog_invalid",
  );
});

test("model catalog validates schema and model entries", async () => {
  await expectCode(
    () => loadValue({ ...validCatalog(), schemaVersion: 2 }),
    "model_catalog_schema_unsupported",
  );
  await expectCode(
    () => loadValue({ ...validCatalog(), schemaVersion: "1" }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({ ...validCatalog(), models: [] }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({ ...validCatalog(), unknown: true }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      models: [{ id: "openai/gpt-5.2", provider: "openai", extra: true }],
    }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      models: [{ id: "openai/gpt-5.2", provider: "openai", displayName: 7 }],
    }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      models: [{ id: "openai/gpt-5.2", provider: "anthropic" }],
    }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      models: [
        { id: "openai/gpt-5.2", provider: "openai" },
        { id: "openai/gpt-5.2", provider: "openai" },
      ],
    }),
    "model_catalog_invalid",
  );
  for (const id of ["openai", "openai/", "/gpt", "OpenAI/gpt", "openai/gpt/extra", "openai/*"]) {
    await expectCode(
      () => loadValue({
        ...validCatalog(),
        models: [{ id, provider: id.split("/")[0] }],
      }),
      "model_catalog_invalid",
    );
  }
});

test("model catalog rejects invalid groups and references", async () => {
  await expectCode(
    () => loadValue({ ...validCatalog(), groups: {} }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { "Engineering-approved": ["openai/gpt-5.2"] },
    }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { engineering: ["openai/gpt-5.2", "openai/gpt-5.2"] },
    }),
    "model_catalog_invalid",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { engineering: ["openai/unknown"] },
    }),
    "unknown_model",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { engineering: ["group/other"] },
    }),
    "unknown_model_group",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { engineering: ["*"] },
    }),
    "provider_wildcard_not_allowed",
  );
  await expectCode(
    () => loadValue({
      ...validCatalog(),
      groups: { engineering: ["openai/*"] },
    }),
    "provider_wildcard_not_allowed",
  );
  await expectCode(
    () => loadValue(null, {
      raw: "{\"schemaVersion\":1,\"models\":[{\"id\":\"openai/gpt-5.2\",\"provider\":\"openai\"}],\"groups\":{\"engineering\":[\"openai/gpt-5.2\"],\"engineering\":[\"openai/gpt-5.2\"]}}",
    }),
    "model_catalog_invalid",
  );
});

test("provider wildcards are explicit and selectors cannot widen implicitly", async () => {
  await expectCode(
    () => loadValue({ ...validCatalog(), providerWildcards: ["openai/*"] }),
    "provider_wildcard_not_allowed",
  );
  await expectCode(
    () => loadValue({ ...validCatalog(), providerWildcards: [] }),
    "model_catalog_invalid",
  );

  const catalog = await loadValue({
    ...validCatalog(),
    providerWildcards: ["company-model"],
  });
  assert.deepEqual(catalog.expandSelectors(["company-model/*"]), ["company-model/*"]);
  await expectCode(() => catalog.expandSelectors(["openai/*"]), "provider_wildcard_not_allowed");
  await expectCode(() => catalog.expandSelectors(["*"]), "provider_wildcard_not_allowed");

  const implicit = await loadValue({
    ...validCatalog(),
    providerWildcards: undefined,
  });
  await expectCode(() => implicit.expandSelectors(["openai/*"]), "provider_wildcard_not_allowed");
});

test("model catalog enforces the 2 MiB limit and optional digest pin", async () => {
  await withTempDir(async (directory) => {
    const filePath = path.join(directory, "catalog.json");
    await fs.writeFile(filePath, Buffer.alloc(MAX_MODEL_CATALOG_BYTES + 1, 0x20));
    await expectCode(
      () => loadModelCatalog({ filePath }),
      "model_catalog_too_large",
    );
  });

  await withTempDir(async (directory) => {
    const filePath = path.join(directory, "catalog.json");
    const source = JSON.stringify(validCatalog());
    await fs.writeFile(filePath, source, "utf8");
    const digest = crypto.createHash("sha256").update(source).digest("hex");
    await expectCode(
      () => loadModelCatalog({
        filePath,
        expectedDigest: `sha256:${"0".repeat(64)}`,
      }),
      "model_catalog_digest_mismatch",
    );
    const loaded = await loadModelCatalog({ filePath, expectedDigest: digest });
    assert.equal(loaded.status.catalogDigest, `sha256:${digest}`);
  });
});

test("legacy ADMIN_MODELS remains display-only and cannot authorize unknown models", async () => {
  const legacy = legacyModelCatalog([
    "deepseek/deepseek-chat",
    "deepseek/deepseek-chat",
  ]);
  assert.equal(legacy.status.source, "legacy_env");
  assert.equal(legacy.status.authorizationReady, false);
  assert.equal(legacy.status.catalogVersion, 0);
  assert.deepEqual(legacy.expandSelectors(["deepseek/deepseek-chat"]), [
    "deepseek/deepseek-chat",
  ]);
  await expectCode(() => legacy.expandSelectors(["deepseek/other"]), "unknown_model");
});
