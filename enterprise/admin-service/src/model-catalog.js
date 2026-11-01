import crypto from "node:crypto";
import fs from "node:fs/promises";

export const MAX_MODEL_CATALOG_BYTES = 2 * 1024 * 1024;

const PROVIDER_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_PART_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:+@-]{0,127}$/;
const GROUP_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_JSON_DEPTH = 64;

export class ModelCatalogError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ModelCatalogError";
    this.code = code;
  }
}

function invalid(message = "The model catalog is invalid") {
  return new ModelCatalogError("model_catalog_invalid", message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ownKeys(value) {
  return Object.keys(value);
}

function assertOnlyKeys(value, allowed, label) {
  const allowedSet = new Set(allowed);
  for (const key of ownKeys(value)) {
    if (!allowedSet.has(key)) throw invalid(`${label} contains an unknown field`);
  }
}

function requiredString(value, label, maxLength = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw invalid(`${label} must be a non-empty string no longer than ${maxLength} characters`);
  }
  return value;
}

function optionalString(value, label, maxLength = 512) {
  if (value == null) return "";
  return requiredString(value, label, maxLength);
}

function canonicalModelId(value, label) {
  const raw = requiredString(value, label, 256);
  if (raw.includes("*") || raw.startsWith("group/")) {
    throw invalid(`${label} must be a canonical model ID, not an authorization expression`);
  }
  const slash = raw.indexOf("/");
  if (slash <= 0 || slash !== raw.lastIndexOf("/")) {
    throw invalid(`${label} must use the canonical <provider>/<model> form`);
  }
  const provider = raw.slice(0, slash);
  const model = raw.slice(slash + 1);
  if (!PROVIDER_PATTERN.test(provider) || !MODEL_PART_PATTERN.test(model)) {
    throw invalid(`${label} must use the canonical <provider>/<model> form`);
  }
  return { id: raw, provider };
}

function normalizeDigest(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "";
  const digest = raw.startsWith("sha256:") ? raw.slice("sha256:".length) : raw;
  if (!/^[a-f0-9]{64}$/.test(digest)) throw invalid("The expected catalog digest is invalid");
  return `sha256:${digest}`;
}

class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  parse() {
    const value = this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) throw invalid("The model catalog has trailing content");
    return value;
  }

  whitespace() {
    while (this.index < this.text.length && /[\t\n\r ]/.test(this.text[this.index])) {
      this.index += 1;
    }
  }

  value(depth) {
    if (depth > MAX_JSON_DEPTH) throw invalid("The model catalog JSON is nested too deeply");
    this.whitespace();
    const char = this.text[this.index];
    if (char === "{") return this.object(depth + 1);
    if (char === "[") return this.array(depth + 1);
    if (char === "\"") return this.string();
    if (char === "-" || /[0-9]/.test(char || "")) return this.number();
    if (this.text.startsWith("true", this.index)) {
      this.index += 4;
      return true;
    }
    if (this.text.startsWith("false", this.index)) {
      this.index += 5;
      return false;
    }
    if (this.text.startsWith("null", this.index)) {
      this.index += 4;
      return null;
    }
    throw invalid("The model catalog contains malformed JSON");
  }

  object(depth) {
    this.index += 1;
    this.whitespace();
    const result = Object.create(null);
    const seen = new Set();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (this.index < this.text.length) {
      if (this.text[this.index] !== "\"") throw invalid("The model catalog JSON object is malformed");
      const key = this.string();
      if (seen.has(key)) throw invalid("The model catalog contains duplicate JSON keys");
      seen.add(key);
      this.whitespace();
      if (this.text[this.index] !== ":") throw invalid("The model catalog JSON object is malformed");
      this.index += 1;
      result[key] = this.value(depth);
      this.whitespace();
      const char = this.text[this.index];
      if (char === "}") {
        this.index += 1;
        return result;
      }
      if (char !== ",") throw invalid("The model catalog JSON object is malformed");
      this.index += 1;
      this.whitespace();
    }
    throw invalid("The model catalog JSON object is malformed");
  }

  array(depth) {
    this.index += 1;
    this.whitespace();
    const result = [];
    if (this.text[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (this.index < this.text.length) {
      result.push(this.value(depth));
      this.whitespace();
      const char = this.text[this.index];
      if (char === "]") {
        this.index += 1;
        return result;
      }
      if (char !== ",") throw invalid("The model catalog JSON array is malformed");
      this.index += 1;
      this.whitespace();
    }
    throw invalid("The model catalog JSON array is malformed");
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      if (char === "\"") {
        this.index += 1;
        try {
          return JSON.parse(this.text.slice(start, this.index));
        } catch {
          throw invalid("The model catalog contains malformed JSON");
        }
      }
      if (char === "\\") {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === "u") {
          const hex = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[a-fA-F0-9]{4}$/.test(hex)) throw invalid("The model catalog contains malformed JSON");
          this.index += 5;
          continue;
        }
        if (!"\"\\/bfnrt".includes(escaped || "")) throw invalid("The model catalog contains malformed JSON");
        this.index += 1;
        continue;
      }
      if (char.charCodeAt(0) < 0x20) throw invalid("The model catalog contains malformed JSON");
      this.index += 1;
    }
    throw invalid("The model catalog contains malformed JSON");
  }

  number() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.text.slice(this.index),
    );
    if (!match) throw invalid("The model catalog contains malformed JSON");
    this.index += match[0].length;
    return Number(match[0]);
  }
}

function parseStrictJson(text) {
  return new StrictJsonParser(text).parse();
}

function validateCatalog(value) {
  if (!isObject(value)) throw invalid("The model catalog must be a JSON object");
  assertOnlyKeys(value, ["schemaVersion", "models", "providerWildcards", "groups"], "The model catalog");
  if (value.schemaVersion !== 1) {
    if (typeof value.schemaVersion === "number") {
      throw new ModelCatalogError(
        "model_catalog_schema_unsupported",
        "The model catalog schema version is not supported",
      );
    }
    throw invalid("The model catalog schemaVersion must be 1");
  }

  if (!Array.isArray(value.models) || value.models.length === 0) {
    throw invalid("The model catalog must contain at least one model");
  }
  const models = [];
  const modelIds = new Set();
  for (const [index, entry] of value.models.entries()) {
    if (!isObject(entry)) throw invalid(`models[${index}] must be an object`);
    assertOnlyKeys(entry, ["id", "provider", "displayName"], `models[${index}]`);
    const model = canonicalModelId(entry.id, `models[${index}].id`);
    const provider = requiredString(entry.provider, `models[${index}].provider`, 64);
    if (!PROVIDER_PATTERN.test(provider) || provider !== model.provider) {
      throw invalid(`models[${index}].provider must match the canonical model ID`);
    }
    if (modelIds.has(model.id)) throw invalid("The model catalog contains duplicate model IDs");
    modelIds.add(model.id);
    models.push(Object.freeze({
      id: model.id,
      provider,
      displayName: optionalString(entry.displayName, `models[${index}].displayName`, 128),
    }));
  }

  let providerWildcards = [];
  if (Object.hasOwn(value, "providerWildcards")) {
    if (!Array.isArray(value.providerWildcards) || value.providerWildcards.length === 0) {
      throw invalid("providerWildcards must be a non-empty array when present");
    }
    const seen = new Set();
    providerWildcards = value.providerWildcards.map((entry, index) => {
      const provider = requiredString(entry, `providerWildcards[${index}]`, 64);
      if (!PROVIDER_PATTERN.test(provider)) {
        throw new ModelCatalogError(
          "provider_wildcard_not_allowed",
          "providerWildcards entries must be provider names",
        );
      }
      if (seen.has(provider)) throw invalid("providerWildcards contains duplicate provider names");
      seen.add(provider);
      return provider;
    });
  }

  const groups = Object.create(null);
  if (Object.hasOwn(value, "groups")) {
    if (!isObject(value.groups) || ownKeys(value.groups).length === 0) {
      throw invalid("groups must be a non-empty object when present");
    }
    for (const [name, references] of Object.entries(value.groups)) {
      if (!GROUP_PATTERN.test(name)) throw invalid("A model group name is invalid");
      if (!Array.isArray(references) || references.length === 0) {
        throw invalid(`groups.${name} must be a non-empty array`);
      }
      const seen = new Set();
      const stable = [];
      for (const reference of references) {
        const value = requiredString(reference, `groups.${name}`, 256);
        if (value === "*" || value.endsWith("/*")) {
          throw new ModelCatalogError(
            "provider_wildcard_not_allowed",
            "Model groups cannot contain wildcard selectors",
          );
        }
        if (value.startsWith("group/")) {
          throw new ModelCatalogError(
            "unknown_model_group",
            "Model groups cannot reference another group",
          );
        }
        if (!modelIds.has(value)) {
          throw new ModelCatalogError("unknown_model", "A model group references an unknown model");
        }
        if (seen.has(value)) throw invalid("A model group contains duplicate model references");
        seen.add(value);
        stable.push(value);
      }
      groups[name] = Object.freeze(stable);
    }
  }

  return {
    models: Object.freeze(models),
    providerWildcards: Object.freeze(providerWildcards),
    groups: Object.freeze(groups),
  };
}

function catalogStatus(source, descriptor, digest, loadedAt, authorizationReady) {
  return Object.freeze({
    source,
    authorizationReady,
    catalogVersion: descriptor.catalogVersion,
    catalogDigest: digest,
    loadedAt,
    modelCount: descriptor.models.length,
    groupCount: Object.keys(descriptor.groups).length,
    providerWildcardCount: descriptor.providerWildcards.length,
  });
}

function makeCatalog(descriptor, status) {
  const models = new Map(descriptor.models.map((model) => [model.id, model]));
  const groups = new Map(Object.entries(descriptor.groups));
  const wildcards = new Set(descriptor.providerWildcards);
  return Object.freeze({
    models: descriptor.models,
    providerWildcards: descriptor.providerWildcards,
    groups: descriptor.groups,
    status,
    expandSelectors(selectors) {
      if (!Array.isArray(selectors) || selectors.length === 0) {
        throw new ModelCatalogError("unknown_model", "At least one model selector is required");
      }
      const expanded = [];
      const seen = new Set();
      const add = (value) => {
        if (!seen.has(value)) {
          seen.add(value);
          expanded.push(value);
        }
      };
      for (const selector of selectors) {
        const value = String(selector || "");
        if (value === "*") {
          throw new ModelCatalogError(
            "provider_wildcard_not_allowed",
            "A bare wildcard is not allowed",
          );
        }
        if (value.startsWith("group/")) {
          const group = groups.get(value.slice("group/".length));
          if (!group) throw new ModelCatalogError("unknown_model_group", "Unknown model group");
          for (const model of group) add(model);
          continue;
        }
        if (value.endsWith("/*")) {
          const provider = value.slice(0, -2);
          if (!wildcards.has(provider)) {
            throw new ModelCatalogError(
              "provider_wildcard_not_allowed",
              "This provider wildcard is not explicitly allowed",
            );
          }
          add(value);
          continue;
        }
        if (!models.has(value)) throw new ModelCatalogError("unknown_model", "Unknown model");
        add(value);
      }
      return Object.freeze(expanded);
    },
  });
}

export function legacyModelCatalog(modelIds = []) {
  const loadedAt = new Date().toISOString();
  const unique = [...new Set(modelIds.map(String).filter(Boolean))];
  const models = unique.map((id) => Object.freeze({
    id,
    provider: id.includes("/") ? id.slice(0, id.indexOf("/")) : "",
    displayName: id,
  }));
  const descriptor = {
    catalogVersion: 0,
    models,
    providerWildcards: Object.freeze([]),
    groups: Object.freeze(Object.create(null)),
  };
  return makeCatalog(
    descriptor,
    catalogStatus("legacy_env", descriptor, "", loadedAt, false),
  );
}

export async function loadModelCatalog({ filePath, expectedDigest = "" } = {}) {
  if (!filePath) throw new ModelCatalogError("model_catalog_unavailable", "The model catalog is not configured");
  const expected = normalizeDigest(expectedDigest);
  let bytes;
  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) {
      throw new ModelCatalogError("model_catalog_unavailable", "The model catalog is unavailable");
    }
    if (stat.size > MAX_MODEL_CATALOG_BYTES) {
      throw new ModelCatalogError("model_catalog_too_large", "The model catalog exceeds 2 MiB");
    }
    bytes = await fs.readFile(filePath);
  } catch (error) {
    if (error instanceof ModelCatalogError) throw error;
    throw new ModelCatalogError("model_catalog_unavailable", "The model catalog is unavailable");
  }
  if (bytes.length > MAX_MODEL_CATALOG_BYTES) {
    throw new ModelCatalogError("model_catalog_too_large", "The model catalog exceeds 2 MiB");
  }

  const digest = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
  if (expected && expected !== digest) {
    throw new ModelCatalogError(
      "model_catalog_digest_mismatch",
      "The model catalog digest does not match the pinned digest",
    );
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ModelCatalogError("model_catalog_invalid", "The model catalog is not valid UTF-8");
  }

  let raw;
  try {
    raw = parseStrictJson(text);
  } catch (error) {
    if (error instanceof ModelCatalogError) throw error;
    throw new ModelCatalogError("model_catalog_invalid", "The model catalog contains malformed JSON");
  }
  const descriptor = {
    catalogVersion: raw.schemaVersion,
    ...validateCatalog(raw),
  };
  return makeCatalog(
    descriptor,
    catalogStatus("file", descriptor, digest, new Date().toISOString(), true),
  );
}

export function publicModelCatalog(catalog) {
  return {
    models: catalog.models.map((model) => ({
      id: model.id,
    })),
    providerWildcards: [...catalog.providerWildcards],
    groups: Object.entries(catalog.groups).map(([name, models]) => ({
      name,
      models: [...models],
    })),
    catalog: { ...catalog.status },
  };
}

export function modelCatalogStartupAudit(catalog) {
  return {
    id: `audit_system_${crypto.randomUUID()}`,
    timestamp: new Date().toISOString(),
    action: "model_catalog.load",
    result: "succeeded",
    ...catalog.status,
  };
}
