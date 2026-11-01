const PERIODS = new Set(["day", "week", "month", "days", "hours"]);
const POLICY_STATUSES = new Set(["unknown", "pending", "known"]);
const MODEL_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._:@+-]*$/;
const PROVIDER_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const MAX_MODELS = 200;
const MAX_MODEL_LENGTH = 256;
const MAX_LIMITS = 5;

export class PolicyValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function createUnknownPolicy(now = new Date().toISOString(), initializationSource = "m1_unknown") {
  return {
    version: 0,
    models: null,
    limits: null,
    quotaStatus: "unknown",
    modelStatus: "unknown",
    updatedAt: now,
    initializationSource,
  };
}

function validModels(value) {
  try {
    validateModels(value);
    return true;
  } catch {
    return false;
  }
}

function validLimits(value) {
  try {
    validateLimits(value);
    return true;
  } catch {
    return false;
  }
}

export function normalizeStoredPolicy(value, now = new Date().toISOString(), source = "m1_unknown") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return createUnknownPolicy(now, source);
  }
  const policy = {
    version: Number.isSafeInteger(value.version) && value.version >= 0 ? value.version : 0,
    models: Array.isArray(value.models) && validModels(value.models) ? structuredClone(value.models) : null,
    limits: Array.isArray(value.limits) && validLimits(value.limits) ? structuredClone(value.limits) : null,
    quotaStatus: POLICY_STATUSES.has(value.quotaStatus) ? value.quotaStatus : "unknown",
    modelStatus: POLICY_STATUSES.has(value.modelStatus) ? value.modelStatus : "unknown",
    updatedAt: typeof value.updatedAt === "string" && value.updatedAt ? value.updatedAt : now,
    initializationSource: typeof value.initializationSource === "string" && value.initializationSource
      ? value.initializationSource
      : source,
  };
  if (!policy.models) policy.modelStatus = "unknown";
  if (!policy.limits) policy.quotaStatus = "unknown";
  if (typeof value.confirmedAt === "string" && value.confirmedAt) policy.confirmedAt = value.confirmedAt;
  if (typeof value.operationId === "string" && value.operationId) policy.operationId = value.operationId;
  return policy;
}

export function validateModels(input) {
  if (!Array.isArray(input) || input.length === 0) {
    throw new PolicyValidationError("invalid_models", "models must be a non-empty array");
  }
  if (input.length > MAX_MODELS) {
    throw new PolicyValidationError("invalid_models", `models must contain at most ${MAX_MODELS} entries`);
  }

  const models = [];
  const seen = new Set();
  for (const raw of input) {
    if (typeof raw !== "string" || !raw || raw !== raw.trim()) {
      throw new PolicyValidationError("invalid_models", "each model must be a non-empty stable model ID");
    }
    if (raw.length > MAX_MODEL_LENGTH) {
      throw new PolicyValidationError("invalid_models", "a model ID is too long");
    }
    const parts = raw.split("/");
    if (parts.length < 2 || parts.some((part) => !part)) {
      throw new PolicyValidationError("invalid_models", "each model must use provider/model syntax");
    }
    const [provider, ...modelParts] = parts;
    if (!PROVIDER_SEGMENT.test(provider)) {
      throw new PolicyValidationError("invalid_models", "a provider is not a stable provider ID");
    }
    if (provider === "group") {
      throw new PolicyValidationError(
        "invalid_models",
        "model group expressions must be expanded against the model catalog first",
      );
    }
    const model = modelParts.join("/");
    if (model === "*") {
      models.push(`${provider}/*`);
      continue;
    }
    if (modelParts.includes("*") || modelParts.some((part) => !MODEL_SEGMENT.test(part))) {
      throw new PolicyValidationError("invalid_models", "a model ID contains an unsupported segment");
    }
    models.push(`${provider}/${model}`);
  }

  const deduplicated = [];
  for (const model of models) {
    if (seen.has(model)) continue;
    seen.add(model);
    deduplicated.push(model);
  }
  return deduplicated;
}

function safeTokens(value) {
  const tokens = value == null ? 0 : value;
  if (!Number.isSafeInteger(tokens) || tokens < 0) {
    throw new PolicyValidationError("invalid_quota", "tokens must be a non-negative safe integer");
  }
  return tokens;
}

function safeCost(value) {
  const cost = value == null ? 0 : value;
  if (!Number.isFinite(cost) || cost < 0) {
    throw new PolicyValidationError("invalid_quota", "cost must be a finite non-negative number");
  }
  const scaled = cost * 10000;
  if (Math.abs(scaled - Math.round(scaled)) > 1e-7) {
    throw new PolicyValidationError("invalid_quota", "cost must have at most four decimal places");
  }
  return cost;
}

function optionalWindowInteger(value, minimum, maximum, name) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new PolicyValidationError(
      "invalid_quota",
      `${name} must be an integer from ${minimum} to ${maximum}`,
    );
  }
  return value;
}

export function validateLimits(input) {
  if (!Array.isArray(input)) {
    throw new PolicyValidationError("invalid_quota", "limits must be an array");
  }
  if (input.length > MAX_LIMITS) {
    throw new PolicyValidationError("invalid_quota", `limits must contain at most ${MAX_LIMITS} windows`);
  }

  const limits = [];
  const seen = new Set();
  for (const raw of input) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new PolicyValidationError("invalid_quota", "each limit must be an object");
    }
    if (!PERIODS.has(raw.period)) {
      throw new PolicyValidationError(
        "invalid_quota",
        "period must be day, week, month, days, or hours",
      );
    }

    const tokens = safeTokens(raw.tokens);
    const cost = safeCost(raw.cost);
    if (tokens <= 0 && cost <= 0) {
      throw new PolicyValidationError("invalid_quota", "each limit needs a positive tokens or cost value");
    }
    if (raw.cacheReads != null && typeof raw.cacheReads !== "boolean") {
      throw new PolicyValidationError("invalid_quota", "cacheReads must be a boolean");
    }

    const limit = {
      period: raw.period,
      tokens,
      cost,
      cacheReads: raw.cacheReads === true,
    };
    if (raw.period === "days") {
      limit.days = optionalWindowInteger(raw.days, 1, 3650, "days");
      if (raw.hours != null) {
        throw new PolicyValidationError("invalid_quota", "days windows cannot include hours");
      }
    } else if (raw.period === "hours") {
      limit.hours = optionalWindowInteger(raw.hours, 1, 8760, "hours");
      if (raw.days != null) {
        throw new PolicyValidationError("invalid_quota", "hours windows cannot include days");
      }
    } else if (raw.days != null || raw.hours != null) {
      throw new PolicyValidationError("invalid_quota", "day, week, and month windows cannot include days or hours");
    }

    const key = `${limit.period}|${limit.days || ""}|${limit.hours || ""}`;
    if (seen.has(key)) {
      throw new PolicyValidationError("invalid_quota", "duplicate quota windows are not allowed");
    }
    seen.add(key);
    limits.push(limit);
  }
  return limits;
}

export function policyMissing(policy) {
  const missing = [];
  if (!Array.isArray(policy?.limits)) missing.push("quota");
  if (!Array.isArray(policy?.models)) missing.push("models");
  return missing;
}

export function policySections(policy) {
  return {
    including: [
      ...(Array.isArray(policy?.limits) ? ["quota"] : []),
      ...(Array.isArray(policy?.models) ? ["models"] : []),
    ],
    missing: policyMissing(policy),
  };
}

export function policyIsComplete(policy) {
  return policyMissing(policy).length === 0;
}

export function policyIsKnown(policy) {
  return policyIsComplete(policy)
    && policy.quotaStatus === "known"
    && policy.modelStatus === "known";
}

export function samePolicyContent(policy, models, limits) {
  if (!Array.isArray(policy?.models) || !Array.isArray(policy?.limits)) return false;
  return JSON.stringify(policy.models) === JSON.stringify(models)
    && JSON.stringify(policy.limits) === JSON.stringify(limits);
}

export function policyStatusView(policy) {
  return {
    version: Number.isSafeInteger(policy?.version) ? policy.version : 0,
    quotaStatus: policy?.quotaStatus || "unknown",
    modelStatus: policy?.modelStatus || "unknown",
    ...policySections(policy),
  };
}

export function publicPolicy(policy) {
  if (!policy) return null;
  return {
    version: policy.version,
    models: Array.isArray(policy.models) ? structuredClone(policy.models) : null,
    limits: Array.isArray(policy.limits) ? structuredClone(policy.limits) : null,
    quotaStatus: policy.quotaStatus,
    modelStatus: policy.modelStatus,
    updatedAt: policy.updatedAt || "",
    confirmedAt: policy.confirmedAt || "",
    operationId: policy.operationId || "",
  };
}

export function clonePolicy(policy) {
  return structuredClone(policy);
}
