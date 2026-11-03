/**
 * Employee Portal - Config
 * Loads and validates environment configuration.
 */

export class PortalConfigError extends Error {
  constructor(message = "portal config error") {
    super(message);
    this.name = "PortalConfigError";
  }
}

const DEFAULTS = Object.freeze({
  PORT: 3007,
  ADMIN_MODEL_CATALOG_URL: "",
  ADMIN_MODEL_CATALOG_TOKEN: "",
  USAGE_SERVICE_URL: "",
  USAGE_SERVICE_TOKEN: "",
  STORE_PATH: "./data/portal.json",
  DEFAULT_ORG_UNIT: "",
});

export function loadPortalConfig(env = process.env) {
  const port = parseInt(env.PORT || String(DEFAULTS.PORT), 10);
  const adminCatalogUrl = (env.ADMIN_MODEL_CATALOG_URL || "").trim();
  const adminCatalogToken = (env.ADMIN_MODEL_CATALOG_TOKEN || "").trim();
  const usageServiceUrl = (env.USAGE_SERVICE_URL || "").trim();
  const usageServiceToken = (env.USAGE_SERVICE_TOKEN || "").trim();
  const storePath = (env.STORE_PATH || DEFAULTS.STORE_PATH).trim();
  const defaultOrgUnit = (env.DEFAULT_ORG_UNIT || DEFAULTS.DEFAULT_ORG_UNIT).trim();

  const config = {
    port: Number.isInteger(port) && port > 0 ? port : DEFAULTS.PORT,
    adminModelCatalogUrl: adminCatalogUrl,
    adminModelCatalogToken: adminCatalogToken,
    usageServiceUrl: usageServiceUrl,
    usageServiceToken: usageServiceToken,
    storePath,
    defaultOrgUnit,
    hasModelCatalog: adminCatalogUrl.length > 0 && adminCatalogToken.length > 0,
    hasUsageService: usageServiceUrl.length > 0,
  };

  return config;
}
