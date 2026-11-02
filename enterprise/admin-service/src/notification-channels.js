import crypto from "node:crypto";
import dns from "node:dns/promises";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import {
  NOTIFICATION_EVENT_TYPES,
  publicNotificationDelivery,
} from "./notification-schema.js";
import {
  DEFAULT_SIEM_MAX_EVENT_BYTES,
  assertSiemEventSize,
  httpCollectorPayload,
  otlpLogsPayload,
  syslogOctetFrame,
  syslogRfc5424,
} from "./notification-siem.js";

export const NOTIFICATION_CHANNEL_TYPES = Object.freeze([
  "email",
  "im",
  "webhook",
  "ticketing",
  "siem",
]);

export const NOTIFICATION_CHANNEL_PROVIDERS = Object.freeze({
  email: ["mail-gateway"],
  im: ["feishu", "teams", "slack", "generic"],
  webhook: ["generic"],
  ticketing: ["servicenow", "jira", "feishu", "generic"],
  siem: ["http-collector", "otlp-http", "syslog-tls"],
});

const CHANNEL_TYPES = new Set(NOTIFICATION_CHANNEL_TYPES);
const EVENT_TYPES = new Set(NOTIFICATION_EVENT_TYPES);
const SECRET_REF_PATTERN = /^[A-Z][A-Z0-9_]{2,80}$/;
const CHANNEL_ID_PATTERN = /^nch_[a-f0-9]{24}$/;
const TEST_ID_PATTERN = /^nct_[a-f0-9]{24}$/;
const FORBIDDEN_KEYS = new Set([
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "password",
  "secret",
  "secretvalue",
  "token",
  "tokenhash",
  "gatewaykey",
  "oidctoken",
  "servicetoken",
]);
const MAX_NAME_LENGTH = 100;
const MAX_RECIPIENTS = 20;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;
const MAX_ENDPOINT_LENGTH = 2048;
const SYSLOG_PORT = "6514";

function safeText(value, maxLength = 320) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maxLength);
}

function requirePlainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function normalizedKeys(value) {
  return Object.keys(value).map((key) => key.replace(/[_-]/g, "").toLowerCase());
}

export function assertNoSecretMaterial(value, path = "value") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecretMaterial(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.replace(/[_-]/g, "").toLowerCase();
    if (FORBIDDEN_KEYS.has(normalized) && normalized !== "secretref") {
      throw new Error(`${path}.${key} must use a secret reference, not a secret value`);
    }
    assertNoSecretMaterial(child, `${path}.${key}`);
  }
}

function normalizeEndpoint(value, name, options = {}) {
  const raw = safeText(value, MAX_ENDPOINT_LENGTH);
  if (!raw) throw new Error(`${name} is required`);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL`);
  }
  const protocol = options.protocol || "https:";
  const allowedPorts = options.allowedPorts || ["443"];
  if (parsed.protocol !== protocol) {
    throw new Error(`${name} must use ${protocol === "tls:" ? "TLS" : "HTTPS"}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${name} must not contain credentials`);
  }
  if (parsed.port && !allowedPorts.includes(parsed.port)) {
    throw new Error(`${name} must use port ${allowedPorts.join(" or ")}`);
  }
  if (!options.allowQuery && (parsed.search || parsed.hash)) {
    throw new Error(`${name} must not contain a query string or fragment`);
  }
  if (parsed.hostname === "localhost"
      || parsed.hostname.endsWith(".localhost")
      || parsed.hostname.endsWith(".local")
      || parsed.hostname.endsWith(".internal")) {
    throw new Error(`${name} must not point to a local hostname`);
  }
  parsed.hash = "";
  return parsed.toString();
}

function endpointOptionsForChannel(type, provider) {
  if (type === "siem" && provider === "syslog-tls") {
    return {
      protocol: "tls:",
      allowedPorts: [SYSLOG_PORT],
      protocols: ["tls:"],
    };
  }
  return {
    protocol: "https:",
    allowedPorts: ["443"],
    protocols: ["https:"],
  };
}

function normalizeRef(value, name) {
  const ref = safeText(value, 81);
  if (!ref) return "";
  if (!SECRET_REF_PATTERN.test(ref)) {
    throw new Error(`${name} must be an environment variable name`);
  }
  return ref;
}

function normalizeEventTypes(value) {
  if (value == null) return [...NOTIFICATION_EVENT_TYPES];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("eventTypes must be a non-empty array");
  }
  const eventTypes = [...new Set(value.map((item) => safeText(item, 80)))];
  if (eventTypes.some((item) => !EVENT_TYPES.has(item))) {
    throw new Error("eventTypes contains an unsupported event type");
  }
  return eventTypes.sort();
}

function normalizeEmail(value, name) {
  const email = safeText(value, 320).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw new Error(`${name} must be an email address`);
  }
  return email;
}

function emailDomain(value) {
  return normalizeEmail(value, "recipient").split("@")[1];
}

function normalizeDomains(value, name) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  const domains = [...new Set(value.map((item) => safeText(item, 253).toLowerCase()))];
  for (const domain of domains) {
    if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(domain)
        || domain.includes("..")) {
      throw new Error(`${name} contains an invalid domain`);
    }
  }
  return domains.sort();
}

function normalizeRecipients(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("config.recipients must be a non-empty array");
  }
  if (value.length > MAX_RECIPIENTS) {
    throw new Error(`config.recipients must contain at most ${MAX_RECIPIENTS} addresses`);
  }
  return [...new Set(value.map((item) => normalizeEmail(item, "recipient")))];
}

function normalizeChannelConfig(type, provider, value, options = {}) {
  const input = requirePlainObject(value, "config");
  const output = {};
  const endpointOptions = endpointOptionsForChannel(type, provider);
  const hasEndpoint = input.endpoint != null && safeText(input.endpoint);
  const endpointRef = normalizeRef(input.endpointRef, "config.endpointRef");
  if (hasEndpoint && endpointRef) {
    throw new Error("config.endpoint and config.endpointRef are mutually exclusive");
  }
  if (hasEndpoint) {
    output.endpoint = normalizeEndpoint(input.endpoint, "config.endpoint", endpointOptions);
  } else if (endpointRef) {
    output.endpointRef = endpointRef;
  } else {
    throw new Error("config.endpoint or config.endpointRef is required");
  }
  if (input.timeoutMs != null) {
    const timeoutMs = Number(input.timeoutMs);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30000) {
      throw new Error("config.timeoutMs must be an integer from 500 to 30000");
    }
    output.timeoutMs = timeoutMs;
  }
  if (type === "email") {
    output.provider = "mail-gateway";
    output.from = normalizeEmail(input.from, "config.from");
    output.recipients = normalizeRecipients(input.recipients);
    const recipients = output.recipients;
    const domains = normalizeDomains(input.recipientDomains, "config.recipientDomains");
    const allowedGlobal = new Set(options.emailRecipientDomains || []);
    for (const recipient of recipients) {
      const domain = emailDomain(recipient);
      if (allowedGlobal.size > 0 && !allowedGlobal.has(domain)) {
        throw new Error("config.recipients contains a domain outside the deployment allowlist");
      }
      if (domains.length > 0 && !domains.includes(domain)) {
        throw new Error("config.recipients contains a domain outside config.recipientDomains");
      }
    }
    if (domains.length > 0) output.recipientDomains = domains;
    output.subjectPrefix = safeText(input.subjectPrefix || "[Magpie Enterprise]", 80);
    return output;
  }
  output.provider = provider;
  if (type === "ticketing") {
    output.projectKey = safeText(input.projectKey, 100);
    output.queue = safeText(input.queue, 100);
  }
  if (type === "im") {
    output.channelLabel = safeText(input.channelLabel, 100);
  }
  if (type === "siem") {
    output.provider = provider;
    if (provider === "otlp-http") {
      output.serviceName = safeText(input.serviceName || "magpie-enterprise-admin", 128);
      if (!/^[A-Za-z0-9._-]+$/.test(output.serviceName)) {
        throw new Error("config.serviceName contains unsupported characters");
      }
    }
    if (provider === "syslog-tls") {
      output.hostname = safeText(input.hostname || "magpie-enterprise", 255);
      output.appName = safeText(input.appName || "magpie-ent", 48);
      if (!/^[A-Za-z0-9._-]+$/.test(output.hostname)
          || !/^[A-Za-z0-9._-]+$/.test(output.appName)) {
        throw new Error("config syslog hostname or appName contains unsupported characters");
      }
      const facility = input.facility == null ? 10 : Number(input.facility);
      if (!Number.isSafeInteger(facility) || facility < 0 || facility > 23) {
        throw new Error("config.facility must be an integer from 0 to 23");
      }
      output.facility = facility;
    }
  }
  return output;
}

function normalizeChannelInput(input, options = {}) {
  const value = requirePlainObject(input, "notification channel");
  assertNoSecretMaterial(value);
  const name = safeText(value.name, MAX_NAME_LENGTH);
  if (!name) throw new Error("name is required");
  const type = safeText(value.type, 20);
  if (!CHANNEL_TYPES.has(type)) throw new Error("type is not supported");
  const providers = NOTIFICATION_CHANNEL_PROVIDERS[type];
  const provider = safeText(value.provider || providers[0], 30);
  if (!providers.includes(provider)) {
    throw new Error("provider is not supported for this channel type");
  }
  const enabled = value.enabled === undefined ? true : Boolean(value.enabled);
  const eventTypes = normalizeEventTypes(value.eventTypes);
  const secretRef = normalizeRef(value.secretRef, "secretRef");
  if (type === "webhook" && !secretRef) {
    throw new Error("secretRef is required for a signed webhook");
  }
  if (type === "siem" && provider === "syslog-tls" && secretRef) {
    throw new Error("secretRef is not supported for syslog over TLS");
  }
  const config = normalizeChannelConfig(type, provider, value.config, options);
  if (endpointRequiresAllowlist(config, options.allowlist)) {
    throw new Error("config.endpoint is not in the outbound host allowlist");
  }
  return {
    name,
    type,
    provider,
    enabled,
    eventTypes,
    secretRef,
    config,
  };
}

function endpointRequiresAllowlist(config, allowlist) {
  if (!config.endpoint) return false;
  return !hostAllowed(new URL(config.endpoint).hostname, allowlist || []);
}

function channelIdFor(now = new Date()) {
  return `nch_${crypto.createHash("sha256")
    .update(`${now.toISOString()}\0${crypto.randomUUID()}`)
    .digest("hex")
    .slice(0, 24)}`;
}

export function createNotificationChannel(input, options = {}) {
  const normalized = normalizeChannelInput(input, options);
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const channelId = channelIdFor(now);
  return {
    channelId,
    ...normalized,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    createdBy: safeText(options.actorSubjectId, 100),
    updatedBy: safeText(options.actorSubjectId, 100),
  };
}

export function updateNotificationChannel(existing, patch, options = {}) {
  requirePlainObject(existing, "stored notification channel");
  requirePlainObject(patch, "notification channel update");
  assertNoSecretMaterial(patch);
  const merged = {
    name: patch.name === undefined ? existing.name : patch.name,
    type: patch.type === undefined ? existing.type : patch.type,
    provider: patch.provider === undefined ? existing.provider : patch.provider,
    enabled: patch.enabled === undefined ? existing.enabled : patch.enabled,
    eventTypes: patch.eventTypes === undefined ? existing.eventTypes : patch.eventTypes,
    secretRef: patch.secretRef === undefined ? existing.secretRef : patch.secretRef,
    config: patch.config === undefined
      ? existing.config
      : {
        ...existing.config,
        ...requirePlainObject(patch.config, "config"),
      },
  };
  const normalized = normalizeChannelInput(merged, options);
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  return {
    ...existing,
    ...normalized,
    updatedAt: now.toISOString(),
    updatedBy: safeText(options.actorSubjectId, 100),
  };
}

export function publicNotificationChannel(channel) {
  return {
    channelId: String(channel?.channelId || ""),
    name: String(channel?.name || ""),
    type: String(channel?.type || ""),
    provider: String(channel?.provider || ""),
    enabled: Boolean(channel?.enabled),
    eventTypes: Array.isArray(channel?.eventTypes)
      ? channel.eventTypes.map(String)
      : [],
    config: publicChannelConfig(channel?.config),
    secretRef: String(channel?.secretRef || ""),
    secretConfigured: Boolean(channel?.secretRef),
    createdAt: String(channel?.createdAt || ""),
    updatedAt: String(channel?.updatedAt || ""),
    createdBy: String(channel?.createdBy || ""),
    updatedBy: String(channel?.updatedBy || ""),
  };
}

function publicChannelConfig(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) return {};
  const output = {};
  for (const key of [
    "endpoint",
    "endpointRef",
    "provider",
    "timeoutMs",
    "from",
    "recipients",
    "recipientDomains",
    "subjectPrefix",
    "projectKey",
    "queue",
    "channelLabel",
    "serviceName",
    "hostname",
    "appName",
    "facility",
  ]) {
    if (config[key] === undefined) continue;
    output[key] = Array.isArray(config[key])
      ? config[key].map(String)
      : typeof config[key] === "number"
        ? config[key]
        : String(config[key]);
  }
  return output;
}

export function channelMatchesEvent(channel, eventType) {
  return Boolean(channel?.enabled)
    && Array.isArray(channel?.eventTypes)
    && channel.eventTypes.includes(eventType);
}

export function validateNotificationChannelStore(data) {
  for (const [channelId, channel] of Object.entries(data.notificationChannels || {})) {
    if (!CHANNEL_ID_PATTERN.test(channelId)
        || !channel
        || typeof channel !== "object"
        || Array.isArray(channel)
        || channel.channelId !== channelId) {
      throw new Error("admin store notificationChannels contains an invalid channel");
    }
    assertNoSecretMaterial(channel, `notificationChannels.${channelId}`);
    if (!CHANNEL_TYPES.has(channel.type)
        || !NOTIFICATION_CHANNEL_PROVIDERS[channel.type]?.includes(channel.provider)
        || typeof channel.enabled !== "boolean"
        || !Array.isArray(channel.eventTypes)
        || channel.eventTypes.length === 0
        || channel.eventTypes.some((eventType) => !EVENT_TYPES.has(eventType))
        || (channel.secretRef && !SECRET_REF_PATTERN.test(channel.secretRef))
        || (channel.type === "webhook" && !channel.secretRef)
        || (channel.type === "siem"
          && channel.provider === "syslog-tls"
          && channel.secretRef)) {
      throw new Error("admin store notificationChannels contains invalid channel metadata");
    }
    for (const key of ["name", "createdAt", "updatedAt", "createdBy", "updatedBy"]) {
      if (typeof channel[key] !== "string") {
        throw new Error(`admin store notification channel ${key} is invalid`);
      }
    }
    if (!channel.name || channel.name.length > MAX_NAME_LENGTH) {
      throw new Error("admin store notification channel name is invalid");
    }
    if (!Number.isFinite(Date.parse(channel.createdAt))
        || !Number.isFinite(Date.parse(channel.updatedAt))) {
      throw new Error("admin store notification channel timestamps are invalid");
    }
    if (!channel.config
        || typeof channel.config !== "object"
        || Array.isArray(channel.config)
        || (!channel.config.endpoint && !channel.config.endpointRef)) {
      throw new Error("admin store notification channel config is invalid");
    }
    if ((channel.config.endpoint && channel.config.endpointRef)
        || (channel.config.endpointRef && !SECRET_REF_PATTERN.test(channel.config.endpointRef))) {
      throw new Error("admin store notification channel endpoint reference is invalid");
    }
    if (channel.config.endpoint) {
      normalizeEndpoint(
        channel.config.endpoint,
        "notification channel endpoint",
        endpointOptionsForChannel(channel.type, channel.provider),
      );
    }
    if (channel.type === "siem" && channel.provider === "otlp-http") {
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(String(channel.config.serviceName || ""))) {
        throw new Error("admin store notification channel OTLP serviceName is invalid");
      }
    }
    if (channel.type === "siem" && channel.provider === "syslog-tls") {
      if (!/^[A-Za-z0-9._-]{1,255}$/.test(String(channel.config.hostname || ""))
          || !/^[A-Za-z0-9._-]{1,48}$/.test(String(channel.config.appName || ""))
          || !Number.isSafeInteger(channel.config.facility)
          || channel.config.facility < 0
          || channel.config.facility > 23) {
        throw new Error("admin store notification channel syslog metadata is invalid");
      }
    }
  }
  for (const [testId, result] of Object.entries(data.notificationChannelTests || {})) {
    if (!TEST_ID_PATTERN.test(testId)
        || !result
        || typeof result !== "object"
        || Array.isArray(result)
        || result.testId !== testId
        || !data.notificationChannels[result.channelId]
        || !["succeeded", "failed"].includes(result.status)) {
      throw new Error("admin store notificationChannelTests contains an invalid test");
    }
    assertNoSecretMaterial(result, `notificationChannelTests.${testId}`);
    for (const key of [
      "channelId",
      "status",
      "resultCode",
      "actorSubjectId",
      "createdAt",
    ]) {
      if (typeof result[key] !== "string") {
        throw new Error(`admin store notification channel test ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(result.createdAt))) {
      throw new Error("admin store notification channel test createdAt is invalid");
    }
  }
  for (const [keyHash, request] of Object.entries(data.notificationChannelRequests || {})) {
    if (!/^[a-f0-9]{64}$/.test(keyHash)
        || !request
        || typeof request !== "object"
        || Array.isArray(request)
        || request.idempotencyKeyHash !== keyHash
        || !/^[a-f0-9]{64}$/.test(String(request.requestFingerprint || ""))
        || !["in_progress", "succeeded", "failed"].includes(request.status)
        || (request.channelId != null
          && (!CHANNEL_ID_PATTERN.test(String(request.channelId))
            || !data.notificationChannels[request.channelId]))
        || (request.testId != null
          && (!TEST_ID_PATTERN.test(String(request.testId))
            || (request.status !== "in_progress"
              && !data.notificationChannelTests[request.testId])))) {
      throw new Error("admin store notificationChannelRequests contains an invalid request");
    }
    assertNoSecretMaterial(request, `notificationChannelRequests.${keyHash}`);
    for (const key of ["action", "createdAt", "updatedAt"]) {
      if (typeof request[key] !== "string" || !request[key]) {
        throw new Error(`admin store notification channel request ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(request.createdAt))
        || !Number.isFinite(Date.parse(request.updatedAt))) {
      throw new Error("admin store notification channel request timestamps are invalid");
    }
    if (request.status === "in_progress" && request.action !== "notification.channel.test") {
      throw new Error("admin store notification channel request state is invalid");
    }
  }
}

export function channelProviderFromData(data) {
  return Object.values(data.notificationChannels || {})
    .filter((channel) => channel.enabled)
    .sort((left, right) => String(left.channelId).localeCompare(String(right.channelId)));
}

export function deliveryIdForChannel(eventId, channelId) {
  if (!channelId) {
    return `ntd_${crypto.createHash("sha256").update(eventId).digest("hex").slice(0, 32)}`;
  }
  return `ntd_${crypto.createHash("sha256")
    .update(`${eventId}\0${channelId}`)
    .digest("hex")
    .slice(0, 32)}`;
}

export function signWebhook(secret, timestamp, nonce, body) {
  return `v1=${crypto.createHmac("sha256", secret)
    .update(`${timestamp}.${nonce}.${body}`)
    .digest("hex")}`;
}

function ipv4IsPublic(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part)
    || part < 0
    || part > 255)) {
    return false;
  }
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && [0, 2].includes(c)) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false;
  return true;
}

function expandIpv6(address) {
  const trimmed = address.toLowerCase().split("%")[0];
  if (!net.isIPv6(trimmed)) return null;
  if (trimmed.includes(".")) {
    const lastColon = trimmed.lastIndexOf(":");
    const ipv4 = trimmed.slice(lastColon + 1);
    if (!net.isIPv4(ipv4)) return null;
    const octets = ipv4.split(".").map(Number);
    const hex = `${((octets[0] << 8) | octets[1]).toString(16)}:${
      ((octets[2] << 8) | octets[3]).toString(16)}`;
    const prefix = trimmed.slice(0, lastColon + 1);
    return expandIpv6(`${prefix}${hex}`);
  }
  const [left, right = ""] = trimmed.split("::");
  const leftParts = left ? left.split(":") : [];
  const rightParts = right ? right.split(":") : [];
  const missing = 8 - leftParts.length - rightParts.length;
  if (missing < 0 || (!trimmed.includes("::") && missing !== 0)) return null;
  const parts = [...leftParts, ...Array(missing).fill("0"), ...rightParts];
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) {
    return null;
  }
  return parts.map((part) => parseInt(part, 16));
}

export function isPublicAddress(address) {
  const value = String(address || "").split("%")[0];
  const family = net.isIP(value);
  if (family === 4) return ipv4IsPublic(value);
  if (family !== 6) return false;
  const parts = expandIpv6(value);
  if (!parts) return false;
  if (parts.slice(0, 5).every((part) => part === 0) && parts[5] === 0xffff) {
    const ipv4 = [
      parts[6] >> 8,
      parts[6] & 0xff,
      parts[7] >> 8,
      parts[7] & 0xff,
    ].join(".");
    return ipv4IsPublic(ipv4);
  }
  if (parts.every((part) => part === 0) || (parts.slice(0, 7).every((part) => part === 0)
    && parts[7] === 1)) {
    return false;
  }
  if ((parts[0] & 0xfe00) === 0xfc00 || (parts[0] & 0xffc0) === 0xfe80) {
    return false;
  }
  if ((parts[0] & 0xff00) === 0xff00) return false;
  if (parts[0] === 0x2001 && parts[1] === 0x0db8) return false;
  if ((parts[0] === 0x2001 && (parts[1] & 0xfff0) === 0x0010)
      || (parts[0] === 0x2001 && (parts[1] & 0xfff0) === 0x0020)) {
    return false;
  }
  if (parts[0] === 0x2002 || (parts[0] === 0x0064 && parts[1] === 0xff9b)) {
    return false;
  }
  return true;
}

export function hostAllowed(hostname, allowlist) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  return (allowlist || []).some((entry) => {
    const allowed = String(entry || "").toLowerCase().replace(/\.$/, "");
    if (!allowed) return false;
    if (allowed.startsWith("*.")) {
      const suffix = allowed.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }
    return host === allowed;
  });
}

export async function validateOutboundUrl(rawUrl, options = {}) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw Object.assign(new Error("outbound URL is invalid"), { code: "transport_invalid_url" });
  }
  const protocols = options.protocols || ["https:"];
  const allowedPorts = options.allowedPorts || ["443"];
  const defaultPort = parsed.protocol === "tls:" ? SYSLOG_PORT : "443";
  const effectivePort = parsed.port || defaultPort;
  if (!protocols.includes(parsed.protocol)
      || parsed.username
      || parsed.password
      || !allowedPorts.includes(effectivePort)) {
    throw Object.assign(new Error("outbound URL is not allowed"), {
      code: "transport_url_rejected",
    });
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostAllowed(hostname, options.allowlist || [])) {
    throw Object.assign(new Error("outbound host is not allowlisted"), {
      code: "transport_host_not_allowed",
    });
  }
  let addresses;
  if (net.isIP(hostname)) {
    addresses = [{ address: hostname, family: net.isIP(hostname) }];
  } else {
    const resolver = options.dnsResolver || dns.lookup;
    try {
      addresses = await resolver(hostname, { all: true, verbatim: true });
    } catch {
      throw Object.assign(new Error("outbound host could not be resolved"), {
        code: "transport_unavailable",
      });
    }
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw Object.assign(new Error("outbound host has no addresses"), {
      code: "transport_unavailable",
    });
  }
  if (addresses.some((entry) => !isPublicAddress(entry.address))) {
    throw Object.assign(new Error("outbound host resolves to a private address"), {
      code: "transport_private_address",
    });
  }
  return {
    parsed,
    addresses: addresses.map((entry) => ({
      address: String(entry.address),
      family: Number(entry.family) || net.isIP(String(entry.address)),
    })),
  };
}

function pinnedLookup(addresses) {
  return (hostname, options, callback) => {
    const requestedFamily = typeof options === "number" ? options : options?.family;
    const selected = addresses.find((entry) => !requestedFamily || entry.family === requestedFamily)
      || addresses[0];
    if (!selected) {
      callback(Object.assign(new Error("no validated address"), { code: "transport_unavailable" }));
      return;
    }
    if (options?.all) callback(null, [selected]);
    else callback(null, selected.address, selected.family);
  };
}

function requestOnce(options) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = https.request({
      protocol: "https:",
      hostname: options.url.hostname,
      port: 443,
      path: `${options.url.pathname}${options.url.search}`,
      method: options.method || "POST",
      headers: options.headers,
      servername: options.url.hostname,
      lookup: pinnedLookup(options.addresses),
      timeout: options.timeoutMs,
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        if (settled) return;
        bytes += chunk.length;
        if (bytes > options.maxResponseBytes) {
          response.destroy();
          request.destroy(Object.assign(new Error("response is too large"), {
            code: "transport_response_too_large",
          }));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        finish(null, {
          statusCode: Number(response.statusCode) || 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
      response.on("error", (error) => finish(error));
    });
    request.on("timeout", () => {
      request.destroy(Object.assign(new Error("outbound request timed out"), {
        code: "transport_timeout",
      }));
    });
    request.on("error", (error) => finish(error));
    if (options.body) request.write(options.body);
    request.end();
  });
}

export async function secureHttpsRequest(options) {
  let url = new URL(options.url);
  let method = options.method || "POST";
  let body = options.body || "";
  const maxRedirects = Number.isSafeInteger(options.maxRedirects)
    ? options.maxRedirects
    : DEFAULT_MAX_REDIRECTS;
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const validated = await validateOutboundUrl(url.href, {
      allowlist: options.allowlist,
      dnsResolver: options.dnsResolver,
    });
    const response = await (options.requestImpl || requestOnce)({
      url: validated.parsed,
      addresses: validated.addresses,
      method,
      headers: {
        ...options.headers,
        host: validated.parsed.host,
        "content-length": Buffer.byteLength(body),
      },
      body,
      timeoutMs: options.timeoutMs || DEFAULT_TIMEOUT_MS,
      maxResponseBytes: options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES,
    });
    if (![301, 302, 303, 307, 308].includes(response.statusCode)) return response;
    const location = String(response.headers?.location || "");
    if (!location || redirects === maxRedirects) {
      throw Object.assign(new Error("redirect is not allowed"), {
        code: "transport_redirect_rejected",
      });
    }
    if (![307, 308].includes(response.statusCode)) {
      throw Object.assign(new Error("redirect would change the request method"), {
        code: "transport_redirect_rejected",
      });
    }
    url = new URL(location, url);
    method = "POST";
    body = options.body || "";
  }
  throw Object.assign(new Error("redirect limit exceeded"), {
    code: "transport_redirect_rejected",
  });
}

export async function secureTlsSyslog(options) {
  const validated = await validateOutboundUrl(options.url, {
    allowlist: options.allowlist,
    dnsResolver: options.dnsResolver,
    protocols: ["tls:"],
    allowedPorts: [SYSLOG_PORT],
  });
  const frame = syslogOctetFrame(options.message);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const connect = options.connectImpl || tls.connect;
    const socket = connect({
      host: validated.parsed.hostname,
      port: Number(validated.parsed.port || SYSLOG_PORT),
      servername: validated.parsed.hostname,
      rejectUnauthorized: true,
      lookup: pinnedLookup(validated.addresses),
    }, () => {
      socket.write(frame, "utf8", (error) => {
        if (error) {
          finish(error);
          socket.destroy();
          return;
        }
        socket.destroy();
        finish(null, { ok: true, protocol: "syslog-tls" });
      });
    });
    socket.setTimeout(options.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
      socket.destroy(Object.assign(new Error("syslog request timed out"), {
        code: "transport_timeout",
      }));
    });
    socket.on("error", (error) => finish(error));
  });
}

function channelEventPayload(delivery) {
  return {
    schemaVersion: 1,
    event: publicNotificationDelivery(delivery),
  };
}

function emailPayload(channel, delivery) {
  const event = publicNotificationDelivery(delivery);
  const subject = `${channel.config.subjectPrefix || "[Magpie Enterprise]"} `
    + `[${event.severity}] ${event.eventType}`;
  const text = [
    event.summary,
    `Event: ${event.eventId}`,
    `Type: ${event.eventType}`,
    `Target: ${event.targetType || "-"} ${event.targetId || ""}`.trim(),
    `Occurred: ${event.occurredAt}`,
  ].join("\n");
  return {
    subject: safeText(subject, 200),
    text,
    to: [...channel.config.recipients],
    from: channel.config.from,
  };
}

function imPayload(channel, delivery) {
  const event = publicNotificationDelivery(delivery);
  const text = `[${event.severity}] ${event.summary}\n`
    + `eventId=${event.eventId}\ndeliveryId=${event.deliveryId}`;
  if (channel.provider === "feishu") {
    return { msg_type: "text", content: { text } };
  }
  if (channel.provider === "slack") return { text };
  if (channel.provider === "teams") {
    return {
      type: "message",
      attachments: [{
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          type: "AdaptiveCard",
          version: "1.4",
          body: [{ type: "TextBlock", text, wrap: true }],
        },
      }],
    };
  }
  return channelEventPayload(delivery);
}

function ticketingPayload(channel, delivery) {
  const event = publicNotificationDelivery(delivery);
  return {
    schemaVersion: 1,
    title: safeText(`[Magpie][${event.severity}] ${event.eventType}`, 200),
    description: event.summary,
    externalReference: event.deliveryId,
    priority: event.severity === "critical" ? "high" : "normal",
    projectKey: channel.config.projectKey || "",
    queue: channel.config.queue || "",
    event,
  };
}

function resolveSecret(ref, env, required = false) {
  if (!ref) {
    if (required) {
      throw Object.assign(new Error("notification channel secret is unavailable"), {
        code: "transport_secret_unavailable",
      });
    }
    return "";
  }
  const value = String(env?.[ref] || "");
  if (!value || value.length < 32) {
    throw Object.assign(new Error("notification channel secret is unavailable"), {
      code: "transport_secret_unavailable",
    });
  }
  return value;
}

function resolveEndpoint(channel, env, options = {}) {
  const ref = channel.config.endpointRef;
  const raw = ref ? String(env?.[ref] || "") : channel.config.endpoint;
  if (!raw) {
    throw Object.assign(new Error("notification channel endpoint is unavailable"), {
      code: "transport_endpoint_unavailable",
    });
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw Object.assign(new Error("notification channel endpoint is invalid"), {
      code: "transport_invalid_url",
    });
  }
  const protocols = options.protocols || ["https:"];
  const allowedPorts = options.allowedPorts || ["443"];
  const defaultPort = parsed.protocol === "tls:" ? SYSLOG_PORT : "443";
  if (!protocols.includes(parsed.protocol)
      || parsed.username
      || parsed.password
      || !allowedPorts.includes(parsed.port || defaultPort)) {
    throw Object.assign(new Error("notification channel endpoint is not allowed"), {
      code: "transport_url_rejected",
    });
  }
  return parsed.toString();
}

export class NotificationChannelTransport {
  constructor(store, options = {}) {
    this.store = store;
    this.env = options.env || process.env;
    this.allowlist = options.allowlist || [];
    this.emailRecipientDomains = options.emailRecipientDomains || [];
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.maxResponseBytes = options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;
    this.maxSiemEventBytes = options.maxSiemEventBytes || DEFAULT_SIEM_MAX_EVENT_BYTES;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.dnsResolver = options.dnsResolver;
    this.requestImpl = options.requestImpl;
    this.syslogConnectImpl = options.syslogConnectImpl;
    this.now = options.now || (() => new Date());
  }

  async resolveChannel(channelId) {
    return this.store.read((data) => {
      const channel = data.notificationChannels[channelId];
      return channel ? structuredClone(channel) : null;
    });
  }

  async deliver(delivery) {
    if (!delivery.channelId) {
      throw Object.assign(new Error("delivery has no notification channel"), {
        code: "transport_channel_unavailable",
      });
    }
    const channel = await this.resolveChannel(delivery.channelId);
    if (!channel || !channel.enabled) {
      throw Object.assign(new Error("notification channel is unavailable"), {
        code: "transport_channel_unavailable",
      });
    }
    return this.sendChannelEvent(channel, delivery);
  }

  async sendChannelEvent(channel, delivery) {
    if (channel.type === "siem") {
      return this.sendSiemEvent(channel, delivery);
    }
    const endpoint = resolveEndpoint(channel, this.env, endpointOptionsForChannel(
      channel.type,
      channel.provider,
    ));
    const secret = resolveSecret(
      channel.secretRef,
      this.env,
      channel.type === "webhook",
    );
    let payload;
    if (channel.type === "email") {
      this.validateEmailRecipients(channel);
      payload = emailPayload(channel, delivery);
    } else if (channel.type === "im") {
      payload = imPayload(channel, delivery);
    } else if (channel.type === "ticketing") {
      payload = ticketingPayload(channel, delivery);
    } else {
      payload = channelEventPayload(delivery);
    }
    const body = JSON.stringify(payload);
    const headers = {
      "content-type": "application/json; charset=utf-8",
      "user-agent": "magpie-enterprise-notifications/1",
      "x-magpie-event-id": String(delivery.eventId || ""),
      "x-magpie-delivery-id": String(delivery.deliveryId || ""),
      "x-magpie-channel-id": String(channel.channelId),
    };
    if (channel.type === "webhook") {
      const timestamp = String(Math.floor(this.now().getTime() / 1000));
      const nonce = crypto.randomBytes(16).toString("hex");
      headers["x-magpie-timestamp"] = timestamp;
      headers["x-magpie-nonce"] = nonce;
      headers["x-magpie-signature"] = signWebhook(secret, timestamp, nonce, body);
      headers["x-magpie-webhook-version"] = "1";
    } else if (secret) {
      headers.authorization = `Bearer ${secret}`;
    }
    const response = await secureHttpsRequest({
      url: endpoint,
      method: "POST",
      headers,
      body,
      allowlist: this.allowlist,
      timeoutMs: channel.config.timeoutMs || this.timeoutMs,
      maxResponseBytes: this.maxResponseBytes,
      maxRedirects: this.maxRedirects,
      dnsResolver: this.dnsResolver,
      requestImpl: this.requestImpl,
    });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Object.assign(new Error("notification endpoint rejected the request"), {
        statusCode: response.statusCode,
        code: response.statusCode === 429
          ? "transport_rate_limited"
          : response.statusCode >= 500
            ? "transport_server_error"
            : "transport_rejected",
      });
    }
    return {
      ok: true,
      statusCode: response.statusCode,
    };
  }

  async sendSiemEvent(channel, delivery) {
    const endpointOptions = endpointOptionsForChannel(channel.type, channel.provider);
    const endpoint = resolveEndpoint(channel, this.env, endpointOptions);
    if (channel.provider === "syslog-tls") {
      const message = syslogRfc5424(delivery, channel.config);
      assertSiemEventSize(message, this.maxSiemEventBytes);
      return secureTlsSyslog({
        url: endpoint,
        message,
        allowlist: this.allowlist,
        timeoutMs: channel.config.timeoutMs || this.timeoutMs,
        dnsResolver: this.dnsResolver,
        connectImpl: this.syslogConnectImpl,
      });
    }

    const secret = resolveSecret(channel.secretRef, this.env, false);
    const payload = channel.provider === "otlp-http"
      ? otlpLogsPayload(delivery, { serviceName: channel.config.serviceName })
      : httpCollectorPayload(delivery);
    const body = JSON.stringify(payload);
    assertSiemEventSize(body, this.maxSiemEventBytes);
    const headers = {
      "content-type": "application/json; charset=utf-8",
      "user-agent": "magpie-enterprise-siem/1",
      "x-magpie-event-id": String(delivery.eventId || ""),
      "x-magpie-delivery-id": String(delivery.deliveryId || ""),
      "x-magpie-channel-id": String(channel.channelId),
    };
    if (secret) headers.authorization = `Bearer ${secret}`;
    const response = await secureHttpsRequest({
      url: endpoint,
      method: "POST",
      headers,
      body,
      allowlist: this.allowlist,
      timeoutMs: channel.config.timeoutMs || this.timeoutMs,
      maxResponseBytes: this.maxResponseBytes,
      maxRedirects: this.maxRedirects,
      dnsResolver: this.dnsResolver,
      requestImpl: this.requestImpl,
    });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Object.assign(new Error("SIEM collector rejected the event"), {
        statusCode: response.statusCode,
        code: response.statusCode === 429
          ? "transport_rate_limited"
          : response.statusCode >= 500
            ? "transport_server_error"
            : "transport_rejected",
      });
    }
    return {
      ok: true,
      statusCode: response.statusCode,
      protocol: channel.provider,
    };
  }

  validateEmailRecipients(channel) {
    const global = new Set(this.emailRecipientDomains);
    const local = new Set(channel.config.recipientDomains || []);
    for (const recipient of channel.config.recipients || []) {
      const domain = emailDomain(recipient);
      if (global.size > 0 && !global.has(domain)) {
        throw Object.assign(new Error("email recipient domain is not allowed"), {
          code: "transport_recipient_domain_rejected",
        });
      }
      if (local.size > 0 && !local.has(domain)) {
        throw Object.assign(new Error("email recipient domain is not allowed"), {
          code: "transport_recipient_domain_rejected",
        });
      }
    }
  }

  async test(channel) {
    const now = this.now();
    const testId = `nct_${crypto.createHash("sha256")
      .update(`${channel.channelId}\0${now.toISOString()}\0${crypto.randomUUID()}`)
      .digest("hex")
      .slice(0, 24)}`;
    const event = {
      deliveryId: `ntd_${crypto.createHash("sha256")
        .update(`channel-test\0${testId}`)
        .digest("hex")
        .slice(0, 32)}`,
      eventId: `evt_channel_test_${testId.slice(4)}`,
      schemaVersion: 1,
      eventType: "operation.failed",
      severity: "warning",
      occurredAt: now.toISOString(),
      organizationId: "notification_channel_test",
      actorSubjectId: "system_notification_test",
      actorEmail: "",
      targetType: "notification_channel",
      targetId: channel.channelId,
      targetOrgUnitId: "",
      operationId: "",
      requestId: "",
      errorCode: "",
      summary: `Notification channel ${channel.channelId} test`,
      dataClassification: "L0",
      status: "delivery_test",
      attemptCount: 0,
      nextAttemptAt: "",
      leaseExpiresAt: "",
      lastErrorCode: "",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      deliveredAt: "",
    };
    await this.sendChannelEvent(channel, event);
    return testId;
  }
}
