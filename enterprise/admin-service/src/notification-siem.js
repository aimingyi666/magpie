const FIELD_LIMIT = 320;

export const SIEM_SCHEMA_VERSION = 1;
export const SIEM_SOURCE = "magpie-enterprise";
export const SIEM_CRITICAL_VISIBILITY_TARGET_MS = 5 * 60 * 1000;
export const DEFAULT_SIEM_MAX_EVENT_BYTES = 32 * 1024;

const OTLP_SEVERITY = Object.freeze({
  info: { number: 9, text: "INFO" },
  warning: { number: 13, text: "WARN" },
  critical: { number: 17, text: "ERROR" },
});

const SYSLOG_SEVERITY = Object.freeze({
  info: 6,
  warning: 4,
  critical: 2,
});

function safeText(value, maxLength = FIELD_LIMIT) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maxLength);
}

function validTimestamp(value) {
  return Number.isFinite(Date.parse(value || ""))
    ? new Date(value).toISOString()
    : new Date(0).toISOString();
}

function timestampToUnixNano(value) {
  return (BigInt(Date.parse(value)) * 1_000_000n).toString();
}

export function publicSiemEvent(delivery) {
  return {
    schemaVersion: SIEM_SCHEMA_VERSION,
    source: SIEM_SOURCE,
    eventId: safeText(delivery?.eventId, 200),
    deliveryId: safeText(delivery?.deliveryId, 80),
    eventType: safeText(delivery?.eventType, 80),
    severity: safeText(delivery?.severity, 20),
    occurredAt: validTimestamp(delivery?.occurredAt),
    organizationId: safeText(delivery?.organizationId),
    actorSubjectId: safeText(delivery?.actorSubjectId),
    targetType: safeText(delivery?.targetType, 80),
    targetId: safeText(delivery?.targetId),
    targetOrgUnitId: safeText(delivery?.targetOrgUnitId),
    operationId: safeText(delivery?.operationId),
    requestId: safeText(delivery?.requestId),
    errorCode: safeText(delivery?.errorCode, 80),
    dataClassification: "L0",
  };
}

export function httpCollectorPayload(delivery) {
  return {
    schemaVersion: SIEM_SCHEMA_VERSION,
    event: publicSiemEvent(delivery),
  };
}

function otlpAttribute(key, value) {
  return {
    key,
    value: { stringValue: safeText(value) },
  };
}

export function otlpLogsPayload(delivery, options = {}) {
  const event = publicSiemEvent(delivery);
  const severity = OTLP_SEVERITY[event.severity] || OTLP_SEVERITY.info;
  const attributes = [
    ["magpie.event.id", event.eventId],
    ["magpie.delivery.id", event.deliveryId],
    ["magpie.event.type", event.eventType],
    ["magpie.organization.id", event.organizationId],
    ["magpie.actor.subject_id", event.actorSubjectId],
    ["magpie.target.type", event.targetType],
    ["magpie.target.id", event.targetId],
    ["magpie.target.org_unit_id", event.targetOrgUnitId],
    ["magpie.operation.id", event.operationId],
    ["magpie.request.id", event.requestId],
    ["magpie.error.code", event.errorCode],
    ["magpie.data.classification", event.dataClassification],
  ].filter(([, value]) => value);
  return {
    resourceLogs: [{
      resource: {
        attributes: [
          otlpAttribute("service.name", options.serviceName || "magpie-enterprise-admin"),
          otlpAttribute("service.namespace", "magpie-enterprise"),
        ],
      },
      scopeLogs: [{
        scope: {
          name: "magpie.enterprise.notifications",
          version: String(SIEM_SCHEMA_VERSION),
        },
        logRecords: [{
          timeUnixNano: timestampToUnixNano(event.occurredAt),
          observedTimeUnixNano: timestampToUnixNano(new Date().toISOString()),
          severityNumber: severity.number,
          severityText: severity.text,
          body: {
            stringValue: `${event.eventType} ${event.eventId}`,
          },
          attributes: attributes.map(([key, value]) => otlpAttribute(key, value)),
        }],
      }],
    }],
  };
}

export function syslogPriority(severity, facility = 10) {
  const priorityFacility = Number.isSafeInteger(Number(facility))
    && Number(facility) >= 0
    && Number(facility) <= 23
    ? Number(facility)
    : 10;
  return priorityFacility * 8 + (SYSLOG_SEVERITY[String(severity)] || SYSLOG_SEVERITY.info);
}

export function syslogRfc5424(delivery, config = {}) {
  const event = publicSiemEvent(delivery);
  const hostname = safeText(config.hostname || "magpie-enterprise", 255);
  const appName = safeText(config.appName || "magpie-ent", 48);
  const message = JSON.stringify({
    schemaVersion: SIEM_SCHEMA_VERSION,
    event,
  });
  return `<${syslogPriority(event.severity, config.facility)}>1 `
    + `${event.occurredAt} ${hostname} ${appName} - MAGPIE - ${message}`;
}

export function syslogOctetFrame(message) {
  const bytes = Buffer.byteLength(message, "utf8");
  return `${bytes} ${message}`;
}

export function assertSiemEventSize(body, maxEventBytes = DEFAULT_SIEM_MAX_EVENT_BYTES) {
  const bytes = Buffer.byteLength(body, "utf8");
  if (bytes > maxEventBytes) {
    throw Object.assign(new Error("SIEM event is too large"), {
      code: "transport_payload_too_large",
    });
  }
  return bytes;
}
