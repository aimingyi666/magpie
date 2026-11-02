import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { JsonStore } from "../src/store.js";
import {
  NotificationChannelTransport,
  createNotificationChannel,
} from "../src/notification-channels.js";
import {
  NotificationDispatcher,
  claimNotificationDelivery,
  enqueueNotification,
} from "../src/notification-outbox.js";
import {
  SIEM_SOURCE,
  httpCollectorPayload,
  otlpLogsPayload,
  publicSiemEvent,
  syslogPriority,
  syslogRfc5424,
} from "../src/notification-siem.js";

const SIEM_SECRET = "{{SECRET_siemcollectortoken}}-test-only-padding";
const FORBIDDEN_MARKERS = [
  "prompt-secret-marker",
  "reply-secret-marker",
  "tool-argument-secret-marker",
  "gateway-key-secret-marker",
  "token-hash-secret-marker",
  "cookie-secret-marker",
];

function event(overrides = {}) {
  return {
    eventId: `evt_security_${crypto.randomUUID()}`,
    eventType: "security.break_glass_used",
    severity: "critical",
    occurredAt: "2026-11-02T00:00:00.000Z",
    organizationId: "env_test",
    actorSubjectId: "adm_test",
    actorEmail: "admin@corp.example",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org-platform",
    operationId: "op_test",
    requestId: "req_test",
    errorCode: "security_policy_denied",
    summary: `Approval denied ${FORBIDDEN_MARKERS[0]}`,
    ...overrides,
  };
}

async function channelStore(t) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-notification-siem-"));
  const store = new JsonStore(path.join(temp, "admin-store.json"));
  await store.load();
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  return store;
}

function fakeSyslogSocket(onWrite) {
  const socket = new EventEmitter();
  socket.write = (value, encoding, callback) => {
    onWrite(value);
    callback();
  };
  socket.setTimeout = () => {};
  socket.destroy = () => {
    socket.destroyed = true;
  };
  return socket;
}

test("NOTIFY-01c SIEM projection has a fixed metadata-only schema", () => {
  const { delivery } = enqueueNotification({ notificationDeliveries: {} }, event({
    prompt: FORBIDDEN_MARKERS[0],
    reply: FORBIDDEN_MARKERS[1],
    toolArguments: { value: FORBIDDEN_MARKERS[2] },
    gatewayKey: FORBIDDEN_MARKERS[3],
    tokenHash: FORBIDDEN_MARKERS[4],
    cookie: FORBIDDEN_MARKERS[5],
  }));
  const projected = publicSiemEvent(delivery);
  assert.deepEqual(Object.keys(projected).sort(), [
    "actorSubjectId",
    "dataClassification",
    "deliveryId",
    "errorCode",
    "eventId",
    "eventType",
    "occurredAt",
    "operationId",
    "organizationId",
    "requestId",
    "schemaVersion",
    "severity",
    "source",
    "targetId",
    "targetOrgUnitId",
    "targetType",
  ].sort());
  assert.equal(projected.source, SIEM_SOURCE);
  assert.equal(projected.dataClassification, "L0");
  assert.equal(projected.eventId, delivery.eventId);
  const serialized = JSON.stringify(httpCollectorPayload(delivery));
  for (const marker of FORBIDDEN_MARKERS) {
    assert.equal(serialized.includes(marker), false, marker);
  }
  assert.equal(serialized.includes("summary"), false);
  assert.equal(serialized.includes("actorEmail"), false);
});

test("NOTIFY-01c HTTP collector receives only allowlisted metadata over pinned HTTPS", async (t) => {
  const store = await channelStore(t);
  const channel = createNotificationChannel({
    name: "Security collector",
    type: "siem",
    provider: "http-collector",
    eventTypes: ["security.break_glass_used"],
    secretRef: "MAGPIE_SIEM_TOKEN",
    config: {
      endpoint: "https://siem.example.test/events",
      timeoutMs: 2000,
    },
  }, { allowlist: ["siem.example.test"] });
  await store.mutate((data) => {
    data.notificationChannels[channel.channelId] = channel;
  });
  let request;
  const transport = new NotificationChannelTransport(store, {
    env: { MAGPIE_SIEM_TOKEN: SIEM_SECRET },
    allowlist: ["siem.example.test"],
    dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
    requestImpl: async (captured) => {
      request = captured;
      return { statusCode: 202, headers: {}, body: "" };
    },
  });
  const input = event();
  const { delivery } = enqueueNotification({ notificationDeliveries: {} }, input, {
    channelId: channel.channelId,
  });
  const result = await transport.deliver(delivery);
  assert.deepEqual(result, {
    ok: true,
    statusCode: 202,
    protocol: "http-collector",
  });
  assert.deepEqual(request.addresses, [{ address: "8.8.8.8", family: 4 }]);
  assert.equal(request.headers.authorization, `Bearer ${SIEM_SECRET}`);
  assert.equal(request.headers["x-magpie-event-id"], input.eventId);
  const body = JSON.parse(request.body);
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.event.eventId, input.eventId);
  assert.equal(body.event.eventType, "security.break_glass_used");
  assert.equal(body.event.severity, "critical");
  assert.equal(request.body.includes("Approval denied"), false);
  assert.equal(request.body.includes("admin@corp.example"), false);
});

test("NOTIFY-01c OTLP/HTTP JSON maps critical events to standard log records", () => {
  const { delivery } = enqueueNotification({ notificationDeliveries: {} }, event());
  const payload = otlpLogsPayload(delivery, { serviceName: "magpie-soc" });
  const resource = payload.resourceLogs[0].resource.attributes;
  assert.deepEqual(resource[0], {
    key: "service.name",
    value: { stringValue: "magpie-soc" },
  });
  const record = payload.resourceLogs[0].scopeLogs[0].logRecords[0];
  assert.equal(record.severityNumber, 17);
  assert.equal(record.severityText, "ERROR");
  assert.equal(record.body.stringValue, `${delivery.eventType} ${delivery.eventId}`);
  assert.equal(record.attributes.some((attribute) => (
    attribute.key === "magpie.event.id"
    && attribute.value.stringValue === delivery.eventId
  )), true);
  assert.equal(JSON.stringify(payload).includes("summary"), false);
  assert.equal(JSON.stringify(payload).includes("actorEmail"), false);
});

test("NOTIFY-01c Syslog/TLS uses RFC 5424 JSON and validates every address", async (t) => {
  const store = await channelStore(t);
  const channel = createNotificationChannel({
    name: "SOC syslog",
    type: "siem",
    provider: "syslog-tls",
    eventTypes: ["security.break_glass_used"],
    config: {
      endpoint: "tls://syslog.example.test:6514",
      hostname: "magpie-prod",
      appName: "magpie-ent",
      facility: 10,
    },
  }, { allowlist: ["syslog.example.test"] });
  await store.mutate((data) => {
    data.notificationChannels[channel.channelId] = channel;
  });
  let frame = "";
  let connectOptions;
  const transport = new NotificationChannelTransport(store, {
    allowlist: ["syslog.example.test"],
    dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
    syslogConnectImpl: (options, connected) => {
      connectOptions = options;
      const socket = fakeSyslogSocket((value) => {
        frame = value;
      });
      setImmediate(connected);
      return socket;
    },
  });
  const { delivery } = enqueueNotification({ notificationDeliveries: {} }, event(), {
    channelId: channel.channelId,
  });
  assert.deepEqual(await transport.deliver(delivery), {
    ok: true,
    protocol: "syslog-tls",
  });
  assert.equal(connectOptions.port, 6514);
  assert.equal(connectOptions.servername, "syslog.example.test");
  assert.equal(connectOptions.rejectUnauthorized, true);
  const octets = Number(frame.slice(0, frame.indexOf(" ")));
  assert.equal(octets, Buffer.byteLength(frame.slice(frame.indexOf(" ") + 1), "utf8"));
  const message = frame.slice(frame.indexOf(" ") + 1);
  assert.equal(message.startsWith(`<${syslogPriority("critical", 10)}>1 `), true);
  assert.equal(message.includes("magpie-prod magpie-ent"), true);
  assert.equal(message.includes(delivery.eventId), true);
  assert.equal(message.includes("Approval denied"), false);

  const privateStore = await channelStore(t);
  await privateStore.mutate((data) => {
    data.notificationChannels[channel.channelId] = channel;
  });
  const privateTransport = new NotificationChannelTransport(privateStore, {
    allowlist: ["syslog.example.test"],
    dnsResolver: async () => [{ address: "10.0.0.8", family: 4 }],
    syslogConnectImpl: () => {
      throw new Error("must not connect");
    },
  });
  await assert.rejects(
    privateTransport.deliver(delivery),
    (error) => error.code === "transport_private_address",
  );
});

test("NOTIFY-01c channel validation rejects unsafe protocols and secret-bearing syslog", () => {
  assert.throws(() => createNotificationChannel({
    name: "Unsafe collector",
    type: "siem",
    provider: "http-collector",
    config: { endpoint: "tls://siem.example.test:6514" },
  }), /HTTPS/);
  assert.throws(() => createNotificationChannel({
    name: "Unsafe syslog",
    type: "siem",
    provider: "syslog-tls",
    secretRef: "MAGPIE_SIEM_TOKEN",
    config: { endpoint: "tls://syslog.example.test:6514" },
  }), /not supported/);
  assert.throws(() => createNotificationChannel({
    name: "Wrong syslog port",
    type: "siem",
    provider: "syslog-tls",
    config: { endpoint: "tls://syslog.example.test:443" },
  }), /port 6514/);
});

test("NOTIFY-01c critical events outrank lower severities and polling meets the five-minute bound", () => {
  const data = { notificationDeliveries: {} };
  enqueueNotification(data, event({
    eventId: "evt_security_info_first",
    eventType: "security.anomaly_detected",
    severity: "info",
    occurredAt: "2026-11-02T00:00:00.000Z",
  }));
  enqueueNotification(data, event({
    eventId: "evt_security_critical_second",
    occurredAt: "2026-11-02T00:01:00.000Z",
  }));
  const claimed = claimNotificationDelivery(data, {
    now: new Date("2026-11-02T00:01:00.000Z"),
    ownerId: "worker_test",
  });
  assert.equal(claimed.eventId, "evt_security_critical_second");
  assert.throws(() => new NotificationDispatcher({}, {
    transport: async () => ({ ok: true }),
    pollIntervalMs: 5 * 60 * 1000 + 1,
  }), /5-minute SIEM target/);
  const message = syslogRfc5424({
    ...enqueueNotification(data, event()).delivery,
  }, {});
  assert.equal(message.includes('"schemaVersion":1'), true);
});
