import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { JsonStore } from "../src/store.js";
import {
  NotificationChannelTransport,
  createNotificationChannel,
  publicNotificationChannel,
  secureHttpsRequest,
  signWebhook,
  validateOutboundUrl,
} from "../src/notification-channels.js";
import {
  enqueueNotification,
  enqueueNotificationFanout,
} from "../src/notification-outbox.js";

const TEST_SECRET = "test-only-webhook-secret-0000000000000001";

function event(overrides = {}) {
  return {
    eventId: `evt_channel_${crypto.randomUUID()}`,
    eventType: "approval.requested",
    severity: "warning",
    occurredAt: "2026-11-02T00:00:00.000Z",
    organizationId: "env_test",
    actorSubjectId: "adm_test",
    actorEmail: "admin@corp.example",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org-platform",
    operationId: "op_test",
    requestId: "req_test",
    errorCode: "",
    summary: "Approval request needs review",
    ...overrides,
  };
}

async function channelStore(t) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-notification-channels-"));
  const store = new JsonStore(path.join(temp, "admin-store.json"));
  await store.load();
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  return store;
}

test("NOTIFY-01b public channel projections contain no secret values", () => {
  const channel = createNotificationChannel({
    name: "Security webhook",
    type: "webhook",
    provider: "generic",
    eventTypes: ["operation.failed"],
    secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
    config: {
      endpointRef: "MAGPIE_SECURITY_WEBHOOK_URL",
      timeoutMs: 5000,
    },
  });
  const projected = publicNotificationChannel(channel);
  assert.equal(projected.secretRef, "MAGPIE_NOTIFICATION_WEBHOOK_SECRET");
  assert.equal(projected.secretConfigured, true);
  assert.equal(projected.config.endpointRef, "MAGPIE_SECURITY_WEBHOOK_URL");
  assert.equal(JSON.stringify(projected).includes(TEST_SECRET), false);
  assert.throws(() => createNotificationChannel({
    name: "Unsafe webhook",
    type: "webhook",
    provider: "generic",
    secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
    config: {
      endpointRef: "MAGPIE_SECURITY_WEBHOOK_URL",
      token: TEST_SECRET,
    },
  }), /secret reference/);
});

test("NOTIFY-01b email recipients obey deployment and channel domain allowlists", () => {
  const options = { emailRecipientDomains: ["corp.example"] };
  const channel = createNotificationChannel({
    name: "Security mailbox",
    type: "email",
    provider: "mail-gateway",
    secretRef: "MAGPIE_NOTIFICATION_EMAIL_GATEWAY_TOKEN",
    config: {
      endpointRef: "MAGPIE_EMAIL_GATEWAY_URL",
      from: "security@corp.example",
      recipients: ["soc@corp.example"],
      recipientDomains: ["corp.example"],
    },
  }, options);
  assert.deepEqual(channel.config.recipients, ["soc@corp.example"]);
  assert.throws(() => createNotificationChannel({
    name: "External mailbox",
    type: "email",
    provider: "mail-gateway",
    secretRef: "MAGPIE_NOTIFICATION_EMAIL_GATEWAY_TOKEN",
    config: {
      endpointRef: "MAGPIE_EMAIL_GATEWAY_URL",
      from: "security@corp.example",
      recipients: ["personal@example.net"],
    },
  }, options), /deployment allowlist/);
});

test("NOTIFY-01b webhook delivery is signed and uses only validated pinned addresses", async (t) => {
  const store = await channelStore(t);
  const channel = createNotificationChannel({
    name: "Signed webhook",
    type: "webhook",
    provider: "generic",
    secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
    config: {
      endpoint: "https://hooks.example.test/notify",
    },
  }, { allowlist: ["hooks.example.test"] });
  await store.mutate((data) => {
    data.notificationChannels[channel.channelId] = channel;
  });
  let captured;
  const transport = new NotificationChannelTransport(store, {
    env: { MAGPIE_NOTIFICATION_WEBHOOK_SECRET: TEST_SECRET },
    allowlist: ["hooks.example.test"],
    dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
    now: () => new Date("2026-11-02T00:00:00.000Z"),
    requestImpl: async (request) => {
      captured = request;
      return { statusCode: 204, headers: {}, body: "" };
    },
  });
  const { delivery } = enqueueNotification({ notificationDeliveries: {} }, event(), {
    channelId: channel.channelId,
  });
  const result = await transport.deliver(delivery);
  assert.deepEqual(result, { ok: true, statusCode: 204 });
  assert.equal(captured.url.hostname, "hooks.example.test");
  assert.deepEqual(captured.addresses, [{ address: "8.8.8.8", family: 4 }]);
  assert.equal(
    captured.headers["x-magpie-timestamp"],
    String(Math.floor(new Date("2026-11-02T00:00:00.000Z").getTime() / 1000)),
  );
  assert.equal(typeof captured.headers["x-magpie-nonce"], "string");
  assert.equal(
    captured.headers["x-magpie-signature"],
    signWebhook(
      TEST_SECRET,
      captured.headers["x-magpie-timestamp"],
      captured.headers["x-magpie-nonce"],
      captured.body,
    ),
  );
  const payload = JSON.parse(captured.body);
  assert.equal(payload.event.occurredAt, "2026-11-02T00:00:00.000Z");
  assert.equal(payload.event.targetType, "user");
  assert.equal(payload.event.targetId, "usr_alice");
});

test("NOTIFY-01b outbound validation rejects private, metadata and non-allowlisted hosts", async () => {
  await assert.rejects(
    validateOutboundUrl("https://evil.example.test/hook", {
      allowlist: ["hooks.example.test"],
      dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
    }),
    (error) => error.code === "transport_host_not_allowed",
  );
  for (const address of ["127.0.0.1", "10.0.0.7", "169.254.169.254", "::1", "fd00::1"]) {
    await assert.rejects(
      validateOutboundUrl("https://hooks.example.test/hook", {
        allowlist: ["hooks.example.test"],
        dnsResolver: async () => [{
          address,
          family: address.includes(":") ? 6 : 4,
        }],
      }),
      (error) => error.code === "transport_private_address",
      address,
    );
  }
  const validated = await validateOutboundUrl("https://hooks.example.test/hook", {
    allowlist: ["hooks.example.test"],
    dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
  });
  assert.equal(validated.parsed.hostname, "hooks.example.test");
  assert.deepEqual(validated.addresses, [{ address: "8.8.8.8", family: 4 }]);
});

test("NOTIFY-01b redirects are limited and every hop is independently validated", async () => {
  const calls = [];
  const response = await secureHttpsRequest({
    url: "https://hooks.example.test/first",
    allowlist: ["hooks.example.test", "events.example.test"],
    dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
    requestImpl: async (request) => {
      calls.push(request.url.href);
      if (calls.length === 1) {
        return {
          statusCode: 307,
          headers: { location: "https://events.example.test/second" },
          body: "",
        };
      }
      return { statusCode: 202, headers: {}, body: "accepted" };
    },
  });
  assert.equal(response.statusCode, 202);
  assert.deepEqual(calls, [
    "https://hooks.example.test/first",
    "https://events.example.test/second",
  ]);
  await assert.rejects(
    secureHttpsRequest({
      url: "https://hooks.example.test/first",
      allowlist: ["hooks.example.test"],
      dnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
      requestImpl: async () => ({
        statusCode: 308,
        headers: { location: "https://not-allowed.example.test/second" },
        body: "",
      }),
    }),
    (error) => error.code === "transport_host_not_allowed",
  );
});

test("NOTIFY-01b fanout deduplicates by event and channel while preserving legacy IDs", () => {
  const webhook = createNotificationChannel({
    name: "Webhook",
    type: "webhook",
    provider: "generic",
    secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
    config: { endpointRef: "WEBHOOK_URL" },
  });
  const im = createNotificationChannel({
    name: "IM",
    type: "im",
    provider: "generic",
    eventTypes: ["approval.requested"],
    config: { endpointRef: "IM_URL" },
  });
  const disabled = { ...im, channelId: `nch_${"f".repeat(24)}`, enabled: false };
  const data = { notificationDeliveries: {} };
  const fanoutEvent = event();
  const first = enqueueNotificationFanout(
    data,
    fanoutEvent,
    [webhook, im, disabled],
  );
  assert.equal(first.insertedCount, 2);
  assert.deepEqual(
    first.deliveries.map((delivery) => delivery.channelId).sort(),
    [webhook.channelId, im.channelId].sort(),
  );
  const duplicate = enqueueNotificationFanout(data, fanoutEvent, [webhook, im, disabled]);
  assert.equal(duplicate.insertedCount, 0);
  assert.equal(Object.keys(data.notificationDeliveries).length, 2);
  const legacyInput = event();
  const legacy = enqueueNotification(data, legacyInput);
  assert.equal(legacy.delivery.deliveryId, `ntd_${crypto.createHash("sha256")
    .update(legacyInput.eventId)
    .digest("hex")
    .slice(0, 32)}`);
});

test("NOTIFY-01b store migrates channel collections and rejects persisted secret fields", async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-notification-store-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const file = path.join(temp, "admin-store.json");
  await fs.writeFile(file, `${JSON.stringify({ version: 1 })}\n`, "utf8");
  const store = new JsonStore(file);
  const loaded = await store.load();
  assert.deepEqual(loaded.notificationChannels, {});
  assert.deepEqual(loaded.notificationChannelTests, {});
  assert.deepEqual(loaded.notificationChannelRequests, {});
  await assert.rejects(
    store.mutate((data) => {
      const channel = createNotificationChannel({
        name: "Unsafe persisted channel",
        type: "webhook",
        provider: "generic",
        secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
        config: { endpointRef: "WEBHOOK_URL" },
      });
      channel.config.token = TEST_SECRET;
      data.notificationChannels[channel.channelId] = channel;
    }),
    /secret reference/,
  );
});
