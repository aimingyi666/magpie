// Writing one captured text into audit-service.
//
// The gateway delivers a caller key and the text; this client creates a
// content stream with the identity the control plane resolved and appends
// the whole text as its final chunk. audit-service redacts on finalize, so
// the text leaves this process once, unredacted, over the internal network
// only. Nothing here logs the text or a token.

const SCHEMA_VERSION = 1;

export class ContentIngestError extends Error {
  constructor(message, { status = 502, code = "content_ingest_failed" } = {}) {
    super(message);
    this.name = "ContentIngestError";
    this.status = status;
    this.code = code;
  }
}

function text(value) {
  return typeof value === "string" ? value : "";
}

export class ContentIngestClient {
  constructor(config, fetchImpl = fetch) {
    this.url = text(config?.url).replace(/\/+$/, "");
    this.token = text(config?.ingestToken);
    this.timeoutMs = Number(config?.timeoutMs) || 5000;
    this.maxResponseBytes = Number(config?.maxResponseBytes) || 1024 * 1024;
    this.fetch = fetchImpl;
  }

  headers(idempotencyKey) {
    return {
      authorization: `Bearer ${this.token}`,
      "content-type": "application/json",
      accept: "application/json",
      "idempotency-key": idempotencyKey,
    };
  }

  async post(pathname, body, idempotencyKey) {
    let response;
    try {
      response = await this.fetch(`${this.url}${pathname}`, {
        method: "POST",
        headers: this.headers(idempotencyKey),
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      const timedOut = error?.name === "TimeoutError" || error?.name === "AbortError";
      throw new ContentIngestError(
        timedOut
          ? "audit-service did not answer in time"
          : "audit-service could not be reached",
        { status: 502, code: timedOut ? "content_ingest_timeout" : "content_ingest_unavailable" },
      );
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) {
      const code = typeof payload?.error?.code === "string"
        && /^[a-z][a-z0-9._-]{0,63}$/.test(payload.error.code)
        ? payload.error.code
        : "content_ingest_rejected";
      throw new ContentIngestError(
        `audit-service answered ${response.status}`,
        { status: 502, code },
      );
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new ContentIngestError("audit-service answered an unreadable body", {
        status: 502,
        code: "content_ingest_invalid_response",
      });
    }
    return payload;
  }

  // capture creates the stream and appends the text as chunk 0, final. The
  // idempotency keys come from the request and kind, so a retry of the same
  // capture replays instead of writing a second stream.
  async capture({
    requestId,
    sessionId,
    userId,
    departmentId,
    deviceId,
    agentId,
    modelId,
    contentKind,
    purpose,
    authorizationId,
    retentionDays,
    text: content,
  }) {
    const keyBase = `${requestId}:${contentKind}`;
    const stream = await this.post(
      "/api/v1/internal/audit/content/streams",
      {
        schemaVersion: SCHEMA_VERSION,
        requestId,
        sessionId,
        userId,
        departmentId,
        deviceId,
        agentId,
        modelId,
        contentKind,
        mediaType: "text/plain",
        auditLevel: "L2",
        collection: {
          purpose,
          authorizationId,
          confirmed: true,
          retentionDays,
        },
      },
      `${keyBase}:stream`,
    );
    // audit-service answers {stream: {...}}, not the stream at the root.
    const created = stream.stream && typeof stream.stream === "object" ? stream.stream : stream;
    const streamId = text(created.streamId);
    if (!streamId) {
      throw new ContentIngestError("audit-service did not name the stream", {
        status: 502,
        code: "content_ingest_invalid_response",
      });
    }
    const sequence = Number.isInteger(created.nextSequence) ? created.nextSequence : 0;
    const chunk = await this.post(
      `/api/v1/internal/audit/content/streams/${encodeURIComponent(streamId)}/chunks`,
      { schemaVersion: SCHEMA_VERSION, sequence, text: content, final: true },
      `${keyBase}:chunk:${sequence}`,
    );
    const finalized = chunk.stream && typeof chunk.stream === "object" ? chunk.stream : chunk;
    return {
      streamId,
      contentRef: text(finalized.contentRef),
      bytes: Number(finalized.bytes) || 0,
      redaction: finalized.redaction && typeof finalized.redaction === "object"
        ? finalized.redaction
        : null,
    };
  }
}
