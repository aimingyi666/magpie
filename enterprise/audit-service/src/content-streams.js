import {
  AuditContentValidationError,
  contentChunkFingerprint,
  publicContentStream,
  validateContentChunk,
  validateContentStreamId,
} from "./content-schema.js";
import { redactContent } from "./redaction.js";

const DEFAULT_MAX_CHUNK_BYTES = 256 * 1024;
const DEFAULT_MAX_STREAM_BYTES = 1024 * 1024;
const DEFAULT_MAX_TOTAL_BUFFER_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_ACTIVE_STREAMS = 256;
const DEFAULT_STREAM_TTL_MS = 15 * 60 * 1000;

export class ContentStreamError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ContentStreamError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function bytesOf(value) {
  return Buffer.byteLength(value, "utf8");
}

function conflict(code, message) {
  throw new ContentStreamError(409, code, message);
}

export class ContentStreamManager {
  constructor(store, options = {}) {
    this.store = store;
    this.redact = options.redact || redactContent;
    this.now = options.now || Date.now;
    this.maxChunkBytes = options.maxChunkBytes ?? DEFAULT_MAX_CHUNK_BYTES;
    this.maxStreamBytes = options.maxStreamBytes ?? DEFAULT_MAX_STREAM_BYTES;
    this.maxTotalBufferBytes = options.maxTotalBufferBytes ?? DEFAULT_MAX_TOTAL_BUFFER_BYTES;
    this.maxActiveStreams = options.maxActiveStreams ?? DEFAULT_MAX_ACTIVE_STREAMS;
    this.streamTtlMs = options.streamTtlMs ?? DEFAULT_STREAM_TTL_MS;
    this.buffers = new Map();
    this.locks = new Map();
    this.totalBufferBytes = 0;
    this.timer = null;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.pruneExpired().catch(() => {});
    }, Math.min(30_000, Math.max(1_000, Math.floor(this.streamTtlMs / 4))));
    this.timer.unref?.();
  }

  async close() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const streamIds = [...this.buffers.keys()];
    for (const streamId of streamIds) {
      try {
        await this.store.failStream(streamId, "content_stream_interrupted");
      } catch {
        // Shutdown is best effort; a later load marks any collecting stream interrupted.
      }
      this.dropBuffer(streamId);
    }
  }

  status() {
    return {
      activeStreams: this.buffers.size,
      bufferedBytes: this.totalBufferBytes,
      maxStreamBytes: this.maxStreamBytes,
      maxChunkBytes: this.maxChunkBytes,
      maxActiveStreams: this.maxActiveStreams,
      streamTtlMs: this.streamTtlMs,
    };
  }

  async create(request, idempotencyKey) {
    return this.withLock("__create__", async () => {
      await this.pruneExpired();
      const result = await this.store.createStream(request, idempotencyKey);
      if (result.duplicate) return result;
      if (this.buffers.size >= this.maxActiveStreams) {
        await this.store.failStream(result.stream.streamId, "content_stream_capacity");
        throw new ContentStreamError(
          503,
          "content_stream_capacity",
          "Too many active content streams",
          true,
        );
      }
      this.buffers.set(result.stream.streamId, {
        chunks: [],
        bytes: 0,
        nextSequence: result.stream.nextSequence || 0,
        lastActivityAt: this.now(),
      });
      return result;
    });
  }

  async get(streamId) {
    const normalized = validateContentStreamId(streamId);
    return this.store.getStream(normalized);
  }

  async append(streamId, value, idempotencyKey) {
    const normalizedStreamId = validateContentStreamId(streamId);
    const chunk = validateContentChunk(value);
    const chunkBytes = bytesOf(chunk.text);
    if (chunkBytes > this.maxChunkBytes) {
      throw new ContentStreamError(413, "content_chunk_too_large", "The content chunk exceeds the configured limit");
    }
    return this.withLock(normalizedStreamId, async () => {
      await this.pruneExpired();
      const state = this.buffers.get(normalizedStreamId);

      const fingerprint = contentChunkFingerprint(chunk);
      let result;
      try {
        result = await this.store.acceptChunk(
          normalizedStreamId,
          chunk.sequence,
          fingerprint,
          idempotencyKey,
          chunkBytes,
        );
      } catch (error) {
        if (error instanceof AuditContentValidationError) throw error;
        if (error?.code === "content_stream_too_large") {
          throw new ContentStreamError(413, error.code, error.message);
        }
        if (error?.code === "content_stream_not_found" || error?.code === "content_stream_closed") {
          throw new ContentStreamError(error.statusCode || 409, error.code, error.message);
        }
        throw error;
      }
      if (result?.conflict) {
        conflict(
          result.conflict === "idempotency" ? "content_idempotency_conflict" : "content_chunk_conflict",
          "The content chunk conflicts with an existing record",
        );
      }
      if (result?.outOfOrder) {
        conflict("content_sequence_out_of_order", "Content chunks must be submitted in sequence order");
      }
      if (result?.duplicate) {
        return {
          duplicate: true,
          stream: result.stream,
        };
      }

      const current = state;
      if (!current) {
        await this.store.failStream(normalizedStreamId, "content_stream_state_lost");
        throw new ContentStreamError(
          409,
          "content_stream_state_lost",
          "Content stream state is unavailable; start a new stream",
        );
      }
      if (chunk.sequence < current.nextSequence) {
        conflict("content_chunk_conflict", "The content chunk conflicts with an existing record");
      }
      if (chunk.sequence !== current.nextSequence) {
        conflict("content_sequence_out_of_order", "Content chunks must be submitted in sequence order");
      }
      this.buffers.set(normalizedStreamId, current);
      current.lastActivityAt = this.now();

      if (!chunk.final) {
        if (this.totalBufferBytes + chunkBytes > this.maxTotalBufferBytes) {
          await this.store.failStream(normalizedStreamId, "content_buffer_full");
          this.dropBuffer(normalizedStreamId);
          throw new ContentStreamError(503, "content_buffer_full", "The content buffer is full", true);
        }
        current.chunks.push(chunk.text);
        current.bytes += chunkBytes;
        current.nextSequence += 1;
        this.totalBufferBytes += chunkBytes;
        return {
          duplicate: false,
          stream: result.stream,
        };
      }

      const fullText = `${current.chunks.join("")}${chunk.text}`;
      if (fullText.length === 0) {
        await this.store.failStream(normalizedStreamId, "content_stream_empty");
        this.dropBuffer(normalizedStreamId);
        throw new ContentStreamError(400, "content_stream_empty", "The content stream is empty");
      }
      const fullBytes = bytesOf(fullText);
      if (fullBytes > this.maxStreamBytes) {
        await this.store.failStream(normalizedStreamId, "content_stream_too_large");
        this.dropBuffer(normalizedStreamId);
        throw new ContentStreamError(413, "content_stream_too_large", "The content stream exceeds the configured limit");
      }

      try {
        const redacted = this.redact(fullText, {
          maxOutputBytes: this.maxStreamBytes,
        });
        const finalized = await this.store.finalizeStream(
          normalizedStreamId,
          redacted.text,
          redacted.summary,
        );
        this.dropBuffer(normalizedStreamId);
        return {
          duplicate: false,
          finalized: true,
          ...finalized,
        };
      } catch (error) {
        try {
          await this.store.failStream(normalizedStreamId, "content_finalize_failed");
        } finally {
          this.dropBuffer(normalizedStreamId);
        }
        if (error?.code === "content_redaction_output_too_large") {
          throw new ContentStreamError(
            413,
            "content_stream_too_large",
            "The redacted content stream exceeds the configured limit",
          );
        }
        throw error;
      }
    });
  }

  async pruneExpired() {
    const now = this.now();
    for (const [streamId, state] of this.buffers) {
      if (now - state.lastActivityAt <= this.streamTtlMs) continue;
      try {
        await this.store.failStream(streamId, "content_stream_expired");
      } finally {
        this.dropBuffer(streamId);
      }
    }
  }

  dropBuffer(streamId) {
    const state = this.buffers.get(streamId);
    if (!state) return;
    this.totalBufferBytes = Math.max(0, this.totalBufferBytes - state.bytes);
    this.buffers.delete(streamId);
  }

  async withLock(streamId, fn) {
    const previous = this.locks.get(streamId) || Promise.resolve();
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const queued = previous.then(() => gate);
    this.locks.set(streamId, queued);
    try {
      await previous;
      return await fn();
    } finally {
      release();
      if (this.locks.get(streamId) === queued) this.locks.delete(streamId);
    }
  }
}

export function publicStream(stream) {
  return stream ? publicContentStream(stream) : null;
}
