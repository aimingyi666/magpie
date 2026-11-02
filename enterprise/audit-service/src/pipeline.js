function safeFailure(error) {
  return {
    name: String(error?.name || "Error").slice(0, 80),
    code: String(error?.code || "audit_commit_failed").slice(0, 120),
    at: new Date().toISOString(),
  };
}

export class AuditPipeline {
  constructor(store, options = {}) {
    this.store = store;
    this.batchSize = options.batchSize || 200;
    this.intervalMs = options.intervalMs || 1000;
    this.logger = options.logger || (() => {});
    this.timer = null;
    this.draining = null;
    this.state = {
      consecutiveFailures: 0,
      lastFailure: null,
      lastSuccessAt: null,
    };
  }

  async drainOnce() {
    if (this.draining) return this.draining;
    this.draining = (async () => {
      try {
        const result = await this.store.commitQueued(this.batchSize);
        this.state.lastSuccessAt = new Date().toISOString();
        this.state.consecutiveFailures = 0;
        this.state.lastFailure = null;
        return result;
      } catch (error) {
        this.state.consecutiveFailures += 1;
        this.state.lastFailure = safeFailure(error);
        this.logger({
          code: "audit_drain_failed",
          name: error?.name || "Error",
          failures: this.state.consecutiveFailures,
        });
        throw error;
      } finally {
        this.draining = null;
      }
    })();
    return this.draining;
  }

  async drainSafely() {
    try {
      await this.drainOnce();
      return true;
    } catch {
      return false;
    }
  }

  async drainAll(maxBatches = 10_000) {
    let last = { committed: 0, queued: 0 };
    for (let index = 0; index < maxBatches; index += 1) {
      last = await this.drainOnce();
      if (last.queued === 0 || last.committed === 0) return last;
    }
    throw new Error("audit queue did not drain within the batch limit");
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.drainSafely();
    }, this.intervalMs);
    this.timer.unref?.();
    void this.drainSafely();
  }

  stop() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }

  async stopAndDrain() {
    this.stop();
    return this.drainAll();
  }

  async status() {
    return this.store.read((data) => ({
      queueDepth: Object.keys(data.queue).length,
      oldestQueuedAt: Object.values(data.queue)
        .map((record) => record.acceptedAt)
        .sort()[0] || null,
      committedCount: Object.keys(data.events).length,
      sessionCount: Object.keys(data.sessions).length,
      stats: { ...data.stats },
      ...this.state,
    }));
  }
}
