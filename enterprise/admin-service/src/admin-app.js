const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

function resultText(result) {
  if (!result || typeof result !== "object") return "No operation result was returned.";
  const credentials = result.credentials || {};
  const failed = Array.isArray(credentials.failedItems)
    ? credentials.failedItems
      .map((item) => `${item.credentialId || "credential"}/${item.deviceId || "device"}: ${item.errorCode || "unknown_error"}`)
      .join(", ")
    : "";
  const counts = `credentials: ${Number(credentials.succeeded) || 0} synced, `
    + `${Number(credentials.pending) || 0} pending, ${Number(credentials.failed) || 0} failed, `
    + `${Number(credentials.unknown) || 0} unknown`;
  switch (result.state) {
    case "succeeded":
      return result.requiresReconciliation
        ? `Policy updated, but reconciliation is still required. ${counts}${failed ? `. ${failed}` : ""}`
        : `Applied and verified. ${counts}`;
    case "pending_sync":
      return `Policy saved but gateway synchronization is pending. ${counts}${failed ? `. ${failed}` : ""}`;
    case "partial_success":
      return `Partial success; policy remains pending. ${counts}${failed ? `. ${failed}` : ""}`;
    case "unknown":
      return `The gateway was invoked but the result is unknown. Do not retry automatically. ${counts}`;
    default:
      return `Operation state: ${result.state || "unknown"}. ${counts}${failed ? `. ${failed}` : ""}`;
  }
}

function setResult(form, message, tone = "") {
  const output = form.querySelector(".write-result");
  if (!output) return;
  output.textContent = message;
  output.dataset.tone = tone;
}

function requestBody(form) {
  const part = form.dataset.part;
  const body = {
    reason: String(form.elements.reason.value || "").trim(),
    expectedVersion: Number(form.dataset.version),
  };
  const approvalId = String(form.elements.approvalId.value || "").trim();
  if (approvalId) body.approvalId = approvalId;
  if (part === "quota") {
    let limits;
    try {
      limits = JSON.parse(String(form.elements.limits.value || ""));
    } catch {
      throw new Error("Quota windows must be valid JSON.");
    }
    if (!Array.isArray(limits)) throw new Error("Quota windows must be a JSON array.");
    body.limits = limits;
  } else {
    const selectors = String(form.elements.selectors.value || "")
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (selectors.length === 0) throw new Error("Enter at least one model selector.");
    body.models = selectors;
  }
  return body;
}

document.addEventListener("submit", async (event) => {
  const form = event.target.closest?.(".policy-write-form");
  if (!form) return;
  event.preventDefault();
  if (form.dataset.inFlight === "true") return;

  let body;
  try {
    body = requestBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }

  const button = form.querySelector('button[type="submit"]');
  const idempotencyKey = crypto.randomUUID();
  form.dataset.inFlight = "true";
  if (button) button.disabled = true;
  setResult(form, `Submitting with Idempotency-Key ${idempotencyKey}.`, "pending");

  try {
    const response = await fetch(form.dataset.endpoint, {
      method: form.dataset.method,
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrfToken,
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = payload.error || {};
      const evidence = [
        `HTTP ${response.status}`,
        error.code || "request_failed",
        error.operationId ? `operation ${error.operationId}` : "",
        `Idempotency-Key ${idempotencyKey}`,
      ].filter(Boolean).join("; ");
      setResult(
        form,
        `${error.message || "The management service rejected the request"}. ${evidence}. `
          + "Reload and inspect the latest operation before trying again.",
        "error",
      );
      return;
    }
    const result = payload.result || {};
    setResult(form, `${resultText(result)} Operation ${payload.operationId || "unknown"}.`, "result");
  } catch {
    setResult(
      form,
      `The request was sent but no confirmed response was received. Do not retry automatically. `
        + `Keep Idempotency-Key ${idempotencyKey} and inspect the operation before a deliberate retry.`,
      "unknown",
    );
  }
});
