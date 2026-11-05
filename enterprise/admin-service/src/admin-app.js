const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const stepUpStartUrl = document.querySelector('meta[name="step-up-start-url"]')?.content || "";

let selectedApprovalId = "";
let selectedBreakGlassId = "";
let selectedOperationId = "";
let operationCursor = "";
let auditCursor = "";
let selectedNotificationChannel = null;
let selectedNotificationRule = null;
let selectedNotificationDeliveryId = "";
let contentStreamCursor = "";

class ApiError extends Error {
  constructor(payload, status) {
    const error = payload?.error || {};
    super(error.message || `Request failed with HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = String(error.code || "request_failed");
    this.operationId = String(error.operationId || "");
  }
}

function node(tag, text = "", className = "") {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== "") value.textContent = String(text);
  return value;
}

function clear(value) {
  if (value) value.replaceChildren();
}

function field(form, name) {
  return form?.elements?.namedItem(name) || null;
}

function fieldValue(form, name) {
  return String(field(form, name)?.value || "").trim();
}

function setResult(container, message, tone = "") {
  const output = container?.querySelector?.(".write-result") || container;
  if (!output) return;
  output.textContent = message;
  output.dataset.tone = tone;
}

function offerStepUp(container, error) {
  if (!stepUpStartUrl || !String(error?.code || "").startsWith("step_up_")) return;
  const output = container?.querySelector?.(".write-result") || container;
  if (!output) return;
  const link = node("a", "Re-authenticate");
  link.href = stepUpStartUrl;
  output.append(" ", link, " to continue.");
}

function showError(container, error, idempotencyKey = "") {
  const evidence = [
    error instanceof ApiError ? `HTTP ${error.status}` : "",
    error?.code || "request_failed",
    error?.operationId ? `operation ${error.operationId}` : "",
    idempotencyKey ? `Idempotency-Key ${idempotencyKey}` : "",
  ].filter(Boolean).join("; ");
  setResult(
    container,
    `${error?.message || "The management service rejected the request"}. ${evidence}.`,
    "error",
  );
  offerStepUp(container, error);
}

function setBusy(form, busy) {
  form.dataset.inFlight = busy ? "true" : "false";
  for (const button of form.querySelectorAll('button[type="submit"]')) {
    button.disabled = busy;
  }
}

function idempotencyKey() {
  return crypto.randomUUID();
}

function jsonObject(text, label) {
  let value;
  try {
    value = JSON.parse(String(text || "{}"));
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value;
}

async function api(pathname, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.method && options.method !== "GET") headers["x-csrf-token"] = csrfToken;
  if (options.idempotencyKey) headers["idempotency-key"] = options.idempotencyKey;
  const response = await fetch(pathname, {
    method: options.method || "GET",
    credentials: "same-origin",
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(payload, response.status);
  return payload;
}

function queryFromForm(form) {
  const params = new URLSearchParams();
  for (const [name, raw] of new FormData(form)) {
    const value = String(raw || "").trim();
    if (value) params.set(name, value);
  }
  return params;
}

function appendText(parent, tag, text, className = "") {
  const value = node(tag, text, className);
  parent.append(value);
  return value;
}

function dataTable(headers, rows, actions = []) {
  const wrap = node("div", "", "table-wrap");
  const table = node("table");
  const head = node("thead");
  const headRow = node("tr");
  for (const header of headers) appendText(headRow, "th", header);
  head.append(headRow);
  const body = node("tbody");
  rows.forEach((row, index) => {
    const rowNode = node("tr");
    for (const value of row) appendText(rowNode, "td", value == null ? "" : value);
    if (actions[index]) {
      const cell = node("td");
      const button = appendText(
        cell,
        "button",
        actions[index].label,
        actions[index].className || "row-action",
      );
      button.type = "button";
      button.addEventListener("click", actions[index].run);
      rowNode.append(cell);
    }
    body.append(rowNode);
  });
  table.append(head, body);
  wrap.append(table);
  return wrap;
}

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

function policyRequestBody(form) {
  const part = form.dataset.part;
  const body = {
    reason: fieldValue(form, "reason"),
    expectedVersion: Number(fieldValue(form, "expectedVersion")),
  };
  const approvalId = fieldValue(form, "approvalId");
  if (approvalId) body.approvalId = approvalId;
  const breakGlassId = fieldValue(form, "breakGlassId");
  if (breakGlassId) body.breakGlassId = breakGlassId;
  if (part === "quota") {
    let limits;
    try {
      limits = JSON.parse(fieldValue(form, "limits"));
    } catch {
      throw new Error("Quota windows must be valid JSON.");
    }
    if (!Array.isArray(limits)) throw new Error("Quota windows must be a JSON array.");
    body.limits = limits;
  } else {
    const selectors = fieldValue(form, "selectors")
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (selectors.length === 0) throw new Error("Enter at least one model selector.");
    body.models = selectors;
  }
  return body;
}

async function submitPolicy(form) {
  let body;
  try {
    body = policyRequestBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `Submitting with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(form.dataset.endpoint, {
      method: form.dataset.method,
      body,
      idempotencyKey: key,
    });
    const result = payload.result || {};
    setResult(form, `${resultText(result)} Operation ${payload.operationId || "unknown"}.`, "result");
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function setSelectionText(selectors, text) {
  for (const selector of selectors) {
    const selection = document.querySelector(selector);
    if (selection) selection.textContent = text;
  }
}

function clearApprovalSelection() {
  selectedApprovalId = "";
  setSelectionText([
    "#approval-selection",
    "#approval-revoke-selection",
    "#approval-withdraw-selection",
    "#approval-transfer-selection",
  ], "No approval selected.");
  document.querySelectorAll('input[name="approvalId"]').forEach((input) => {
    input.value = "";
  });
}

function clearBreakGlassSelection() {
  selectedBreakGlassId = "";
  setSelectionText(["#break-glass-selection"], "No break-glass grant selected.");
  document.querySelectorAll('input[name="breakGlassId"]').forEach((input) => {
    input.value = "";
  });
  const detail = document.querySelector("#break-glass-detail");
  if (detail) detail.textContent = "Select a grant to inspect its safe metadata.";
}

function selectApproval(approvalId, status = "", approval = null) {
  clearBreakGlassSelection();
  selectedApprovalId = approvalId;
  const text = `${approvalId}${status ? ` (${status})` : ""}`;
  setSelectionText([
    "#approval-selection",
    "#approval-revoke-selection",
    "#approval-withdraw-selection",
    "#approval-transfer-selection",
  ], text);
  const activeStepIds = Array.isArray(approval?.activeStepIds) ? approval.activeStepIds : [];
  const suggestedStepId = activeStepIds.length === 1 ? activeStepIds[0] : "";
  for (const formSelector of ["#approval-decision-form", "#approval-transfer-form"]) {
    const form = document.querySelector(formSelector);
    const step = field(form, "stepId");
    if (step && suggestedStepId) step.value = suggestedStepId;
  }
  document.querySelectorAll('input[name="approvalId"]').forEach((input) => {
    input.value = approvalId;
  });
}

function selectBreakGlass(grant) {
  clearApprovalSelection();
  selectedBreakGlassId = String(grant?.breakGlassId || "");
  setSelectionText(
    ["#break-glass-selection"],
    `${selectedBreakGlassId} (${grant?.status || "unknown"})`,
  );
  document.querySelectorAll('input[name="breakGlassId"]').forEach((input) => {
    input.value = selectedBreakGlassId;
  });
  const detail = document.querySelector("#break-glass-detail");
  if (detail) detail.textContent = JSON.stringify(grant || {}, null, 2);
}

function renderBreakGlass(grants) {
  const target = document.querySelector("#break-glass-list");
  if (!target) return;
  clear(target);
  if (grants.length === 0) {
    target.append(node("p", "No break-glass grants matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Created", "Grant", "Status", "Action", "Requester", "Target", "Scope", "Expires", "Review due"],
    grants.map((grant) => [
      grant.createdAt,
      grant.breakGlassId,
      grant.status,
      grant.action,
      grant.requesterEmail || grant.requesterSubjectId,
      `${grant.targetType}:${grant.targetId}`,
      grant.targetOrgUnitId,
      grant.expiresAt,
      grant.reviewDueAt,
    ]),
    grants.map((grant) => ({
      label: "Select",
      run: () => selectBreakGlass(grant),
    })),
  ));
}

async function loadBreakGlass() {
  const form = document.querySelector("#break-glass-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "Loading break-glass grants.", "pending");
  try {
    const payload = await api(`/api/v1/admin/break-glass?${params}`);
    renderBreakGlass(payload.grants || []);
    setResult(form, `${(payload.grants || []).length} break-glass grant(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function requestBreakGlass(form) {
  let payload;
  try {
    payload = jsonObject(fieldValue(form, "payload"), "Business payload");
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const body = {
    ...payload,
    action: fieldValue(form, "action"),
    incidentId: fieldValue(form, "incidentId"),
    reason: fieldValue(form, "reason"),
  };
  const targetId = fieldValue(form, "targetId");
  if (targetId) body.targetId = targetId;
  setBusy(form, true);
  try {
    const response = await api("/api/v1/admin/break-glass", { method: "POST", body });
    const grant = response.grant || {};
    selectBreakGlass(grant);
    setResult(
      form,
      `Break-glass grant ${grant.breakGlassId || "unknown"} created and expires at ${grant.expiresAt || "unknown"}.`,
      "result",
    );
    await loadBreakGlass();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function reviewSelectedBreakGlass(form) {
  if (!selectedBreakGlassId) {
    setResult(form, "Select a break-glass grant first.", "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  try {
    const response = await api(
      `/api/v1/admin/break-glass/${encodeURIComponent(selectedBreakGlassId)}/review`,
      {
        method: "POST",
        body: {
          conclusion: fieldValue(form, "conclusion"),
          reason: fieldValue(form, "reason"),
        },
        idempotencyKey: key,
      },
    );
    selectBreakGlass(response.grant || { breakGlassId: selectedBreakGlassId, status: "reviewed" });
    setResult(
      form,
      `Break-glass review recorded${response.replayed ? " (idempotent replay)" : ""}.`,
      "result",
    );
    await loadBreakGlass();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function approvalStepSummary(approval) {
  return (approval.steps || []).map((step) => {
    const transfers = (step.transferHistory || []).length;
    return `${step.order}. ${step.stepId} [${step.mode}/${step.status}] `
      + `${(step.decidedBySubjectIds || []).length}/${step.quorum} of ${step.requiredApprovers}`
      + `${transfers ? `, ${transfers} transfer(s)` : ""}`;
  }).join("; ");
}

function renderApprovals(approvals) {
  const target = document.querySelector("#approval-list");
  if (!target) return;
  clear(target);
  if (approvals.length === 0) {
    target.append(node("p", "No approval requests matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Approval", "Workflow", "Steps", "Action", "Status", "Requester", "Target", "Scope", "Expires"],
    approvals.map((approval) => [
      approval.approvalId,
      approval.workflowKind,
      approvalStepSummary(approval),
      approval.action,
      approval.status,
      approval.requesterEmail || approval.requesterSubjectId,
      `${approval.targetType}:${approval.targetId}`,
      approval.targetOrgUnitId,
      approval.expiresAt,
    ]),
    approvals.map((approval) => ({
      label: "Select",
      run: () => selectApproval(approval.approvalId, approval.status, approval),
    })),
  ));
}

async function loadApprovals() {
  const form = document.querySelector("#approval-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "Loading approvals.", "pending");
  try {
    const view = params.get("view");
    params.delete("view");
    const endpoint = view ? "/api/v1/admin/approvals/inbox" : "/api/v1/admin/approvals";
    if (view) params.set("view", view);
    const payload = await api(`${endpoint}?${params}`);
    renderApprovals(payload.approvals || []);
    setResult(
      form,
      `${(payload.approvals || []).length} approval request(s) loaded`
        + `${payload.view ? ` from the ${payload.view} view` : ""}.`,
      "result",
    );
  } catch (error) {
    showError(form, error);
  }
}

async function requestApproval(form) {
  let payload;
  try {
    payload = jsonObject(fieldValue(form, "payload"), "Business payload");
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const body = {
    ...payload,
    action: fieldValue(form, "action"),
    reason: fieldValue(form, "reason"),
  };
  const targetId = fieldValue(form, "targetId");
  if (targetId) body.targetId = targetId;
  else delete body.targetId;
  setBusy(form, true);
  try {
    const response = await api("/api/v1/admin/approvals", { method: "POST", body });
    const approval = response.approval || {};
    selectApproval(approval.approvalId, approval.status, approval);
    setResult(
      form,
      `Approval ${approval.approvalId || "unknown"} created with status ${approval.status || "unknown"}.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function decideSelectedApproval(form) {
  if (!selectedApprovalId) {
    setResult(form, "Select an approval request first.", "error");
    return;
  }
  setBusy(form, true);
  try {
    const response = await api(
      `/api/v1/admin/approvals/${encodeURIComponent(selectedApprovalId)}/decisions`,
      {
        method: "POST",
        body: {
          decision: fieldValue(form, "decision"),
          reason: fieldValue(form, "reason"),
          ...(fieldValue(form, "stepId") ? { stepId: fieldValue(form, "stepId") } : {}),
        },
      },
    );
    const approval = response.approval || {};
    setResult(
      form,
      `Approval ${approval.approvalId || selectedApprovalId} is now ${approval.status || "updated"}.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function revokeSelectedApproval(form) {
  if (!selectedApprovalId) {
    setResult(form, "Select an approval request first.", "error");
    return;
  }
  setBusy(form, true);
  try {
    const response = await api(
      `/api/v1/admin/approvals/${encodeURIComponent(selectedApprovalId)}/revoke`,
      { method: "POST", body: { reason: fieldValue(form, "reason") } },
    );
    const approval = response.approval || {};
    setResult(
      form,
      `Approval ${approval.approvalId || selectedApprovalId} is now ${approval.status || "revoked"}.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function withdrawSelectedApproval(form) {
  if (!selectedApprovalId) {
    setResult(form, "Select an approval request first.", "error");
    return;
  }
  setBusy(form, true);
  try {
    const response = await api(
      `/api/v1/admin/approvals/${encodeURIComponent(selectedApprovalId)}/withdraw`,
      { method: "POST", body: { reason: fieldValue(form, "reason") } },
    );
    const approval = response.approval || {};
    setResult(
      form,
      `Approval ${approval.approvalId || selectedApprovalId} is now ${approval.status || "withdrawn"}.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function transferSelectedApproval(form) {
  if (!selectedApprovalId) {
    setResult(form, "Select an approval request first.", "error");
    return;
  }
  const stepId = fieldValue(form, "stepId");
  setBusy(form, true);
  try {
    const response = await api(
      `/api/v1/admin/approvals/${encodeURIComponent(selectedApprovalId)}`
        + `/steps/${encodeURIComponent(stepId)}/transfer`,
      {
        method: "POST",
        body: {
          toSubjectId: fieldValue(form, "toSubjectId"),
          reason: fieldValue(form, "reason"),
        },
      },
    );
    const approval = response.approval || {};
    setResult(
      form,
      `Approval ${approval.approvalId || selectedApprovalId} step ${stepId} was transferred.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

function exportBody(form) {
  const kind = fieldValue(form, "kind");
  const filters = jsonObject(fieldValue(form, "filters") || "{}", "Filters");
  return {
    exportType: kind,
    orgUnitId: fieldValue(form, "orgUnitId"),
    from: fieldValue(form, "from"),
    to: fieldValue(form, "to"),
    filters,
    reason: fieldValue(form, "reason"),
  };
}

function renderExportResult(payload) {
  const target = document.querySelector("#export-result");
  if (!target) return;
  clear(target);
  const exportRecord = payload.export || {};
  const summary = node("dl", "", "export-summary");
  for (const [label, value] of [
    ["Export ID", exportRecord.exportId],
    ["Kind", exportRecord.kind],
    ["Rows", exportRecord.rowCount],
    ["Bytes", exportRecord.byteLength],
    ["Expires", exportRecord.expiresAt],
  ]) {
    const item = node("div");
    appendText(item, "dt", label);
    appendText(item, "dd", value == null ? "" : value);
    summary.append(item);
  }
  target.append(summary);

  let downloadToken = String(payload.downloadToken || "");
  const button = node("button", "Download once");
  button.type = "button";
  button.addEventListener("click", async () => {
    const token = downloadToken;
    downloadToken = "";
    button.disabled = true;
    if (!token) {
      appendText(
        target,
        "p",
        "The one-time download token is no longer retained. Create the export again with the same Idempotency-Key if needed.",
        "notice",
      );
      return;
    }
    try {
      const response = await fetch(exportRecord.downloadPath, {
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        throw new ApiError(errorPayload, response.status);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = node("a");
      anchor.href = href;
      anchor.download = exportRecord.fileName || "magpie-export.csv";
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(href), 30000);
      appendText(target, "p", "Download started. This export cannot be downloaded again.", "notice");
    } catch (error) {
      showError(target, error);
    }
  });
  target.append(button);
}

async function requestExportApproval(form) {
  let request;
  try {
    request = exportBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const action = request.exportType === "usage"
    ? "usage.export.create"
    : "audit.export.create";
  setBusy(form, true);
  try {
    const response = await api("/api/v1/admin/approvals", {
      method: "POST",
      body: { ...request, action },
    });
    const approval = response.approval || {};
    const approvalField = field(form, "approvalId");
    if (approvalField) approvalField.value = approval.approvalId || "";
    selectApproval(approval.approvalId || "", approval.status);
    setResult(
      form,
      `Matching approval ${approval.approvalId || "unknown"} created. An independent approver must approve it before export.`,
      "result",
    );
    await loadApprovals();
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function createExport(form) {
  let request;
  try {
    request = exportBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const approvalId = fieldValue(form, "approvalId");
  const breakGlassId = fieldValue(form, "breakGlassId");
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  setBusy(form, true);
  setResult(form, `Creating export with Idempotency-Key ${key}.`, "pending");
  try {
    const response = await api(
      request.exportType === "usage"
        ? "/api/v1/admin/usage/export"
        : "/api/v1/admin/audit/export",
      {
        method: "POST",
        body: { ...request, approvalId, breakGlassId },
        idempotencyKey: key,
      },
    );
    setResult(
      form,
      `Export ready${response.replayed ? " (idempotent replay)" : ""}. The one-time token is held only in this page's memory.`,
      "result",
    );
    renderExportResult(response);
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function selectedOperation(operationId) {
  selectedOperationId = operationId;
  const target = document.querySelector("#reconcile-selection");
  if (target) target.textContent = operationId;
}

function renderOperationDetail(operation) {
  const target = document.querySelector("#operation-detail");
  if (target) target.textContent = JSON.stringify(operation, null, 2);
}

async function loadOperationDetail(operationId) {
  selectedOperation(operationId);
  try {
    const payload = await api(`/api/v1/admin/operations/${encodeURIComponent(operationId)}`);
    renderOperationDetail(payload.operation || {});
  } catch (error) {
    renderOperationDetail({ error: error.message, code: error.code || "request_failed" });
  }
}

function renderOperations(operations) {
  const target = document.querySelector("#operation-list");
  if (!target) return;
  clear(target);
  if (operations.length === 0) {
    target.append(node("p", "No operations matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Created", "Operation", "Action", "State", "Target", "Actor", "Approval", "Break-glass", "Reconciliation"],
    operations.map((operation) => [
      operation.createdAt,
      operation.operationId,
      operation.action,
      operation.state,
      `${operation.targetType}:${operation.targetId}`,
      operation.actorEmail || operation.actorSubjectId,
      operation.approvalId,
      operation.breakGlassId,
      operation.reconciliationState,
    ]),
    operations.map((operation) => ({
      label: "Inspect",
      run: () => loadOperationDetail(operation.operationId),
    })),
  ));
}

async function loadOperations(cursor = "") {
  const form = document.querySelector("#operation-filter");
  if (!form) return;
  const params = queryFromForm(form);
  if (cursor) params.set("cursor", cursor);
  setResult(form, "Loading operations.", "pending");
  try {
    const payload = await api(`/api/v1/admin/operations?${params}`);
    operationCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#operation-next");
    if (next) next.hidden = !operationCursor;
    renderOperations(payload.operations || []);
    setResult(form, `${(payload.operations || []).length} operation(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

function operationWriteEndpoint(action, targetType, targetId) {
  const id = encodeURIComponent(targetId);
  if (action === "user.disable" || action === "user.enable") {
    return `/api/v1/admin/users/${id}/${action === "user.disable" ? "disable" : "enable"}`;
  }
  if (action === "device.revoke" && targetType === "device") {
    return `/api/v1/admin/devices/${id}/revoke`;
  }
  if (action === "credential.rotate" && targetType === "credential") {
    return `/api/v1/admin/credentials/${id}/rotate`;
  }
  throw new Error("The selected row action is not supported.");
}

async function submitOperationWrite(form) {
  const { writeAction, targetType, targetId } = form.dataset;
  if (!writeAction || !targetId) {
    setResult(form, "Select an account, device, or credential action first.", "error");
    return;
  }
  let endpoint;
  try {
    endpoint = operationWriteEndpoint(writeAction, targetType, targetId);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `Submitting ${writeAction} with Idempotency-Key ${key}.`, "pending");
  try {
    const body = { reason: fieldValue(form, "reason") };
    const approvalId = fieldValue(form, "approvalId");
    if (approvalId) body.approvalId = approvalId;
    const breakGlassId = fieldValue(form, "breakGlassId");
    if (breakGlassId) body.breakGlassId = breakGlassId;
    const payload = await api(endpoint, {
      method: "POST",
      body,
      idempotencyKey: key,
    });
    setResult(
      form,
      `${resultText(payload.result || {})} Operation ${payload.operationId || "unknown"}.`,
      "result",
    );
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

async function submitReconciliation(form) {
  if (!selectedOperationId) {
    setResult(form, "Select an operation to reconcile first.", "error");
    return;
  }
  const key = idempotencyKey();
  const body = {
    action: fieldValue(form, "action"),
    evidenceRef: fieldValue(form, "evidenceRef"),
    reason: fieldValue(form, "reason"),
    approvalId: fieldValue(form, "approvalId"),
    breakGlassId: fieldValue(form, "breakGlassId"),
  };
  setBusy(form, true);
  setResult(form, `Submitting reconciliation with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(
      `/api/v1/admin/operations/${encodeURIComponent(selectedOperationId)}/reconcile`,
      { method: "POST", body, idempotencyKey: key },
    );
    setResult(
      form,
      `Reconciliation ${payload.operationId || "unknown"} finished in state ${payload.result?.state || "unknown"}.`,
      "result",
    );
    await loadOperationDetail(selectedOperationId);
    await loadOperations();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function usageCard(label, value) {
  const card = node("section", "", "box");
  appendText(card, "h2", label);
  appendText(card, "p", value, "figure");
  return card;
}

function renderUsageSummary(payload) {
  const target = document.querySelector("#usage-summary");
  if (!target) return;
  clear(target);
  const totals = payload.totals || {};
  target.append(
    usageCard("Requests", Number(totals.requests || 0)),
    usageCard("Successful", Number(totals.successfulRequests || 0)),
    usageCard("Errors", Number(totals.errors || 0)),
    usageCard("Tokens", Number(totals.totalTokens || 0)),
    usageCard("Cost (USD)", Number(totals.costUsd || 0).toFixed(4)),
  );
}

function svgNode(tag, attributes = {}) {
  const value = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, content] of Object.entries(attributes)) {
    value.setAttribute(name, String(content));
  }
  return value;
}

function renderUsageChart(payload) {
  const target = document.querySelector("#usage-chart");
  if (!target) return;
  clear(target);
  const points = Array.isArray(payload.points) ? payload.points : [];
  if (points.length === 0) {
    target.append(node("p", "No usage points are available in this window."));
    return;
  }
  const width = 1000;
  const height = 180;
  const pad = 20;
  const maximum = Math.max(1, ...points.map((point) => Number(point.totals?.requests || 0)));
  const svg = svgNode("svg", {
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": "Usage requests over time",
  });
  for (let index = 0; index <= 4; index += 1) {
    const y = pad + ((height - pad * 2) * index) / 4;
    svg.append(svgNode("line", {
      x1: pad,
      x2: width - pad,
      y1: y,
      y2: y,
      stroke: "#d7cfb9",
      "stroke-width": 1,
    }));
  }
  const step = points.length > 1 ? (width - pad * 2) / (points.length - 1) : 0;
  const coordinates = points.map((point, index) => {
    const requests = Number(point.totals?.requests || 0);
    return [
      pad + index * step,
      height - pad - ((height - pad * 2) * requests) / maximum,
    ];
  });
  svg.append(svgNode("polyline", {
    points: coordinates.map(([x, y]) => `${x},${y}`).join(" "),
    fill: "none",
    stroke: "#b93c2b",
    "stroke-width": 4,
    "stroke-linejoin": "round",
    "stroke-linecap": "round",
  }));
  for (const [x, y] of coordinates) {
    svg.append(svgNode("circle", {
      cx: x,
      cy: y,
      r: 4,
      fill: "#172018",
    }));
  }
  const title = svgNode("text", {
    x: pad,
    y: 14,
    fill: "#172018",
    "font-size": 12,
  });
  title.textContent = `${payload.bucket || "bucket"} requests, max ${maximum}`;
  svg.prepend(title);
  target.append(svg);
  appendText(
    target,
    "p",
    `${points[0]?.start || ""} to ${points[points.length - 1]?.end || ""} (UTC)`,
    "notice",
  );
}

async function loadUsage(form) {
  const params = queryFromForm(form);
  setResult(form, "Loading usage metadata.", "pending");
  try {
    const [summary, timeseries] = await Promise.all([
      api(`/api/v1/admin/usage/summary?${params}`),
      api(`/api/v1/admin/usage/timeseries?${params}&groupBy=agent`),
    ]);
    renderUsageSummary(summary);
    renderUsageChart(timeseries);
    setResult(form, "Usage summary and trend refreshed.", "result");
  } catch (error) {
    showError(form, error);
  }
}

function renderAuditLogs(records) {
  const target = document.querySelector("#audit-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No audit metadata matched these filters."));
    return;
  }
  const detail = node("pre", "Select an audit record to inspect its safe metadata.", "detail-panel");
  target.append(dataTable(
    ["Time", "Action", "Phase", "Result", "Actor", "Target", "Scope", "Operation"],
    records.map((record) => [
      record.timestamp,
      record.action,
      record.phase,
      record.result,
      record.actorEmail || record.actorSubjectId,
      `${record.targetType}:${record.targetId}`,
      record.targetOrgUnitId,
      record.operationId,
    ]),
    records.map((record) => ({
      label: "Inspect",
      run: () => {
        detail.textContent = JSON.stringify(record, null, 2);
      },
    })),
  ));
  target.append(detail);
}

async function loadAuditLogs(cursor = "") {
  const form = document.querySelector("#audit-filter");
  if (!form) return;
  const params = queryFromForm(form);
  if (cursor) params.set("cursor", cursor);
  setResult(form, "Loading audit metadata.", "pending");
  try {
    const payload = await api(`/api/v1/admin/audit-logs?${params}`);
    auditCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#audit-next");
    if (next) next.hidden = !auditCursor;
    renderAuditLogs(payload.auditLogs || []);
    setResult(form, `${(payload.auditLogs || []).length} audit record(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

function splitList(value) {
  return String(value || "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderResources(resources) {
  const target = document.querySelector("#resource-list");
  if (!target) return;
  clear(target);
  if (resources.length === 0) {
    target.append(node("p", "No published resource is assigned to your organization scope."));
    return;
  }
  target.append(dataTable(
    ["Name", "Kind", "Status", "Delivery", "Assignments", "Current release", "Updated"],
    resources.map((resource) => [
      resource.name,
      resource.kind,
      resource.status,
      resource.deliveryMode,
      (resource.assignments || []).join(", "),
      resource.currentRelease
        ? `${resource.currentRelease.resourceVersion} (${resource.currentRelease.status})`
        : resource.currentReleaseId || "",
      resource.updatedAt,
    ]),
    resources.map((resource) => ({
      label: "Inspect",
      run: () => inspectResource(resource.id),
    })),
  ));
}

async function inspectResource(resourceId) {
  const target = document.querySelector("#resource-list");
  if (!target || !resourceId) return;
  const form = document.querySelector("#resource-sync-filter");
  if (form) setResult(form, `Loading resource ${resourceId}.`, "pending");
  try {
    const payload = await api(`/api/v1/admin/resources/${encodeURIComponent(resourceId)}`);
    const detail = node("pre", JSON.stringify(payload, null, 2), "detail-panel");
    target.append(detail);
    if (form) setResult(form, "Resource metadata loaded.", "result");
  } catch (error) {
    if (form) showError(form, error);
  }
}

function renderSyncReports(reports) {
  const target = document.querySelector("#resource-sync-report-list");
  if (!target) return;
  clear(target);
  if (reports.length === 0) {
    target.append(node("p", "No client sync report was received from your organization scope."));
    return;
  }
  const detail = document.querySelector("#resource-sync-report-detail");
  target.append(dataTable(
    ["Device", "User", "Status", "Client", "Revision", "Drift", "Reported"],
    reports.map((report) => [
      report.deviceId,
      report.userId,
      report.status,
      report.clientVersion,
      report.revision,
      String(report.driftCount ?? (report.drift || []).length),
      report.reportedAt,
    ]),
    reports.map((report) => ({
      label: "Inspect",
      run: () => {
        if (detail) {
          detail.textContent = JSON.stringify(report, null, 2);
        }
        loadSyncReportDetail(report.deviceId);
      },
    })),
  ));
}

async function loadSyncReportDetail(deviceId) {
  const detail = document.querySelector("#resource-sync-report-detail");
  const form = document.querySelector("#resource-sync-filter");
  if (!deviceId) return;
  try {
    const payload = await api(
      `/api/v1/admin/resource-sync/reports/${encodeURIComponent(deviceId)}`,
    );
    if (detail) detail.textContent = JSON.stringify(payload.report || {}, null, 2);
  } catch (error) {
    if (detail) {
      detail.textContent = `This sync report is outside your scope or unavailable: ${error.code || error.message || "error"}`;
    }
    if (form) showError(form, error);
  }
}

async function loadResourceSyncVisibility(form) {
  if (!form) return;
  const params = queryFromForm(form);
  const resourceList = document.querySelector("#resource-list");
  const reportList = document.querySelector("#resource-sync-report-list");
  setResult(form, "Loading resources and client sync state.", "pending");
  const loaded = [];
  const failures = [];
  if (resourceList) {
    try {
      const payload = await api("/api/v1/admin/resources");
      const resources = (payload.resources || []).filter((resource) => {
        const resourceId = String(params.get("resourceId") || "").trim();
        if (!resourceId) return true;
        return resource.id.includes(resourceId)
          || String(resource.name || "").toLowerCase().includes(resourceId.toLowerCase());
      });
      renderResources(resources);
      loaded.push(`${resources.length} resource(s)`);
    } catch (error) {
      clear(resourceList);
      resourceList.append(node(
        "p",
        `The resource catalog is unavailable (${error.code || error.message || "error"}). `
        + "This list is not empty: it failed closed.",
        "notice",
      ));
      failures.push(error);
    }
  }
  if (reportList) {
    try {
      const payload = await api("/api/v1/admin/resource-sync/reports");
      const reports = (payload.reports || []).filter((report) => {
        const deviceId = String(params.get("deviceId") || "").trim();
        const userId = String(params.get("userId") || "").trim();
        const status = String(params.get("status") || "").trim();
        const drifted = String(params.get("drifted") || "").trim();
        if (deviceId && !String(report.deviceId || "").includes(deviceId)) return false;
        if (userId && !String(report.userId || "").includes(userId)) return false;
        if (status && report.status !== status) return false;
        if (drifted === "true" && (report.drift || []).length === 0) return false;
        return true;
      });
      renderSyncReports(reports);
      loaded.push(`${reports.length} sync report(s)`);
    } catch (error) {
      clear(reportList);
      reportList.append(node(
        "p",
        `Client sync reports are unavailable (${error.code || error.message || "error"}). `
        + "This list is not empty: it failed closed.",
        "notice",
      ));
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    showError(form, failures[0]);
    return;
  }
  setResult(form, `${loaded.join(" and ")} loaded.`, "result");
}

function notificationTestLabel(test) {
  if (!test) return "Not tested";
  return `${test.status || "unknown"} · ${test.resultCode || "no_result_code"}`;
}

function updateNotificationChannelOptions(channels) {
  const selects = [
    field(document.querySelector("#notification-rule-form"), "channelId"),
    field(document.querySelector("#notification-rule-form"), "escalationChannelId"),
  ].filter(Boolean);
  for (const select of selects) {
    const previous = select.value;
    clear(select);
    const blank = node("option", select.name === "channelId" ? "Select a channel" : "None");
    blank.value = "";
    select.append(blank);
    for (const channel of channels) {
      const option = node(
        "option",
        `${channel.name} (${channel.type}/${channel.provider})${channel.enabled ? "" : " · disabled"}`,
      );
      option.value = channel.channelId;
      select.append(option);
    }
    if (previous && !channels.some((channel) => channel.channelId === previous)) {
      const stale = node("option", `${previous} (unavailable)`);
      stale.value = previous;
      select.append(stale);
    }
    if (previous) select.value = previous;
  }
  if (selectedNotificationRule) {
    const form = document.querySelector("#notification-rule-form");
    const primary = field(form, "channelId");
    const escalation = field(form, "escalationChannelId");
    if (primary) primary.value = selectedNotificationRule.channelId || "";
    if (escalation) escalation.value = selectedNotificationRule.escalation?.channelId || "";
  }
}

function selectNotificationChannel(channel) {
  const form = document.querySelector("#notification-channel-form");
  if (!form || !channel) return;
  selectedNotificationChannel = channel;
  const values = {
    channelId: channel.channelId,
    name: channel.name,
    type: channel.type,
    provider: channel.provider,
    enabled: channel.enabled ? "true" : "false",
    eventTypes: (channel.eventTypes || []).join("\n"),
    secretRef: channel.secretRef || "",
    config: JSON.stringify(channel.config || {}, null, 2),
    reason: "",
  };
  for (const [name, value] of Object.entries(values)) {
    const input = field(form, name);
    if (input) input.value = value;
  }
  const selection = document.querySelector("#notification-channel-selection");
  if (selection) {
    selection.textContent = `${channel.channelId} · ${channel.name} · `
      + `${channel.enabled ? "enabled" : "disabled"} · secret reference configured: `
      + `${channel.secretConfigured ? "yes" : "no"}`;
  }
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}

function resetNotificationChannel() {
  selectedNotificationChannel = null;
  const form = document.querySelector("#notification-channel-form");
  if (!form) return;
  form.reset();
  const channelId = field(form, "channelId");
  if (channelId) channelId.value = "";
  const config = field(form, "config");
  if (config) config.value = "{}";
  const selection = document.querySelector("#notification-channel-selection");
  if (selection) selection.textContent = "New channel.";
}

function renderNotificationChannels(channels) {
  updateNotificationChannelOptions(channels);
  const target = document.querySelector("#notification-channel-list");
  if (!target) return;
  clear(target);
  if (channels.length === 0) {
    target.append(node("p", "No notification channels are registered."));
    return;
  }
  const canWrite = Boolean(document.querySelector("#notification-channel-form"));
  target.append(dataTable(
    ["Name", "Type", "Provider", "Enabled", "Events", "Secret reference", "Last test", "Updated"],
    channels.map((channel) => [
      channel.name,
      channel.type,
      channel.provider,
      channel.enabled ? "enabled" : "disabled",
      (channel.eventTypes || []).join(", ") || "all allowed events",
      channel.secretRef
        ? `${channel.secretRef} (${channel.secretConfigured ? "configured" : "missing"})`
        : "not used",
      notificationTestLabel(channel.lastTest),
      channel.updatedAt,
    ]),
    canWrite
      ? channels.map((channel) => ({
        label: "Edit",
        run: () => selectNotificationChannel(channel),
      }))
      : [],
  ));
  if (selectedNotificationChannel) {
    const refreshed = channels.find(
      (channel) => channel.channelId === selectedNotificationChannel.channelId,
    );
    if (refreshed) selectNotificationChannel(refreshed);
  }
}

async function loadNotificationChannels() {
  const form = document.querySelector("#notification-channel-filter");
  if (!form) return;
  setResult(form, "Loading notification channels.", "pending");
  try {
    const payload = await api("/api/v1/admin/notifications/channels");
    const channels = payload.channels || [];
    renderNotificationChannels(channels);
    setResult(form, `${channels.length} notification channel(s) loaded.`, "result");
  } catch (error) {
    const target = document.querySelector("#notification-channel-list");
    if (target) {
      clear(target);
      target.append(node(
        "p",
        error.code === "notification_channels_unavailable"
          ? "Notification channel delivery is unavailable because ADMIN_NOTIFICATION_CHANNELS_ENABLED is off or transport configuration is incomplete."
          : `Notification channels could not be loaded: ${error.message}`,
        "notice",
      ));
    }
    showError(form, error);
  }
}

function notificationChannelBody(form) {
  const type = fieldValue(form, "type");
  const provider = fieldValue(form, "provider");
  const eventTypes = splitList(fieldValue(form, "eventTypes"));
  const secretRef = fieldValue(form, "secretRef");
  const config = jsonObject(fieldValue(form, "config") || "{}", "Channel configuration");
  const body = {
    name: fieldValue(form, "name"),
    type,
    provider,
    enabled: fieldValue(form, "enabled") === "true",
    eventTypes,
    config,
  };
  if (secretRef) body.secretRef = secretRef;
  return body;
}

async function saveNotificationChannel(form) {
  let body;
  try {
    body = notificationChannelBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const channelId = fieldValue(form, "channelId");
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `Saving notification channel with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(
      channelId
        ? `/api/v1/admin/notifications/channels/${encodeURIComponent(channelId)}`
        : "/api/v1/admin/notifications/channels",
      {
        method: channelId ? "PATCH" : "POST",
        body: { ...body, reason: fieldValue(form, "reason") },
        idempotencyKey: key,
      },
    );
    selectNotificationChannel(payload.channel || {});
    setResult(
      form,
      `Notification channel ${payload.channel?.channelId || channelId || "created"} saved. `
        + "Only the secret reference is stored; the secret value is resolved by the deployment.",
      "result",
    );
    await loadNotificationChannels();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

async function testSelectedNotificationChannel() {
  const form = document.querySelector("#notification-channel-form");
  if (!form || !selectedNotificationChannel) {
    if (form) setResult(form, "Select a saved notification channel first.", "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `Testing notification channel with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(
      `/api/v1/admin/notifications/channels/${encodeURIComponent(
        selectedNotificationChannel.channelId,
      )}/test`,
      {
        method: "POST",
        body: { reason: fieldValue(form, "reason") },
        idempotencyKey: key,
      },
    );
    const test = payload.test || {};
    setResult(
      form,
      `Channel test ${test.status || "finished"} with ${test.resultCode || "no_result_code"}.`,
      test.status === "succeeded" ? "result" : "error",
    );
    await loadNotificationChannels();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

async function toggleSelectedNotificationChannel() {
  const form = document.querySelector("#notification-channel-form");
  if (!form || !selectedNotificationChannel) {
    if (form) setResult(form, "Select a saved notification channel first.", "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  try {
    const payload = await api(
      `/api/v1/admin/notifications/channels/${encodeURIComponent(
        selectedNotificationChannel.channelId,
      )}`,
      {
        method: "PATCH",
        body: {
          enabled: !selectedNotificationChannel.enabled,
          reason: fieldValue(form, "reason"),
        },
        idempotencyKey: key,
      },
    );
    selectNotificationChannel(payload.channel || {});
    setResult(
      form,
      `Notification channel ${payload.channel?.enabled ? "enabled" : "disabled"}.`,
      "result",
    );
    await loadNotificationChannels();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function notificationRuleBody(form) {
  const dimensions = splitList(fieldValue(form, "aggregationDimensions"));
  return {
    name: fieldValue(form, "name"),
    enabled: fieldValue(form, "enabled") === "true",
    priority: Number(fieldValue(form, "priority")),
    eventTypes: splitList(fieldValue(form, "eventTypes")),
    severities: splitList(fieldValue(form, "severities")),
    targetOrgUnitId: fieldValue(form, "targetOrgUnitId"),
    channelId: fieldValue(form, "channelId"),
    suppressionWindowSeconds: Number(fieldValue(form, "suppressionWindowSeconds") || 0),
    aggregation: {
      enabled: fieldValue(form, "aggregationEnabled") === "true",
      dimensions: dimensions.length > 0
        ? dimensions
        : ["eventType", "targetType", "targetId", "targetOrgUnitId"],
      windowSeconds: Number(fieldValue(form, "aggregationWindowSeconds") || 300),
    },
    escalation: {
      enabled: fieldValue(form, "escalationEnabled") === "true",
      thresholdCount: Number(fieldValue(form, "escalationThresholdCount") || 0),
      delaySeconds: Number(fieldValue(form, "escalationDelaySeconds") || 0),
      channelId: fieldValue(form, "escalationChannelId"),
    },
  };
}

function selectNotificationRule(rule) {
  const form = document.querySelector("#notification-rule-form");
  if (!form || !rule) return;
  selectedNotificationRule = rule;
  const values = {
    ruleId: rule.ruleId,
    expectedUpdatedAt: rule.updatedAt || "",
    name: rule.name,
    enabled: rule.enabled ? "true" : "false",
    priority: String(rule.priority ?? 100),
    eventTypes: (rule.eventTypes || []).join("\n"),
    severities: (rule.severities || []).join("\n"),
    targetOrgUnitId: rule.targetOrgUnitId || "",
    channelId: rule.channelId || "",
    suppressionWindowSeconds: String(rule.suppressionWindowSeconds || 0),
    aggregationEnabled: rule.aggregation?.enabled ? "true" : "false",
    aggregationDimensions: (rule.aggregation?.dimensions || []).join("\n"),
    aggregationWindowSeconds: String(rule.aggregation?.windowSeconds ?? 300),
    escalationEnabled: rule.escalation?.enabled ? "true" : "false",
    escalationThresholdCount: String(rule.escalation?.thresholdCount || 0),
    escalationDelaySeconds: String(rule.escalation?.delaySeconds || 0),
    escalationChannelId: rule.escalation?.channelId || "",
    reason: "",
  };
  for (const [name, value] of Object.entries(values)) {
    const input = field(form, name);
    if (input) input.value = value;
  }
  const selection = document.querySelector("#notification-rule-selection");
  if (selection) {
    selection.textContent = `${rule.ruleId} · ${rule.name} · priority ${rule.priority} · `
      + `${rule.enabled ? "enabled" : "disabled"}`;
  }
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}

function resetNotificationRule() {
  selectedNotificationRule = null;
  const form = document.querySelector("#notification-rule-form");
  if (!form) return;
  form.reset();
  for (const [name, value] of [
    ["ruleId", ""],
    ["expectedUpdatedAt", ""],
    ["priority", "100"],
    ["suppressionWindowSeconds", "0"],
    ["aggregationWindowSeconds", "300"],
    ["escalationThresholdCount", "0"],
    ["escalationDelaySeconds", "0"],
    ["aggregationDimensions", "eventType\ntargetType\ntargetId\ntargetOrgUnitId"],
  ]) {
    const input = field(form, name);
    if (input) input.value = value;
  }
  const selection = document.querySelector("#notification-rule-selection");
  if (selection) selection.textContent = "New rule.";
}

function renderNotificationRules(rules) {
  const target = document.querySelector("#notification-rule-list");
  if (!target) return;
  clear(target);
  if (rules.length === 0) {
    target.append(node("p", "No notification rules are registered."));
    return;
  }
  const canWrite = Boolean(document.querySelector("#notification-rule-form"));
  target.append(dataTable(
    ["Name", "Priority", "Enabled", "Events", "Severities", "Organization", "Channel", "Suppress", "Aggregation", "Escalation", "Updated"],
    rules.map((rule) => [
      rule.name,
      rule.priority,
      rule.enabled ? "enabled" : "disabled",
      (rule.eventTypes || []).join(", ") || "all allowed events",
      (rule.severities || []).join(", ") || "all severities",
      rule.targetOrgUnitId || "all organizations",
      rule.channelId,
      `${rule.suppressionWindowSeconds || 0}s`,
      rule.aggregation?.enabled
        ? `${rule.aggregation.windowSeconds}s · ${(rule.aggregation.dimensions || []).join(", ")}`
        : "disabled",
      rule.escalation?.enabled
        ? `${rule.escalation.thresholdCount || 0} events / ${rule.escalation.delaySeconds || 0}s`
        : "disabled",
      rule.updatedAt,
    ]),
    canWrite
      ? rules.map((rule) => ({
        label: "Edit",
        run: () => selectNotificationRule(rule),
      }))
      : [],
  ));
  if (selectedNotificationRule) {
    const refreshed = rules.find(
      (rule) => rule.ruleId === selectedNotificationRule.ruleId,
    );
    if (refreshed) selectNotificationRule(refreshed);
  }
}

async function loadNotificationRules() {
  const form = document.querySelector("#notification-rule-filter");
  if (!form) return;
  setResult(form, "Loading notification rules.", "pending");
  try {
    const payload = await api("/api/v1/admin/notifications/rules");
    const rules = payload.rules || [];
    renderNotificationRules(rules);
    setResult(form, `${rules.length} notification rule(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function saveNotificationRule(form) {
  let body;
  try {
    body = notificationRuleBody(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const ruleId = fieldValue(form, "ruleId");
  const expectedUpdatedAt = fieldValue(form, "expectedUpdatedAt");
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `Saving notification rule with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(
      ruleId
        ? `/api/v1/admin/notifications/rules/${encodeURIComponent(ruleId)}`
        : "/api/v1/admin/notifications/rules",
      {
        method: ruleId ? "PATCH" : "POST",
        body: {
          ...body,
          reason: fieldValue(form, "reason"),
          ...(ruleId ? { expectedUpdatedAt } : {}),
        },
        idempotencyKey: key,
      },
    );
    selectNotificationRule(payload.rule || {});
    setResult(
      form,
      `Notification rule ${payload.rule?.ruleId || ruleId || "created"} saved.`,
      "result",
    );
    await loadNotificationRules();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function renderNotificationDeliveries(records, selector, canReplay = false) {
  const target = document.querySelector(selector);
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No notification deliveries matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Created", "Status", "Severity", "Event", "Channel", "Attempts", "Last error", "Target", "Summary"],
    records.map((delivery) => [
      delivery.createdAt,
      delivery.status,
      delivery.severity,
      delivery.eventType,
      delivery.channelId || "default route",
      delivery.attemptCount,
      delivery.lastErrorCode,
      delivery.targetOrgUnitId || delivery.targetId || "",
      delivery.summary,
    ]),
    canReplay
      ? records.map((delivery) => ({
        label: "Replay",
        run: () => {
          selectedNotificationDeliveryId = delivery.deliveryId;
          const selection = document.querySelector("#notification-replay-selection");
          if (selection) {
            selection.textContent = `${delivery.deliveryId} · ${delivery.eventType} · `
              + `${delivery.severity}`;
          }
          const form = document.querySelector("#notification-replay-form");
          form?.scrollIntoView({ behavior: "smooth", block: "center" });
          field(form, "reason")?.focus();
        },
      }))
      : [],
  ));
}

async function loadNotificationDeliveries() {
  const form = document.querySelector("#notification-delivery-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "Loading notification deliveries.", "pending");
  try {
    const payload = await api(`/api/v1/admin/notifications/deliveries?${params}`);
    renderNotificationDeliveries(payload.deliveries || [], "#notification-delivery-list");
    setResult(form, `${(payload.deliveries || []).length} delivery record(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function loadNotificationDeadLetters() {
  const form = document.querySelector("#notification-dead-letter-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "Loading notification dead letters.", "pending");
  try {
    const payload = await api(`/api/v1/admin/notifications/dead-letters?${params}`);
    const deadLetters = payload.deadLetters || [];
    const summary = document.querySelector("#notification-dead-letter-summary");
    if (summary) {
      summary.textContent = `${payload.count || 0} dead letter(s); `
        + `${payload.criticalCount || 0} critical; oldest ${payload.oldestCreatedAt || "none"}; `
        + `critical visibility target ${payload.visibilityTargetSeconds || 0}s.`;
    }
    renderNotificationDeliveries(
      deadLetters,
      "#notification-dead-letter-list",
      Boolean(document.querySelector("#notification-replay-form")),
    );
    setResult(form, `${deadLetters.length} dead letter(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function replaySelectedNotificationDelivery(form) {
  if (!selectedNotificationDeliveryId) {
    setResult(form, "Select a dead-letter delivery first.", "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  try {
    const payload = await api(
      `/api/v1/admin/notifications/deliveries/${encodeURIComponent(
        selectedNotificationDeliveryId,
      )}/retry`,
      {
        method: "POST",
        body: { reason: fieldValue(form, "reason") },
        idempotencyKey: key,
      },
    );
    setResult(
      form,
      `Delivery ${payload.delivery?.deliveryId || selectedNotificationDeliveryId} `
        + `${payload.replayed ? "requeued" : "was already requeued by this key"}.`,
      "result",
    );
    selectedNotificationDeliveryId = "";
    await loadNotificationDeadLetters();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function renderNotificationTimeline(records, selector, headers, mapRow, emptyText) {
  const target = document.querySelector(selector);
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", emptyText));
    return;
  }
  target.append(dataTable(headers, records.map(mapRow)));
}

async function loadNotificationOperations() {
  const form = document.querySelector("#notification-operations-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "Loading notification aggregation and escalation state.", "pending");
  try {
    const [aggregates, suppressions, escalations] = await Promise.all([
      api(`/api/v1/admin/notifications/aggregates?${params}`),
      api(`/api/v1/admin/notifications/suppressions?${params}`),
      api(`/api/v1/admin/notifications/escalations?${params}`),
    ]);
    renderNotificationTimeline(
      aggregates.aggregates || [],
      "#notification-aggregate-list",
      ["Updated", "Event", "Severity", "Count", "Window ends", "Status", "Escalation", "Organization"],
      (aggregate) => [
        aggregate.updatedAt,
        aggregate.eventType,
        aggregate.severity,
        aggregate.count,
        aggregate.windowEndsAt,
        aggregate.status,
        `${aggregate.escalationStatus || "not_configured"}`
          + `${aggregate.escalationErrorCode ? ` · ${aggregate.escalationErrorCode}` : ""}`,
        aggregate.targetOrgUnitId || "global",
      ],
      "No notification aggregates are currently recorded.",
    );
    renderNotificationTimeline(
      suppressions.suppressions || [],
      "#notification-suppression-list",
      ["Updated", "Rule", "Count", "Window ends", "Organization"],
      (suppression) => [
        suppression.updatedAt,
        suppression.ruleId,
        suppression.count,
        suppression.windowEndsAt,
        suppression.targetOrgUnitId || "global",
      ],
      "No notification suppressions are currently active in the returned window.",
    );
    renderNotificationTimeline(
      escalations.escalations || [],
      "#notification-escalation-list",
      ["Created", "Trigger", "Status", "Count", "Rule", "Channel", "Error", "Organization"],
      (escalation) => [
        escalation.createdAt,
        escalation.trigger,
        escalation.status,
        escalation.count,
        escalation.ruleId,
        escalation.channelId,
        escalation.errorCode,
        escalation.targetOrgUnitId || "global",
      ],
      "No notification escalations are currently recorded.",
    );
    setResult(
      form,
      `${(aggregates.aggregates || []).length} aggregate(s), `
        + `${(suppressions.suppressions || []).length} suppression(s), `
        + `${(escalations.escalations || []).length} escalation(s) loaded.`,
      "result",
    );
  } catch (error) {
    showError(form, error);
  }
}

function contentScope(form) {
  return jsonObject(fieldValue(form, "scope"), "Scope");
}

function contentApprovalBody(form) {
  return {
    approvalId: fieldValue(form, "approvalId"),
    reason: fieldValue(form, "reason"),
  };
}

function appendContentSummary(target, entries) {
  clear(target);
  const summary = node("dl", "", "export-summary");
  for (const [label, value] of entries) {
    const item = node("div");
    appendText(item, "dt", label);
    appendText(item, "dd", value == null ? "" : value);
    summary.append(item);
  }
  target.append(summary);
}

async function loadContentStream(streamId) {
  const detail = document.querySelector("#content-stream-detail");
  if (!detail) return;
  detail.textContent = `Loading ${streamId}...`;
  try {
    const payload = await api(
      `/api/v1/admin/audit/content/streams/${encodeURIComponent(streamId)}`,
    );
    detail.textContent = JSON.stringify(payload.stream || {}, null, 2);
  } catch (error) {
    detail.textContent = `${error.message || "Content stream unavailable"} `
      + `[${error.code || "request_failed"}].`;
  }
}

function renderContentStreams(records) {
  const target = document.querySelector("#content-stream-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No audit content streams matched these filters."));
    return;
  }
  target.append(dataTable(
    [
      "Created",
      "Stream",
      "User",
      "Department",
      "Device",
      "Kind",
      "Status",
      "Chunks",
      "Bytes",
      "Content ref",
    ],
    records.map((stream) => [
      stream.createdAt,
      stream.streamId,
      stream.userId,
      stream.departmentId,
      stream.deviceId,
      stream.contentKind,
      stream.effectiveStatus || stream.status,
      stream.chunkCount,
      stream.bytes,
      stream.contentRef,
    ]),
    records.map((stream) => ({
      label: "Inspect",
      run: () => loadContentStream(stream.streamId),
    })),
  ));
}

async function loadContentStreams(cursor = "") {
  const form = document.querySelector("#content-stream-filter");
  if (!form) return;
  const params = queryFromForm(form);
  if (cursor) params.set("cursor", cursor);
  setResult(form, "Loading audit content metadata.", "pending");
  try {
    const payload = await api(`/api/v1/admin/audit/content/streams?${params}`);
    contentStreamCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#content-stream-next");
    if (next) next.hidden = !contentStreamCursor;
    renderContentStreams(payload.streams || []);
    setResult(form, `${(payload.streams || []).length} content stream(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

function renderContentRetention(payload) {
  const target = document.querySelector("#content-retention-result");
  if (!target) return;
  const summary = payload.summary || payload;
  appendContentSummary(target, [
    ["Dry run", summary.dryRun === true],
    ["Scanned", summary.scanned],
    ["Content deleted", summary.contentDeleted],
    ["Metadata redacted", summary.metadataRedacted],
    ["Skipped for legal hold", summary.skippedLegalHold],
    ["Exports expired", summary.exportsExpired],
    ["Errors", summary.errors],
  ]);
}

async function runContentRetention(form) {
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  setBusy(form, true);
  setResult(form, `Running content retention with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api("/api/v1/admin/audit/content/retention/run", {
      method: "POST",
      idempotencyKey: key,
      body: {
        dryRun: fieldValue(form, "dryRun") === "true",
        limit: Number(fieldValue(form, "limit")),
        ...contentApprovalBody(form),
      },
    });
    renderContentRetention(payload);
    setResult(
      form,
      `Content retention ${payload.replayed ? "replayed" : "completed"} for `
        + `${Number(payload.summary?.scanned) || 0} record(s).`,
      "result",
    );
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

async function deleteContent(form) {
  const contentRef = fieldValue(form, "contentRef");
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  setBusy(form, true);
  setResult(form, `Deleting content with Idempotency-Key ${key}.`, "pending");
  try {
    const payload = await api(
      `/api/v1/admin/audit/content/${encodeURIComponent(contentRef)}`,
      {
        method: "DELETE",
        idempotencyKey: key,
        body: {
          contentRef,
          force: fieldValue(form, "force") === "true",
          ...contentApprovalBody(form),
        },
      },
    );
    const deletion = payload.deletion || {};
    const target = document.querySelector("#content-delete-result");
    if (target) {
      appendContentSummary(target, [
        ["Duplicate", payload.replayed === true || payload.duplicate === true],
        ["Deletion ID", deletion.deletionId],
        ["Content ref", deletion.contentRef],
        ["Deleted at", deletion.deletedAt],
        ["Object bytes", deletion.objectBytes],
        ["Retention expires", deletion.retentionExpiresAt],
      ]);
    }
    setResult(
      form,
      `Content deletion ${payload.replayed === true || payload.duplicate === true
        ? "replayed"
        : "recorded"}.`,
      "result",
    );
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function selectContentDeletion(deletion) {
  const form = document.querySelector("#content-deletion-verify-form");
  const fieldNode = field(form, "deletionId");
  if (fieldNode) fieldNode.value = deletion.deletionId || "";
  form?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function renderContentDeletions(records) {
  const target = document.querySelector("#content-deletion-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No deletion proofs matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Deleted", "Deletion", "Content ref", "Actor", "Bytes", "Retention expires"],
    records.map((deletion) => [
      deletion.deletedAt,
      deletion.deletionId,
      deletion.contentRef,
      deletion.actorId,
      deletion.objectBytes,
      deletion.retentionExpiresAt,
    ]),
    records.map((deletion) => ({
      label: "Verify",
      run: () => selectContentDeletion(deletion),
    })),
  ));
}

async function loadContentDeletions() {
  const form = document.querySelector("#content-deletion-filter");
  if (!form) return;
  setResult(form, "Loading deletion proofs.", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/deletions?${params}`);
    renderContentDeletions(payload.deletions || []);
    setResult(form, `${(payload.deletions || []).length} deletion proof(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function verifyContentDeletion(form) {
  const deletionId = fieldValue(form, "deletionId");
  setBusy(form, true);
  try {
    const payload = await api(
      `/api/v1/admin/audit/content/deletions/${encodeURIComponent(deletionId)}/verify`,
      { method: "POST", body: {} },
    );
    const verification = payload.verification || {};
    setResult(
      form,
      `Deletion ${payload.deletionId || deletionId} is `
        + `${verification.valid === true ? "valid" : "not valid"}; `
        + `proof ${verification.proofDigest || "not returned"}.`,
      verification.valid === true ? "result" : "error",
    );
  } catch (error) {
    showError(form, error);
  } finally {
    setBusy(form, false);
  }
}

async function createContentLegalHold(form) {
  let scope;
  try {
    scope = contentScope(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  const body = {
    scope,
    custodianId: fieldValue(form, "custodianId"),
    expiresAt: fieldValue(form, "expiresAt"),
    ...contentApprovalBody(form),
  };
  if (fieldValue(form, "startsAt")) body.startsAt = fieldValue(form, "startsAt");
  setBusy(form, true);
  try {
    const payload = await api("/api/v1/admin/audit/content/legal-holds", {
      method: "POST",
      body,
      idempotencyKey: key,
    });
    setResult(
      form,
      `Legal hold ${payload.hold?.holdId || "unknown"} `
        + `${payload.replayed === true || payload.duplicate === true ? "replayed" : "created"}.`,
      "result",
    );
    await loadContentLegalHolds();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function selectContentLegalHold(hold) {
  const form = document.querySelector("#content-hold-release-form");
  const holdField = field(form, "holdId");
  if (holdField) holdField.value = hold.holdId || "";
  form?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function renderContentLegalHolds(records) {
  const target = document.querySelector("#content-hold-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No content legal holds matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Created", "Hold", "Status", "Scope", "Custodian", "Starts", "Expires"],
    records.map((hold) => [
      hold.createdAt,
      hold.holdId,
      hold.effectiveStatus || hold.status,
      JSON.stringify(hold.scope || {}),
      hold.custodianId,
      hold.startsAt,
      hold.expiresAt,
    ]),
    records.map((hold) => ({
      label: "Select",
      run: () => selectContentLegalHold(hold),
    })),
  ));
}

async function loadContentLegalHolds() {
  const form = document.querySelector("#content-hold-filter");
  if (!form) return;
  setResult(form, "Loading content legal holds.", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/legal-holds?${params}`);
    renderContentLegalHolds(payload.holds || []);
    setResult(form, `${(payload.holds || []).length} legal hold(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function releaseContentLegalHold(form) {
  const holdId = fieldValue(form, "holdId");
  const key = idempotencyKey();
  setBusy(form, true);
  try {
    const payload = await api(
      `/api/v1/admin/audit/content/legal-holds/${encodeURIComponent(holdId)}/release`,
      {
        method: "POST",
        idempotencyKey: key,
        body: contentApprovalBody(form),
      },
    );
    setResult(
      form,
      `Legal hold ${payload.hold?.holdId || holdId} is now `
        + `${payload.hold?.effectiveStatus || payload.hold?.status || "released"}.`,
      "result",
    );
    await loadContentLegalHolds();
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

async function readContentOnce(form) {
  const contentRef = fieldValue(form, "contentRef");
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  const target = document.querySelector("#content-read-result");
  if (target) target.textContent = "";
  const body = {
    contentRef,
    purpose: fieldValue(form, "purpose"),
    ...contentApprovalBody(form),
  };
  const ttl = fieldValue(form, "ttlSeconds");
  if (ttl) body.ttlSeconds = Number(ttl);
  setBusy(form, true);
  setResult(form, `Requesting one-time content read with Idempotency-Key ${key}.`, "pending");
  try {
    const response = await fetch(
      `/api/v1/admin/audit/content/${encodeURIComponent(contentRef)}/read`,
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrfToken,
          "idempotency-key": key,
        },
        body: JSON.stringify(body),
      },
    );
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new ApiError(payload, response.status);
    }
    const text = await response.text();
    if (target) target.textContent = text;
    setResult(form, "Content was returned once and is now displayed below.", "result");
  } catch (error) {
    if (target) target.textContent = "";
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function renderContentExportResult(payload, token) {
  const target = document.querySelector("#content-export-result");
  if (!target) return;
  clear(target);
  const exportRecord = payload.export || payload;
  appendContentSummary(target, [
    ["Export ID", exportRecord.exportId],
    ["Status", exportRecord.status],
    ["Bytes", exportRecord.byteLength],
    ["Expires", exportRecord.expiresAt],
  ]);
  let downloadToken = String(token || "");
  const button = node("button", "Download once");
  button.type = "button";
  button.disabled = !downloadToken || !exportRecord.downloadPath;
  button.addEventListener("click", async () => {
    const currentToken = downloadToken;
    downloadToken = "";
    button.disabled = true;
    if (!currentToken) {
      appendText(
        target,
        "p",
        "The one-time export token is no longer retained. Reuse a ready export from a new approved request.",
        "notice",
      );
      return;
    }
    try {
      const response = await fetch(exportRecord.downloadPath, {
        credentials: "same-origin",
        headers: { "x-magpie-download-token": currentToken },
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        throw new ApiError(errorPayload, response.status);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = node("a");
      anchor.href = href;
      anchor.download = exportRecord.fileName || `${exportRecord.exportId}.mge.enc`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(href), 30000);
      appendText(
        target,
        "p",
        "Encrypted export download started. This token cannot be used again.",
        "notice",
      );
    } catch (error) {
      showError(target, error);
    }
  });
  target.append(button);
}

async function createContentExport(form) {
  let scope;
  try {
    scope = contentScope(form);
  } catch (error) {
    setResult(form, error.message, "error");
    return;
  }
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  const body = {
    scope,
    purpose: fieldValue(form, "purpose"),
    ...contentApprovalBody(form),
  };
  const ttl = fieldValue(form, "ttlSeconds");
  if (ttl) body.ttlSeconds = Number(ttl);
  setBusy(form, true);
  setResult(form, `Creating content export with Idempotency-Key ${key}.`, "pending");
  try {
    const response = await fetch("/api/v1/admin/audit/content/exports", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrfToken,
        "idempotency-key": key,
      },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new ApiError(payload, response.status);
    const token = String(response.headers.get("x-magpie-download-token") || "");
    renderContentExportResult(payload, token);
    setResult(
      form,
      `Content export ${payload.export?.exportId || "unknown"} is ready. `
        + "The one-time token is held only in this page's memory.",
      "result",
    );
    await loadContentExports();
  } catch (error) {
    renderContentExportResult({}, "");
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function renderContentExports(records) {
  const target = document.querySelector("#content-export-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "No content exports matched these filters."));
    return;
  }
  target.append(dataTable(
    ["Created", "Export", "Status", "Bytes", "Expires", "Consumed"],
    records.map((record) => [
      record.createdAt,
      record.exportId,
      record.status,
      record.byteLength,
      record.expiresAt,
      record.consumedAt,
    ]),
  ));
}

async function loadContentExports() {
  const form = document.querySelector("#content-export-filter");
  if (!form) return;
  setResult(form, "Loading content exports.", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/exports?${params}`);
    renderContentExports(payload.exports || []);
    setResult(form, `${(payload.exports || []).length} content export(s) loaded.`, "result");
  } catch (error) {
    showError(form, error);
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest?.(".row-action[data-write-action]");
  if (!button) return;
  const form = document.querySelector("#operation-write-form");
  if (!form) return;
  form.dataset.writeAction = button.dataset.writeAction || "";
  form.dataset.targetType = button.dataset.targetType || "";
  form.dataset.targetId = button.dataset.targetId || "";
  const selection = document.querySelector("#operation-write-selection");
  if (selection) {
    selection.textContent = `${button.dataset.writeAction} on `
      + `${button.dataset.targetType}:${button.dataset.targetId}`;
  }
  form.scrollIntoView({ behavior: "smooth", block: "center" });
  field(form, "reason")?.focus();
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.inFlight === "true") {
    event.preventDefault();
    return;
  }
  const known = form.matches(
    ".policy-write-form, #usage-filter, #approval-request-form, #approval-filter, "
    + "#approval-decision-form, #approval-revoke-form, #approval-withdraw-form, "
    + "#approval-transfer-form, #break-glass-request-form, #break-glass-filter, "
    + "#break-glass-review-form, #export-form, "
    + "#operation-write-form, #operation-filter, #reconcile-form, #audit-filter, "
    + "#notification-channel-form, #notification-channel-filter, "
    + "#notification-delivery-filter, #notification-dead-letter-filter, "
    + "#notification-replay-form, #notification-rule-form, "
    + "#notification-rule-filter, #notification-operations-filter, "
    + "#resource-sync-filter, #content-stream-filter, #content-read-form, "
    + "#content-retention-form, #content-delete-form, "
    + "#content-deletion-filter, #content-deletion-verify-form, "
    + "#content-hold-create-form, #content-hold-filter, "
    + "#content-hold-release-form, #content-export-form, #content-export-filter",
  );
  if (!known) return;
  event.preventDefault();
  if (form.matches(".policy-write-form")) {
    await submitPolicy(form);
  } else if (form.id === "usage-filter") {
    await loadUsage(form);
  } else if (form.id === "approval-request-form") {
    await requestApproval(form);
  } else if (form.id === "approval-filter") {
    await loadApprovals();
  } else if (form.id === "approval-decision-form") {
    await decideSelectedApproval(form);
  } else if (form.id === "approval-revoke-form") {
    await revokeSelectedApproval(form);
  } else if (form.id === "approval-withdraw-form") {
    await withdrawSelectedApproval(form);
  } else if (form.id === "approval-transfer-form") {
    await transferSelectedApproval(form);
  } else if (form.id === "break-glass-request-form") {
    await requestBreakGlass(form);
  } else if (form.id === "break-glass-filter") {
    await loadBreakGlass();
  } else if (form.id === "break-glass-review-form") {
    await reviewSelectedBreakGlass(form);
  } else if (form.id === "export-form") {
    await createExport(form);
  } else if (form.id === "operation-write-form") {
    await submitOperationWrite(form);
  } else if (form.id === "operation-filter") {
    operationCursor = "";
    await loadOperations();
  } else if (form.id === "reconcile-form") {
    await submitReconciliation(form);
  } else if (form.id === "audit-filter") {
    auditCursor = "";
    await loadAuditLogs();
  } else if (form.id === "notification-channel-form") {
    await saveNotificationChannel(form);
  } else if (form.id === "notification-channel-filter") {
    await loadNotificationChannels();
  } else if (form.id === "notification-delivery-filter") {
    await loadNotificationDeliveries();
  } else if (form.id === "notification-dead-letter-filter") {
    await loadNotificationDeadLetters();
  } else if (form.id === "notification-replay-form") {
    await replaySelectedNotificationDelivery(form);
  } else if (form.id === "notification-rule-form") {
    await saveNotificationRule(form);
  } else if (form.id === "notification-rule-filter") {
    await loadNotificationRules();
  } else if (form.id === "notification-operations-filter") {
    await loadNotificationOperations();
  } else if (form.id === "resource-sync-filter") {
    await loadResourceSyncVisibility(form);
  } else if (form.id === "content-stream-filter") {
    contentStreamCursor = "";
    await loadContentStreams();
  } else if (form.id === "content-read-form") {
    await readContentOnce(form);
  } else if (form.id === "content-retention-form") {
    await runContentRetention(form);
  } else if (form.id === "content-delete-form") {
    await deleteContent(form);
  } else if (form.id === "content-deletion-filter") {
    await loadContentDeletions();
  } else if (form.id === "content-deletion-verify-form") {
    await verifyContentDeletion(form);
  } else if (form.id === "content-hold-create-form") {
    await createContentLegalHold(form);
  } else if (form.id === "content-hold-filter") {
    await loadContentLegalHolds();
  } else if (form.id === "content-hold-release-form") {
    await releaseContentLegalHold(form);
  } else if (form.id === "content-export-form") {
    await createContentExport(form);
  } else if (form.id === "content-export-filter") {
    await loadContentExports();
  }
});

document.querySelector("#export-request-approval")?.addEventListener("click", () => {
  const form = document.querySelector("#export-form");
  if (form && form.dataset.inFlight !== "true") requestExportApproval(form);
});

document.querySelector("#operation-next")?.addEventListener("click", () => {
  if (operationCursor) loadOperations(operationCursor);
});

document.querySelector("#audit-next")?.addEventListener("click", () => {
  if (auditCursor) loadAuditLogs(auditCursor);
});

document.querySelector("#content-stream-next")?.addEventListener("click", () => {
  if (contentStreamCursor) loadContentStreams(contentStreamCursor);
});

document.querySelector("#notification-channel-test")?.addEventListener("click", () => {
  testSelectedNotificationChannel();
});

document.querySelector("#notification-channel-toggle")?.addEventListener("click", () => {
  toggleSelectedNotificationChannel();
});

document.querySelector("#notification-channel-reset")?.addEventListener("click", () => {
  resetNotificationChannel();
});

document.querySelector("#notification-rule-reset")?.addEventListener("click", () => {
  resetNotificationRule();
});

document.querySelector("#usage-filter")?.requestSubmit();
document.querySelector("#approval-filter")?.requestSubmit();
document.querySelector("#break-glass-filter")?.requestSubmit();
document.querySelector("#operation-filter")?.requestSubmit();
document.querySelector("#audit-filter")?.requestSubmit();
document.querySelector("#notification-channel-filter")?.requestSubmit();
document.querySelector("#notification-delivery-filter")?.requestSubmit();
document.querySelector("#notification-dead-letter-filter")?.requestSubmit();
document.querySelector("#notification-rule-filter")?.requestSubmit();
document.querySelector("#notification-operations-filter")?.requestSubmit();
document.querySelector("#resource-sync-filter")?.requestSubmit();
document.querySelector("#content-stream-filter")?.requestSubmit();
document.querySelector("#content-deletion-filter")?.requestSubmit();
document.querySelector("#content-hold-filter")?.requestSubmit();
document.querySelector("#content-export-filter")?.requestSubmit();
