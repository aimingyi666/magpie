const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const stepUpStartUrl = document.querySelector('meta[name="step-up-start-url"]')?.content || "";

let selectedApprovalId = "";
let selectedBreakGlassId = "";
let selectedOperationId = "";
let operationCursor = "";
let auditCursor = "";

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
    + "#operation-write-form, #operation-filter, #reconcile-form, #audit-filter",
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

document.querySelector("#usage-filter")?.requestSubmit();
document.querySelector("#approval-filter")?.requestSubmit();
document.querySelector("#break-glass-filter")?.requestSubmit();
document.querySelector("#operation-filter")?.requestSubmit();
document.querySelector("#audit-filter")?.requestSubmit();
