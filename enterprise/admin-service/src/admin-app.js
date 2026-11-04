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
    super(error.message || `请求失败，状态 ${status}`);
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
  const link = node("a", "重新认证");
  link.href = stepUpStartUrl;
  output.append(" ", link, "后继续。");
}

function serviceUnavailableCopy(error) {
  const code = String(error?.code || "");
  if (code === "notification_channels_unavailable") return "通知通道服务未启用。配置投递地址后，通道状态会显示在这里。";
  if (code === "notification_rules_unavailable") return "通知规则服务未启用。规则接入后，触发条件和升级路径会显示在这里。";
  if (code === "resource_service_unavailable") return "资源服务未启用。当前只保留目录框架，不会显示资源内容。";
  return "";
}

function showError(container, error, idempotencyKey = "") {
  const unavailable = serviceUnavailableCopy(error);
  if (unavailable) {
    setResult(container, unavailable, "pending");
    return;
  }
  const evidence = [
    error instanceof ApiError ? `状态 ${error.status}` : "",
    error?.code || "request_failed",
    error?.operationId ? `操作 ${error.operationId}` : "",
    idempotencyKey ? `幂等键 ${idempotencyKey}` : "",
  ].filter(Boolean).join("; ");
  setResult(
    container,
    `${error?.message || "管理服务拒绝了这次请求"}。${evidence}。`,
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
    throw new Error(`${label}必须是有效的 JSON。`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}必须是 JSON 对象。`);
  }
  return value;
}

async function api(pathname, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.method && options.method !== "GET") headers["x-csrf-token"] = csrfToken;
  if (options.idempotencyKey) headers["idempotency-key"] = options.idempotencyKey;
  let response;
  try {
    response = await fetch(pathname, {
      method: options.method || "GET",
      credentials: "same-origin",
      headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
  } catch (error) {
    if (String(pathname).startsWith("/api/v1/admin/resource")) {
      throw new ApiError({ error: { code: "resource_service_unavailable", message: "资源服务未启用。" } }, 503);
    }
    throw new ApiError({ error: { code: "network_unavailable", message: "管理服务暂时没有响应，请重试。" } }, 503);
  }
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

function cell(primary, secondary = "") {
  const wrap = node("span");
  appendText(wrap, "span", primary || "\u2014", "cell-main");
  if (secondary) appendText(wrap, "span", secondary, "cell-sub");
  return wrap;
}

function actionText(value) {
  const labels = {
    "user.policy.quota": "\u8c03\u6574\u914d\u989d",
    "user.policy.models": "\u6388\u6743\u6a21\u578b",
    "user.disable": "\u505c\u7528\u7528\u6237",
    "user.enable": "\u542f\u7528\u7528\u6237",
    "device.revoke": "\u540a\u9500\u8bbe\u5907",
    "credential.rotate": "\u8f6e\u6362\u51ed\u8bc1",
    "usage.export.create": "\u5bfc\u51fa\u7528\u91cf",
    "audit.export.create": "\u5bfc\u51fa\u5ba1\u8ba1",
    "operation.reconcile": "\u6838\u5bf9\u64cd\u4f5c",
  };
  return labels[value] || value || "\u2014";
}

function shortWhen(value) {
  const text = String(value || "");
  return text ? text.replace("T", " ").replace(/\.\d{3}Z$/, " UTC").replace(/Z$/, " UTC") : "\u2014";
}


function phaseMark(value) { const labels = { intent: ["发起", "neutral"], result: ["结果", "neutral"] }; const [label, tone] = labels[value] || [statusText(value), "neutral"]; return { pill: true, text: label, tone }; }
function eventText(value) {
  const labels = {
    "approval.requested": "\u5ba1\u6279\u5df2\u63d0\u4ea4",
    "operation.failed": "\u64cd\u4f5c\u5931\u8d25",
    "security.break_glass_used": "\u5e94\u6025\u6743\u9650\u5df2\u4f7f\u7528",
  };
  return labels[value] || value || "\u2014";
}

function severityMark(value) {
  const labels = {
    info: ["\u4e00\u822c", "neutral"],
    warning: ["\u8b66\u544a", "warn"],
    critical: ["\u7d27\u6025", "bad"],
  };
  const [label, tone] = labels[value] || [value || "\u2014", "neutral"];
  return { pill: true, text: label, tone };
}

function dataTable(headers, rows, actions = []) {
  const wrap = node("div", "", "table-wrap");
  const table = node("table", "", "table");
  const head = node("thead");
  const headRow = node("tr");
  for (const header of headers) appendText(headRow, "th", header);
  head.append(headRow);
  const body = node("tbody");
  rows.forEach((row, index) => {
    const rowNode = node("tr");
    for (const value of row) {
      const td = node("td");
      if (value instanceof Node) td.append(value);
      else if (value && typeof value === "object" && value.pill) {
        td.append(node("span", value.text, `pill ${value.tone || "neutral"}`));
      } else appendText(td, "span", value == null ? "" : value);
      rowNode.append(td);
    }
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

function statusMark(value) {
  const labels = {
    succeeded: ["已完成", "ok"], failed: ["失败", "bad"], pending: ["待返回", "neutral"],
    pending_sync: ["等待同步", "warn"], partial_success: ["部分成功", "warn"], unknown: ["结果未知", "warn"],
    dependency_invoked: ["已调用", "warn"], submitted: ["已提交", "neutral"], approved: ["已通过", "ok"],
    rejected: ["已拒绝", "bad"], denied: ["已拒绝", "bad"], revoked: ["已撤销", "bad"],
    withdrawn: ["已撤回", "neutral"], expired: ["已过期", "bad"], reserved: ["已预留", "warn"],
    consumed: ["已使用", "ok"], reviewed: ["已复核", "ok"], active: ["生效中", "ok"],
    none: ["未核对", "neutral"], reconciled: ["已核对", "ok"], intent: ["发起", "neutral"], result: ["结果", "neutral"],
    serial: ["串行", "neutral"], parallel: ["并行", "neutral"], in_progress: ["处理中", "warn"], updated: ["已更新", "neutral"], finished: ["已完成", "ok"],
    pending_approval: ["待审批", "warn"], requested: ["已提交", "neutral"], delivered: ["已送达", "ok"], retry_wait: ["等待重试", "warn"], dead_letter: ["死信", "bad"], leased: ["已领取", "warn"], delivering: ["投递中", "warn"],
  };
  const [label, tone] = labels[value] || [value || "—", "neutral"];
  return { pill: true, text: label, tone };
}

function statusText(value) {
  return statusMark(value).text;
}

function resultText(result) {
  if (!result || typeof result !== "object") return "没有返回操作结果。";
  const credentials = result.credentials || {};
  const failed = Array.isArray(credentials.failedItems)
    ? credentials.failedItems
      .map((item) => `${item.credentialId || "未命名凭证"}/${item.deviceId || "未命名设备"}：${item.errorCode || "未知错误"}`)
      .join(", ")
    : "";
  const counts = `凭证：${Number(credentials.succeeded) || 0} 已同步，`
    + `${Number(credentials.pending) || 0} 等待中，${Number(credentials.failed) || 0} 失败，`
    + `${Number(credentials.unknown) || 0} 未知`;
  switch (result.state) {
    case "succeeded":
      return result.requiresReconciliation
        ? `策略已更新，仍需核对。${counts}${failed ? `. ${failed}` : ""}`
        : `已生效并核验。${counts}`;
    case "pending_sync":
      return `策略已保存，网关同步仍在等待。${counts}${failed ? `. ${failed}` : ""}`;
    case "partial_success":
      return `部分成功，策略仍待完成。${counts}${failed ? `. ${failed}` : ""}`;
    case "unknown":
      return `网关已调用，但结果未知，请勿自动重试。${counts}`; // Do not retry automatically
    default:
      return `操作状态：${statusText(result.state)}. ${counts}${failed ? `. ${failed}` : ""}`;
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
      throw new Error("配额窗口必须是合法 JSON。");
    }
    if (!Array.isArray(limits)) throw new Error("配额窗口必须是 JSON 数组。");
    body.limits = limits;
  } else {
    const selectors = fieldValue(form, "selectors")
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (selectors.length === 0) throw new Error("请至少填写一个模型选择器。");
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
  setResult(form, `正在提交，幂等键 ${key}.`, "pending");
  try {
    const payload = await api(form.dataset.endpoint, {
      method: form.dataset.method,
      body,
      idempotencyKey: key,
    });
    const result = payload.result || {};
    setResult(form, `${resultText(result)} 操作 ${payload.operationId || "未返回编号"}。`, "result");
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
  ], "尚未选择审批。");
  document.querySelectorAll('input[name="approvalId"]').forEach((input) => {
    input.value = "";
    });
}

function clearBreakGlassSelection() {
  selectedBreakGlassId = "";
  setSelectionText(["#break-glass-selection"], "尚未选择应急授权。");
  document.querySelectorAll('input[name="breakGlassId"]').forEach((input) => {
    input.value = "";
    });
  const detail = document.querySelector("#break-glass-detail");
  if (detail) detail.textContent = "选择一条授权查看安全元数据。";
}

function openApprovalWorkspace() {
  const host = document.querySelector("#approval-host");
  const source = document.querySelector("#approval-workspace");
  if (host && source && !host.contains(source)) host.replaceChildren(source);
  if (source) source.hidden = false;
  document.querySelector("#approval-create")?.setAttribute("hidden", "");
  setActionDrawer(true);
  const title = document.querySelector("#action-drawer h2");
  if (title) title.textContent = "处理审批";
}

function openApprovalCreate() {
  const host = document.querySelector("#approval-host");
  const source = document.querySelector("#approval-create");
  if (host && source && !host.contains(source)) host.replaceChildren(source);
  if (source) source.hidden = false;
  setActionDrawer(true);
  const title = document.querySelector("#action-drawer h2");
  if (title) title.textContent = "发起审批";
  source?.querySelector("input,select,textarea")?.focus();
}

function selectApproval(approvalId, status = "", approval = null) {
  clearBreakGlassSelection();
  selectedApprovalId = approvalId;
  openApprovalWorkspace();
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

function parkSecurityPanels() {
  const host = document.querySelector("#approval-host");
  for (const id of ["#security-create", "#security-review"]) {
    const panel = document.querySelector(id);
    if (host && panel && !host.contains(panel)) host.append(panel);
  }
}




function showResourcePanel(label) {
  const selected = label === "同步" ? "sync" : "catalog";
  const sync = document.querySelector('[data-resource-panel="sync"]');
  const filter = document.querySelector("#resource-sync-filter");
  if (sync && filter && !sync.contains(filter)) sync.prepend(filter);
  document.querySelectorAll("[data-resource-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.resourcePanel !== selected;
    });
  if (filter) filter.hidden = false;
}
function showNotificationPanel(label) {
  const map = {"投递":"delivery","通道":"channels","规则":"rules"};
  const titles = {delivery:"通知投递",channels:"通知通道",rules:"通知规则"};
  const selected = map[label] || "delivery";
  document.querySelectorAll("[data-note-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.notePanel !== selected;
    });
  const heading = document.querySelector("#notification-heading");
  if (heading) heading.textContent = titles[selected];
  const actions = {delivery:"加载投递",channels:"刷新通道",rules:"刷新规则"};
  const primary = document.querySelector("#primary-action");
  if (primary && document.querySelector(".view.active")?.dataset.screen === "notifications") primary.textContent = actions[selected];
}
function openAuditExport() {
  const host = document.querySelector("#approval-host");
  const panel = document.querySelector("#audit-export");
  if (host && panel && !host.contains(panel)) host.append(panel);
  if (panel) panel.hidden = false;
  setActionDrawer(true);
  const title = document.querySelector("#action-drawer h2");
  if (title) title.textContent = "创建导出";
  panel?.querySelector("input,select,textarea")?.focus();
}
function openSecurityPanel(kind) {
  parkSecurityPanels();
  const create = document.querySelector("#security-create");
  const review = document.querySelector("#security-review");
  if (create) create.hidden = kind !== "create";
  if (review) review.hidden = kind !== "review";
  setActionDrawer(true);
  const title = document.querySelector("#action-drawer h2");
  if (title) title.textContent = kind === "review" ? "复核应急操作" : "申请应急权限";
  document.querySelector(kind === "review" ? "#security-review" : "#security-create")
    ?.querySelector("input,select,textarea")?.focus();
}

function selectBreakGlass(grant) {
  clearApprovalSelection();
  selectedBreakGlassId = String(grant?.breakGlassId || "");
  openSecurityPanel("review");
  setSelectionText(
    ["#break-glass-selection"],
    `${selectedBreakGlassId} (${statusText(grant?.status)})`,
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
  const active=grants.filter((grant)=>grant.status==="active").length;
  updateGovernanceBrief("security",{
    value:String(active),
    note:active>0
      ? `${active} 项应急权限仍在生效，需要独立复核并跟踪到期。`
      : "当前没有生效中的应急权限。",
  });
  if (grants.length === 0) {
    target.append(node("p", "没有符合条件的应急授权。", "empty"));
    return;
  }
  target.append(dataTable(
    ["应急事项", "状态", "操作", "申请人", "目标", "复核期限"],
    grants.map((grant) => [
      cell(grant.reason || grant.incidentId, grant.breakGlassId),
      statusMark(grant.status),
      cell(actionText(grant.action), grant.incidentId),
      cell(grant.requesterEmail || grant.requesterSubjectId, grant.targetOrgUnitId),
      cell(grant.targetId, grant.targetType),
      shortWhen(grant.reviewDueAt || grant.expiresAt),
    ]),
    grants.map((grant) => ({
      label: "选择",
      run: () => selectBreakGlass(grant),
    })),
  ));
}

async function loadBreakGlass() {
  const form = document.querySelector("#break-glass-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "正在加载应急授权。", "pending");
  try {
    const payload = await api(`/api/v1/admin/break-glass?${params}`);
    renderBreakGlass(payload.grants || []);
    setResult(form, `${(payload.grants || []).length} 条应急授权已加载。`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function requestBreakGlass(form) {
  let payload;
  try {
    payload = jsonObject(fieldValue(form, "payload"), "业务参数");
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
      `应急授权 ${grant.breakGlassId || "未返回编号"} 已创建，到期时间 ${grant.expiresAt || "未返回时间"}。`,
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
    setResult(form, "请先选择应急授权。", "error");
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
      `应急复核已记录${response.replayed ? "（幂等重放）" : ""}。`,
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
    return `${statusText(step.status)} ${(step.decidedBySubjectIds || []).length}/${step.quorum}`
      + `${transfers ? `，转交 ${transfers} 次` : ""}`;
  }).join("; ");
}

function renderApprovals(approvals) {
  const target = document.querySelector("#approval-list");
  if (!target) return;
  clear(target);
  const pending=approvals.filter((approval)=>["requested","pending_approval","in_progress","reserved"].includes(approval.status)).length;
  updateGovernanceBrief("approvals",{
    value:String(pending),
    note:pending>0
      ? `${pending} 项审批仍在流转，请按职责与组织范围处理。`
      : "当前筛选范围内没有等待处理的审批。",
  });
  const count = document.querySelector("#approval-count");
  if (count) count.textContent = String(approvals.length);
  if (approvals.length === 0) {
    target.append(node("p", "没有符合条件的审批。", "empty"));
    return;
  }
  target.append(dataTable(
    ["审批", "操作", "状态", "申请人", "目标", "到期时间"],
    approvals.map((approval) => [
      cell(approval.reason || approval.approvalId, approval.approvalId),
      cell(actionText(approval.action), approvalStepSummary(approval)),
      statusMark(approval.status),
      cell(approval.requesterEmail || approval.requesterSubjectId, approval.targetOrgUnitId),
      cell(approval.targetId, approval.targetType),
      shortWhen(approval.expiresAt),
    ]),
    approvals.map((approval) => ({
      label: "选择",
      run: () => selectApproval(approval.approvalId, approval.status, approval),
    })),
  ));
}

async function loadApprovals() {
  const form = document.querySelector("#approval-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "正在加载审批。", "pending");
  try {
    const view = params.get("view");
    params.delete("view");
    const endpoint = view ? "/api/v1/admin/approvals/inbox" : "/api/v1/admin/approvals";
    if (view) params.set("view", view);
    const payload = await api(`${endpoint}?${params}`);
    renderApprovals(payload.approvals || []);
    setResult(
      form,
      `${(payload.approvals || []).length} 条审批已加载`
        + `${payload.view ? `，来自${({pending:"待审批",requested:"我发起的",completed:"已完成",closed:"已关闭"})[payload.view] || payload.view}` : ""}。`,
      "result",
    );
  } catch (error) {
    showError(form, error);
  }
}

async function requestApproval(form) {
  let payload;
  try {
    payload = jsonObject(fieldValue(form, "payload"), "业务参数");
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
      `审批 ${approval.approvalId || "未返回编号"} 已创建，状态 ${statusText(approval.status)}。`,
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
    setResult(form, "请先选择审批。", "error");
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
      `审批 ${approval.approvalId || selectedApprovalId} 当前状态：${statusText(approval.status) || "已更新"}。`,
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
    setResult(form, "请先选择审批。", "error");
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
      `审批 ${approval.approvalId || selectedApprovalId} 当前状态：${statusText(approval.status) || "已撤销"}。`,
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
    setResult(form, "请先选择审批。", "error");
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
      `审批 ${approval.approvalId || selectedApprovalId} 当前状态：${statusText(approval.status) || "已撤回"}。`,
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
    setResult(form, "请先选择审批。", "error");
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
      `审批 ${approval.approvalId || selectedApprovalId} 的步骤 ${stepId} 已转交。`,
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
  const filters = jsonObject(fieldValue(form, "filters") || "{}", "筛选条件");
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
    ["导出编号", exportRecord.exportId],
    ["数据集", exportRecord.kind],
    ["行数", exportRecord.rowCount],
    ["字节", exportRecord.byteLength],
    ["到期时间", exportRecord.expiresAt],
  ]) {
    const item = node("div");
    appendText(item, "dt", label);
    appendText(item, "dd", value == null ? "" : value);
    summary.append(item);
  }
  target.append(summary);

  let downloadToken = String(payload.downloadToken || "");
  const button = node("button", "下载一次");
  button.type = "button";
  button.addEventListener("click", async () => {
    const token = downloadToken;
    downloadToken = "";
    button.disabled = true;
    if (!token) {
      appendText(
        target,
        "p",
        "一次性下载令牌不再保留。如需重新下载，请使用相同幂等键再次创建导出。",
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
      appendText(target, "p", "下载已开始。此导出不能再次下载。", "notice");
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
      `匹配审批 ${approval.approvalId || "未返回编号"} 已创建。导出前需要另一名审批人批准。`,
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
  setResult(form, `正在创建导出，幂等键 ${key}。`, "pending");
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
      `导出已就绪${response.replayed ? "（幂等重放）" : ""}。一次性令牌只保留在本页内存中。`,
      "result",
    );
    renderExportResult(response);
  } catch (error) {
    showError(form, error, key);
  } finally {
    setBusy(form, false);
  }
}

function openOperationReview() {
  const host = document.querySelector("#approval-host");
  const panel = document.querySelector("#operation-review");
  if (host && panel && !host.contains(panel)) host.append(panel);
  if (panel) panel.hidden = false;
  setActionDrawer(true);
  const title = document.querySelector("#action-drawer h2");
  if (title) title.textContent = "核对操作";
}

function selectedOperation(operationId) {
  selectedOperationId = operationId;
  const target = document.querySelector("#reconcile-selection");
  if (target) target.textContent = operationId;
  openOperationReview();
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
  const needsReview=operations.filter((operation)=>[
    "unknown","partial_success","dependency_invoked","pending_sync",
  ].includes(operation.state)).length;
  updateGovernanceBrief("operations",{
    value:String(needsReview),
    note:needsReview>0
      ? `${needsReview} 项操作结果不完整，必须核对后才能视为成功。`
      : "当前筛选范围内没有结果不完整、需要人工核对的操作。",
  });
  if (operations.length === 0) {
    target.append(node("p", "没有符合条件的操作。", "empty"));
    return;
  }
  target.append(dataTable(
    ["操作", "状态", "目标", "操作人", "依据", "时间"],
    operations.map((operation) => [
      cell(actionText(operation.action), operation.operationId),
      statusMark(operation.state),
      cell(operation.targetId, operation.targetType),
      cell(operation.actorEmail || operation.actorSubjectId, operation.reason),
      cell(operation.approvalId || operation.breakGlassId || "直接执行", operation.approvalId ? "审批" : operation.breakGlassId ? "应急权限" : ""),
      shortWhen(operation.createdAt),
    ]),
    operations.map((operation) => ({
      label: "查看",
      run: () => loadOperationDetail(operation.operationId),
    })),
  ));
}

async function loadOperations(cursor = "") {
  const form = document.querySelector("#operation-filter");
  if (!form) return;
  const params = queryFromForm(form);
  if (cursor) params.set("cursor", cursor);
  setResult(form, "正在加载操作。", "pending");
  try {
    const payload = await api(`/api/v1/admin/operations?${params}`);
    operationCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#operation-next");
    if (next) next.hidden = !operationCursor;
    renderOperations(payload.operations || []);
    setResult(form, `${(payload.operations || []).length} 条操作已加载。`, "result");
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
  throw new Error("所选行操作不受支持。");
}

async function submitOperationWrite(form) {
  const { writeAction, targetType, targetId } = form.dataset;
  if (!writeAction || !targetId) {
    setResult(form, "请先选择账户、设备或凭证操作。", "error");
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
  setResult(form, `正在提交 ${writeAction}，幂等键 ${key}.`, "pending");
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
      `${resultText(payload.result || {})} 操作 ${payload.operationId || "未返回编号"}。`,
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
    setResult(form, "请先选择要核对的操作。", "error");
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
  setResult(form, `正在提交核对，幂等键 ${key}。`, "pending");
  try {
    const payload = await api(
      `/api/v1/admin/operations/${encodeURIComponent(selectedOperationId)}/reconcile`,
      { method: "POST", body, idempotencyKey: key },
    );
    setResult(
      form,
      `核对 ${payload.operationId || "未返回编号"} 完成，状态 ${statusText(payload.result?.state)}。`,
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

function usageMetric(label, value, note) {
  const card = node("div", "", "metric");
  appendText(card, "span", label);
  appendText(card, "strong", value, "num");
  appendText(card, "em", note);
  return card;
}

function renderUsageSummary(payload) {
  const target = document.querySelector("#usage-summary");
  if (!target) return;
  clear(target);
  target.className = "metric-strip";
  const totals = payload.totals || {};
  const requests = Number(totals.requests || 0);
  const errors = Number(totals.errors || 0);
  target.append(
    usageMetric("请求", requests.toLocaleString("zh-CN"), "当前筛选窗口"),
    usageMetric("成功", Number(totals.successfulRequests || 0).toLocaleString("zh-CN"), "网关已完成"),
    usageMetric("错误", errors.toLocaleString("zh-CN"), requests ? `错误率 ${(errors / requests * 100).toFixed(1)}%` : "错误率 0.0%"),
    usageMetric("Token", Number(totals.totalTokens || 0).toLocaleString("zh-CN"), "输入、输出与缓存合计"),
    usageMetric("费用", `$${Number(totals.costUsd || 0).toFixed(4)}`, "按记账口径"),
  );
  renderUsageRanks(payload);
}

function renderUsageRanks(payload) {
  const chart = document.querySelector("#usage-chart");
  const host = chart?.parentElement;
  if (!host) return;
  host.querySelector(".usage-ranks")?.remove();
  const dimensions = payload.dimensions || {};
  const wrap = node("div", "", "usage-ranks split section-gap");
  for (const [title, rows] of [["模型请求", dimensions.model], ["Agent 请求", dimensions.agent]]) {
    const card = node("article", "", "panel panel-pad");
    const head = node("div", "", "section-head");
    head.append(node("h2", title));
    card.append(head);
    const list = Array.isArray(rows) ? rows.filter((row) => row.key !== "(unknown)").slice(0, 5) : [];
    if (list.length === 0) {
      card.append(node("p", "当前窗口没有可归集的调用。", "empty"));
    } else {
      const peak = Math.max(1, ...list.map((row) => Number(row.requests || 0)));
      const table = node("div", "", "rank-list");
      for (const row of list) {
        const requests = Number(row.requests || 0);
        const item = node("div", "", "rank-row");
        const label = node("span", row.label || row.key || "未标记");
        const track = node("span", "", "rank-track");
        const fill = node("i", "", "rank-fill");
        fill.style.width = `${Math.max(4, Math.round(requests / peak * 100))}%`;
        track.append(fill);
        const value = node("b", requests.toLocaleString("zh-CN"), "num");
        item.append(label, track, value);
        table.append(item);
      }
      card.append(table);
    }
    wrap.append(card);
  }
  host.append(wrap);
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
    target.append(node("div", "这个时间范围内没有调用记录。", "empty"));
    return;
  }
  const width = 1000;
  const height = 220;
  const pad = { left: 42, right: 16, top: 28, bottom: 32 };
  const maximum = Math.max(1, ...points.map((point) => Number(point.totals?.requests || 0)));
  const svg = svgNode("svg", {
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": "用量请求趋势",
    });
  const steps = 3;
  const top = Math.max(steps, Math.ceil(maximum / steps) * steps);
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const yFor = (value) => pad.top + plotHeight * (1 - value / top);
  for (let index = 0; index <= steps; index += 1) {
    const value = (top / steps) * index;
    const y = yFor(value);
    svg.append(svgNode("line", {
      x1: pad.left,
      x2: width - pad.right,
      y1: y,
      y2: y,
      stroke: "#e5eaeb",
      "stroke-width": 1,
    }));
    const tick = svgNode("text", {
      x: pad.left - 8,
      y: y + 4,
      fill: "#687173",
      "font-size": 12,
      "text-anchor": "end",
    });
    tick.textContent = String(Math.round(value));
    svg.append(tick);
  }
  const step = points.length > 1 ? plotWidth / (points.length - 1) : 0;
  const coordinates = points.map((point, index) => {
    const requests = Number(point.totals?.requests || 0);
    return [pad.left + index * step, yFor(requests)];
    });
  svg.append(svgNode("polyline", {
    points: coordinates.map(([x, y]) => `${x},${y}`).join(" "),
    fill: "none",
    stroke: "#1b6c80",
    "stroke-width": 2,
    "stroke-linejoin": "round",
    "stroke-linecap": "round",
  }));
  for (const [x, y] of coordinates) {
    svg.append(svgNode("circle", {
      cx: x,
      cy: y,
      r: 4,
      fill: "#1b6c80",
    }));
  }
  const labelCount = Math.min(6, points.length);
  for (let index = 0; index < labelCount; index += 1) {
    const pointIndex = labelCount === 1 ? 0 : Math.round(index * (points.length - 1) / (labelCount - 1));
    const label = svgNode("text", {
      x: coordinates[pointIndex][0],
      y: height - 8,
      fill: "#687173",
      "font-size": 12,
      "text-anchor": pointIndex === 0 ? "start" : pointIndex === points.length - 1 ? "end" : "middle",
    });
    label.textContent = String(points[pointIndex]?.start || "").slice(5, 10);
    svg.append(label);
  }
  const title = svgNode("text", {
    x: pad.left,
    y: 16,
    fill: "#5d6668",
    "font-size": 12,
    });
  const bucketLabel = payload.bucket === "hour" ? "按小时" : payload.bucket === "day" ? "按日" : "当前粒度";
  title.textContent = `${bucketLabel}请求，最高 ${maximum}`;
  svg.prepend(title);
  target.append(svg);
  appendText(
    target,
    "p",
    `${String(points[0]?.start || "").slice(0, 10)} 至 ${String(points[points.length - 1]?.end || "").slice(0, 10)}（UTC）`,
    "notice",
  );
}

async function loadUsage(form) {
  const params = queryFromForm(form);
  setResult(form, "正在加载用量。", "pending");
  try {
    const [summary, timeseries] = await Promise.all([
      api(`/api/v1/admin/usage/summary?${params}`),
      api(`/api/v1/admin/usage/timeseries?${params}&groupBy=agent`),
    ]);
    renderUsageSummary(summary);
    renderUsageChart(timeseries);
    setResult(form, "用量与趋势已刷新。", "result");
  } catch (error) {
    showError(form, error);
  }
}

function renderAuditLogs(records) {
  const target = document.querySelector("#audit-list");
  if (!target) return;
  clear(target);
  updateGovernanceBrief("audit",{
    value:String(records.length),
    note:records.length>0
      ? `当前查询返回 ${records.length} 条审计元数据，内容字段按权限单独申请。`
      : "当前筛选范围内没有审计元数据。",
  });
  if (records.length === 0) {
    target.append(node("p", "没有符合条件的审计记录。", "empty"));
    return;
  }
  const detail = node("pre", "选择一条审计记录查看安全元数据。", "detail-panel");
  target.append(dataTable(
    ["时间", "操作", "阶段", "结果", "操作人", "目标"],
    records.map((record) => [
      shortWhen(record.timestamp),
      cell(actionText(record.action), record.operationId),
      phaseMark(record.phase),
      statusMark(record.result),
      cell(record.actorEmail || record.actorSubjectId, record.targetOrgUnitId),
      cell(record.targetId, record.targetType),
    ]),
    records.map((record) => ({
      label: "查看",
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
  setResult(form, "正在加载审计记录。", "pending");
  try {
    const payload = await api(`/api/v1/admin/audit-logs?${params}`);
    auditCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#audit-next");
    if (next) next.hidden = !auditCursor;
    renderAuditLogs(payload.auditLogs || []);
    setResult(form, `${(payload.auditLogs || []).length} 条审计记录已加载。`, "result");
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
  const strip = node("div", "", "metric-strip");
  const published = resources.filter((resource) => resource.status === "published" || resource.status === "active").length;
  const assigned = resources.filter((resource) => (resource.assignments || []).length > 0).length;
  const released = resources.filter((resource) => resource.currentRelease || resource.currentReleaseId).length;
  for (const [label, value, note] of [["已发布", String(resources.length), "当前可见范围"],["可投递", String(published || resources.length), "状态为已发布"],["已分配", String(assigned), "至少绑定一个范围"],["有版本", String(released), "存在当前版本"]]) {
    strip.append(usageMetric(label, value, note));
  }
  target.append(strip);
  if (resources.length === 0) {
    target.append(node("p", "当前组织范围没有已发布资源。", "empty section-gap"));
    return;
  }
  target.append(dataTable(
    ["名称", "类型", "状态", "投递", "分配", "当前版本", "更新时间"],
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
      label: "查看",
      run: () => inspectResource(resource.id),
    })),
  ));
}

async function inspectResource(resourceId) {
  const target = document.querySelector("#resource-list");
  if (!target || !resourceId) return;
  const form = document.querySelector("#resource-sync-filter");
  if (form) setResult(form, `正在加载资源 ${resourceId}。`, "pending");
  try {
    const payload = await api(`/api/v1/admin/resources/${encodeURIComponent(resourceId)}`);
    const detail = node("pre", JSON.stringify(payload, null, 2), "detail-panel");
    target.append(detail);
    if (form) setResult(form, "资源元数据已加载。", "result");
  } catch (error) {
    if (form) showError(form, error);
  }
}

function renderSyncReports(reports) {
  const target = document.querySelector("#resource-sync-report-list");
  if (!target) return;
  clear(target);
  if (reports.length === 0) {
    target.append(node("p", "当前组织范围没有客户端同步报告。"));
    return;
  }
  const detail = document.querySelector("#resource-sync-report-detail");
  target.append(dataTable(
    ["设备", "用户", "状态", "客户端", "修订", "漂移", "上报时间"],
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
      label: "查看",
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
      detail.textContent = `此同步报告超出范围或暂不可用： ${error.code || error.message || "error"}`;
    }
    if (form) showError(form, error);
  }
}

async function loadResourceSyncVisibility(form) {
  if (!form) return;
  const params = queryFromForm(form);
  const resourceList = document.querySelector("#resource-list");
  const reportList = document.querySelector("#resource-sync-report-list");
  setResult(form, "正在加载资源与客户端同步状态。", "pending");
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
      loaded.push(`${resources.length} 个资源`);
    } catch (error) {
      clear(resourceList);
      const unavailable = serviceUnavailableCopy(error);
      resourceList.append(node("p", unavailable || "资源目录暂不可用。", "empty"));
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    showError(form, failures[0]);
    return;
  }
  setResult(form, `${loaded.join(" 与 ")} 已加载。`, "result");
}

function notificationTestLabel(test) {
  if (!test) return "尚未测试";
  return `${statusText(test.status)} · ${test.resultCode || "无结果码"}`;
}

function updateNotificationChannelOptions(channels) {
  const selects = [
    field(document.querySelector("#notification-rule-form"), "channelId"),
    field(document.querySelector("#notification-rule-form"), "escalationChannelId"),
  ].filter(Boolean);
  for (const select of selects) {
    const previous = select.value;
    clear(select);
    const blank = node("option", select.name === "channelId" ? "请选择通道" : "无");
    blank.value = "";
    select.append(blank);
    for (const channel of channels) {
      const option = node(
        "option",
        `${channel.name} (${channel.type}/${channel.provider})${channel.enabled ? "" : " · 已停用"}`,
      );
      option.value = channel.channelId;
      select.append(option);
    }
    if (previous && !channels.some((channel) => channel.channelId === previous)) {
      const stale = node("option", `${previous}（不可用）`);
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
  form.closest("details")?.setAttribute("open", "");
  if (selection) {
    selection.textContent = `${channel.channelId} · ${channel.name} · `
      + `${channel.enabled ? "已启用" : "已停用"} · 密钥引用已配置：`
      + `${channel.secretConfigured ? "是" : "否"}`;
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
  if (selection) selection.textContent = "新建通道。";
}

function renderNotificationChannels(channels) {
  updateNotificationChannelOptions(channels);
  const target = document.querySelector("#notification-channel-list");
  if (!target) return;
  clear(target);
  if (channels.length === 0) {
    target.append(node("p", "还没有登记通知通道。", "empty"));
    return;
  }
  const canWrite = Boolean(document.querySelector("#notification-channel-form"));
  target.append(dataTable(
    ["名称", "类型", "供应商", "启用", "事件", "密钥引用", "最近测试", "更新时间"],
    channels.map((channel) => [
      channel.name,
      channel.type,
      channel.provider,
      channel.enabled ? "已启用" : "已停用",
      (channel.eventTypes || []).join(", ") || "全部允许事件",
      channel.secretRef
        ? `${channel.secretRef}（${channel.secretConfigured ? "已配置" : "缺失"}）`
        : "未使用",
      notificationTestLabel(channel.lastTest),
      channel.updatedAt,
    ]),
    canWrite
      ? channels.map((channel) => ({
        label: "编辑",
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
  setResult(form, "正在加载通知通道。", "pending");
  try {
    const payload = await api("/api/v1/admin/notifications/channels");
    const channels = payload.channels || [];
    renderNotificationChannels(channels);
    setResult(form, `${channels.length} 个通知通道已加载。`, "result");
  } catch (error) {
    const target = document.querySelector("#notification-channel-list");
    if (target) {
      clear(target);
      target.append(node(
        "p",
        error.code === "notification_channels_unavailable"
          ? "通知通道暂不可用：功能未开启或传输配置不完整。"
          : `无法加载通知通道： ${error.message}`,
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
  const config = jsonObject(fieldValue(form, "config") || "{}", "通道配置");
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
  setResult(form, `正在保存通知通道，幂等键 ${key}。`, "pending");
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
      `通知通道 ${payload.channel?.channelId || channelId || "已创建"} 已保存。`
        + "系统只保存密钥引用，密钥值由部署环境解析。",
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
    if (form) setResult(form, "请先选择已保存的通知通道。", "error");
    return;
  }
  const key = idempotencyKey();
  setBusy(form, true);
  setResult(form, `正在测试通知通道，幂等键 ${key}。`, "pending");
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
      `通道测试 ${statusText(test.status || "finished")}，结果 ${test.resultCode || "无结果码"}。`,
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
    if (form) setResult(form, "请先选择已保存的通知通道。", "error");
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
      `通知通道已${payload.channel?.enabled ? "启用" : "停用"}。`,
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
  form.closest("details")?.setAttribute("open", "");
  const selection = document.querySelector("#notification-rule-selection");
  if (selection) {
    selection.textContent = `${rule.ruleId} · ${rule.name} · 优先级 ${rule.priority} · `
      + `${rule.enabled ? "已启用" : "已停用"}`;
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
  form.closest("details")?.setAttribute("open", "");
  const selection = document.querySelector("#notification-rule-selection");
  if (selection) selection.textContent = "新建规则。";
}

function renderNotificationRules(rules) {
  const target = document.querySelector("#notification-rule-list");
  if (!target) return;
  clear(target);
  if (rules.length === 0) {
    target.append(node("p", "还没有登记通知规则。", "empty"));
    return;
  }
  const canWrite = Boolean(document.querySelector("#notification-rule-form"));
  target.append(dataTable(
    ["名称", "优先级", "启用", "事件", "严重级别", "组织", "通道", "抑制", "聚合", "升级", "更新时间"],
    rules.map((rule) => [
      rule.name,
      rule.priority,
      rule.enabled ? "已启用" : "已停用",
      (rule.eventTypes || []).join(", ") || "全部允许事件",
      (rule.severities || []).join(", ") || "全部严重级别",
      rule.targetOrgUnitId || "全部组织",
      rule.channelId,
      `${rule.suppressionWindowSeconds || 0}s`,
      rule.aggregation?.enabled
        ? `${rule.aggregation.windowSeconds}s · ${(rule.aggregation.dimensions || []).join(", ")}`
        : "已停用",
      rule.escalation?.enabled
        ? `${rule.escalation.thresholdCount || 0} events / ${rule.escalation.delaySeconds || 0}s`
        : "已停用",
      rule.updatedAt,
    ]),
    canWrite
      ? rules.map((rule) => ({
        label: "编辑",
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
  setResult(form, "正在加载通知规则。", "pending");
  try {
    const payload = await api("/api/v1/admin/notifications/rules");
    const rules = payload.rules || [];
    renderNotificationRules(rules);
    setResult(form, `${rules.length} 条通知规则已加载。`, "result");
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
  setResult(form, `正在保存通知规则，幂等键 ${key}。`, "pending");
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
      `通知规则 ${payload.rule?.ruleId || ruleId || "已创建"} 已保存。`,
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
    target.append(node("p", "没有符合条件的通知投递。", "empty"));
    return;
  }
  target.append(dataTable(
    ["通知", "状态", "级别", "目标", "投递", "时间"],
    records.map((delivery) => [
      cell(delivery.summary, eventText(delivery.eventType)),
      statusMark(delivery.status),
      severityMark(delivery.severity),
      cell(delivery.targetId || delivery.targetOrgUnitId || "企业范围", delivery.targetOrgUnitId),
      cell(delivery.channelId ? `尝试 ${delivery.attemptCount} 次` : "默认路由", delivery.lastErrorCode),
      shortWhen(delivery.createdAt),
    ]),
    canReplay
      ? records.map((delivery) => ({
        label: "重放",
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
  setResult(form, "正在加载通知投递。", "pending");
  try {
    const payload = await api(`/api/v1/admin/notifications/deliveries?${params}`);
    const deliveries=payload.deliveries || [];
    renderNotificationDeliveries(deliveries, "#notification-delivery-list");
    const attention=deliveries.filter((delivery)=>[
      "failed","retry_wait","dead_letter","leased","delivering",
    ].includes(delivery.status)).length;
    updateGovernanceBrief("notifications",{
      value:String(attention),
      note:attention>0
        ? `${attention} 条投递失败、等待重试或仍在处理中，需要检查通道与重放。`
        : "当前范围内没有积压、重试或死信。",
    });
    setResult(form, `${deliveries.length} 条投递记录已加载。`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function loadNotificationDeadLetters() {
  const form = document.querySelector("#notification-dead-letter-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "正在加载死信。", "pending");
  try {
    const payload = await api(`/api/v1/admin/notifications/dead-letters?${params}`);
    const deadLetters = payload.deadLetters || [];
    const summary = document.querySelector("#notification-dead-letter-summary");
    if (summary) {
      const oldest = payload.oldestCreatedAt || "无";
      const target = payload.visibilityTargetSeconds || 0;
      summary.textContent = `死信 ${payload.count || 0} 条，其中紧急 ${payload.criticalCount || 0} 条。最早一条 ${oldest}，紧急项需在 ${target} 秒内可见。`;
    }
    renderNotificationDeliveries(
      deadLetters,
      "#notification-dead-letter-list",
      Boolean(document.querySelector("#notification-replay-form")),
    );
    const attention=Number(payload.count || deadLetters.length || 0);
    updateGovernanceBrief("notifications",{
      value:String(attention),
      note:attention>0
        ? `${attention} 条通知进入死信，至少 ${payload.criticalCount || 0} 条为紧急事件。`
        : "当前没有死信。",
    });
    setResult(form, `${deadLetters.length} 条死信已加载。`, "result");
  } catch (error) {
    showError(form, error);
  }
}

async function replaySelectedNotificationDelivery(form) {
  if (!selectedNotificationDeliveryId) {
    setResult(form, "请先选择死信。", "error");
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
      `投递 ${payload.delivery?.deliveryId || selectedNotificationDeliveryId} `
        + `${payload.replayed ? "已重新入队" : "已由该幂等键重新入队"}。`,
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
    target.append(node("p", emptyText, "empty"));
    return;
  }
  target.append(dataTable(headers, records.map(mapRow)));
}

async function loadNotificationOperations() {
  const form = document.querySelector("#notification-operations-filter");
  if (!form) return;
  const params = queryFromForm(form);
  setResult(form, "正在加载聚合与升级状态。", "pending");
  try {
    const [aggregates, suppressions, escalations] = await Promise.all([
      api(`/api/v1/admin/notifications/aggregates?${params}`),
      api(`/api/v1/admin/notifications/suppressions?${params}`),
      api(`/api/v1/admin/notifications/escalations?${params}`),
    ]);
    renderNotificationTimeline(
      aggregates.aggregates || [],
      "#notification-aggregate-list",
      ["更新时间", "事件", "严重级别", "次数", "窗口结束", "状态", "升级", "组织"],
      (aggregate) => [
        aggregate.updatedAt,
        aggregate.eventType,
        aggregate.severity,
        aggregate.count,
        aggregate.windowEndsAt,
        aggregate.status,
        `${aggregate.escalationStatus || "not_configured"}`
          + `${aggregate.escalationErrorCode ? ` · ${aggregate.escalationErrorCode}` : ""}`,
        aggregate.targetOrgUnitId || "全局",
      ],
      "当前没有通知聚合。",
    );
    renderNotificationTimeline(
      suppressions.suppressions || [],
      "#notification-suppression-list",
      ["更新时间", "规则", "次数", "窗口结束", "组织"],
      (suppression) => [
        suppression.updatedAt,
        suppression.ruleId,
        suppression.count,
        suppression.windowEndsAt,
        suppression.targetOrgUnitId || "全局",
      ],
      "当前窗口没有生效的通知抑制。",
    );
    renderNotificationTimeline(
      escalations.escalations || [],
      "#notification-escalation-list",
      ["创建时间", "触发条件", "状态", "次数", "规则", "通道", "错误", "组织"],
      (escalation) => [
        escalation.createdAt,
        escalation.trigger,
        escalation.status,
        escalation.count,
        escalation.ruleId,
        escalation.channelId,
        escalation.errorCode,
        escalation.targetOrgUnitId || "全局",
      ],
      "当前没有通知升级。",
    );
    setResult(
      form,
      `${(aggregates.aggregates || []).length} 个聚合， `
        + `${(suppressions.suppressions || []).length} 个抑制， `
        + `${(escalations.escalations || []).length} 个升级已加载。`,
      "result",
    );
  } catch (error) {
    showError(form, error);
  }
}

function contentScope(form) {
  return jsonObject(fieldValue(form, "scope"), "范围");
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
  detail.textContent = `正在加载 ${streamId}……`;
  try {
    const payload = await api(
      `/api/v1/admin/audit/content/streams/${encodeURIComponent(streamId)}`,
    );
    detail.textContent = JSON.stringify(payload.stream || {}, null, 2);
  } catch (error) {
    detail.textContent = `${error.message || "内容流暂不可用"} `
      + `[${error.code || "request_failed"}].`;
  }
}

function renderContentStreams(records) {
  const target = document.querySelector("#content-stream-list");
  if (!target) return;
  clear(target);
  if (records.length === 0) {
    target.append(node("p", "没有符合条件的审计内容。", "empty"));
    return;
  }
  target.append(dataTable(
    [
      "创建时间",
      "内容流",
      "用户",
      "部门",
      "设备",
      "类型",
      "状态",
      "分片",
      "字节",
      "内容引用",
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
      label: "查看",
      run: () => loadContentStream(stream.streamId),
    })),
  ));
}

async function loadContentStreams(cursor = "") {
  const form = document.querySelector("#content-stream-filter");
  if (!form) return;
  const params = queryFromForm(form);
  if (cursor) params.set("cursor", cursor);
  setResult(form, "正在加载审计内容。", "pending");
  try {
    const payload = await api(`/api/v1/admin/audit/content/streams?${params}`);
    contentStreamCursor = String(payload.nextCursor || "");
    const next = document.querySelector("#content-stream-next");
    if (next) next.hidden = !contentStreamCursor;
    renderContentStreams(payload.streams || []);
    setResult(form, `${(payload.streams || []).length} 条内容流已加载。`, "result");
  } catch (error) {
    showError(form, error);
  }
}

function renderContentRetention(payload) {
  const target = document.querySelector("#content-retention-result");
  if (!target) return;
  const summary = payload.summary || payload;
  appendContentSummary(target, [
    ["试运行", summary.dryRun === true],
    ["已扫描", summary.scanned],
    ["已删除内容", summary.contentDeleted],
    ["已脱敏元数据", summary.metadataRedacted],
    ["因保全跳过", summary.skippedLegalHold],
    ["已过期导出", summary.exportsExpired],
    ["错误", summary.errors],
  ]);
}

async function runContentRetention(form) {
  const key = fieldValue(form, "idempotencyKey") || idempotencyKey();
  setBusy(form, true);
  setResult(form, `正在执行内容留存，幂等键 ${key}。`, "pending");
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
      `内容留存${payload.replayed ? "已按幂等键重放" : "已完成"}，`
        + `共处理 ${Number(payload.summary?.scanned) || 0} 条记录。`,
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
  setResult(form, `正在删除内容，幂等键 ${key}。`, "pending");
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
        ["重复提交", payload.replayed === true || payload.duplicate === true],
        ["删除编号", deletion.deletionId],
        ["内容引用", deletion.contentRef],
        ["删除时间", deletion.deletedAt],
        ["对象字节", deletion.objectBytes],
        ["留存到期", deletion.retentionExpiresAt],
      ]);
    }
    setResult(
      form,
      `内容删除${payload.replayed === true || payload.duplicate === true
        ? "已按幂等键重放"
        : "已记录"}。`,
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
    target.append(node("p", "没有符合条件的删除证明。", "empty"));
    return;
  }
  target.append(dataTable(
    ["删除时间", "删除编号", "内容引用", "操作人", "字节", "留存到期"],
    records.map((deletion) => [
      deletion.deletedAt,
      deletion.deletionId,
      deletion.contentRef,
      deletion.actorId,
      deletion.objectBytes,
      deletion.retentionExpiresAt,
    ]),
    records.map((deletion) => ({
      label: "核验",
      run: () => selectContentDeletion(deletion),
    })),
  ));
}

async function loadContentDeletions() {
  const form = document.querySelector("#content-deletion-filter");
  if (!form) return;
  setResult(form, "正在加载删除证明。", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/deletions?${params}`);
    renderContentDeletions(payload.deletions || []);
    setResult(form, `${(payload.deletions || []).length} 条删除证明已加载。`, "result");
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
      `删除证明 ${payload.deletionId || deletionId} `
        + `${verification.valid === true ? "有效" : "无效"}；`
        + `摘要 ${verification.proofDigest || "未返回"}。`,
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
      `内容保全 ${payload.hold?.holdId || "未知"} `
        + `${payload.replayed === true || payload.duplicate === true ? "已按幂等键重放" : "已创建"}。`,
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
    target.append(node("p", "没有符合条件的内容保全。", "empty"));
    return;
  }
  target.append(dataTable(
    ["创建时间", "保全编号", "状态", "范围", "保管人", "开始时间", "到期时间"],
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
      label: "选择",
      run: () => selectContentLegalHold(hold),
    })),
  ));
}

async function loadContentLegalHolds() {
  const form = document.querySelector("#content-hold-filter");
  if (!form) return;
  setResult(form, "正在加载内容保全。", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/legal-holds?${params}`);
    renderContentLegalHolds(payload.holds || []);
    setResult(form, `${(payload.holds || []).length} 条内容保全已加载。`, "result");
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
      `内容保全 ${payload.hold?.holdId || holdId} 当前状态为 `
        + `${payload.hold?.effectiveStatus || payload.hold?.status || "已解除"}。`,
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
  setResult(form, `正在申请单次内容读取，幂等键 ${key}。`, "pending");
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
    setResult(form, "内容已单次返回，并显示在下方。", "result");
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
    ["导出编号", exportRecord.exportId],
    ["状态", exportRecord.status],
    ["字节", exportRecord.byteLength],
    ["到期时间", exportRecord.expiresAt],
  ]);
  let downloadToken = String(token || "");
  const button = node("button", "下载一次");
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
        "一次性导出令牌不再保留。请使用新的已批准申请重新获取可下载导出。",
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
        "加密导出已开始下载。此令牌不能再次使用。",
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
  setResult(form, `正在创建内容导出，幂等键 ${key}。`, "pending");
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
      `内容导出 ${payload.export?.exportId || "未知"} 已就绪。`
        + "一次性令牌只保存在本页内存中。",
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
    target.append(node("p", "没有符合条件的内容导出。", "empty"));
    return;
  }
  target.append(dataTable(
    ["创建时间", "导出编号", "状态", "字节", "到期时间", "使用时间"],
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
  setResult(form, "正在加载内容导出。", "pending");
  try {
    const params = queryFromForm(form);
    const payload = await api(`/api/v1/admin/audit/content/exports?${params}`);
    renderContentExports(payload.exports || []);
    setResult(form, `${(payload.exports || []).length} 个内容导出已加载。`, "result");
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
    const view=button.closest(".view");
    const selectedCount=[...view.querySelectorAll(
      "tbody tr:not([hidden]) [data-row-select]:checked",
    )].length;
    selection.textContent=(selectedCount>1 ? `已选择 ${selectedCount} 项；本次先处理 ` : "")
      + `${button.dataset.writeAction}，目标 `
      + `${button.dataset.targetType}:${button.dataset.targetId}。`
      + (selectedCount>1 ? "提交后请按同一流程处理其余选项。" : "");
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
    ".policy-edit-form, #usage-filter, #approval-request-form, #approval-filter, "
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
  if (form.matches(".policy-edit-form")) {
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

const consoleViews={overview:"运行总览",usage:"用量分析",users:"用户与组织",devices:"设备管理",credentials:"凭证与密钥",models:"模型与策略",resources:"资源与同步",approvals:"审批中心",security:"应急权限",operations:"操作记录",audit:"审计与导出",notifications:"通知中心",content:"内容治理"};
const consoleTabs={overview:["今日运行","最近调用"],usage:["趋势","筛选"],users:["用户","组织"],models:["目录","策略"],approvals:["待审批","我的申请"],security:["授权","复核"],resources:["目录","同步"],notifications:["投递","通道","规则"]};
const overviewFinding=document.querySelector("#screen-finding")?.textContent || "";
const screenFindings={usage:"按时间、身份、Agent 和模型查看当前组织的调用。",users:"仅显示当前组织范围内的身份。",devices:"不展示设备令牌或网关密钥。",credentials:"仅展示网关密钥元数据。",models:"目录用于授权，策略变更需要完整证据链。",resources:"资源目录与客户端同步分开查看，内容本身不会显示。",approvals:"待审批、我发起的、已完成和已关闭分开处理。",security:"应急权限需要独立复核，不能由申请人自行批准。",operations:"操作记录只展示当前组织范围内的管理动作。",audit:"审计事件与导出分开查看，下载链接只使用一次。",notifications:"投递、通道和规则分开加载。",content:"内容检索、留存、删除、保全和导出分开处理。"};
const governanceBriefs={
  operations:{label:"待核对的管理动作",value:"0",note:"当前筛选范围内没有需要人工核对的操作。",next:"选择一个时间范围或动作类型重新查询；若没有结果，说明近期没有高风险写入。"},
  audit:{label:"可见审计事件",value:"0",note:"当前筛选范围内没有审计元数据。",next:"扩大时间范围或清除筛选；导出操作会单独进入审批流程。"},
  approvals:{label:"当前待审批",value:"0",note:"没有等待你处理的审批。",next:"从“我的申请”查看进行中的请求，或发起新的高风险操作审批。"},
  security:{label:"生效中的应急权限",value:"0",note:"当前没有生效中的应急权限。",next:"只有最近完成二次认证的管理员可以发起，且必须由另一名管理员复核。"},
  notifications:{label:"待关注投递",value:"0",note:"当前范围内没有积压、重试或死信。",next:"切换到“通道”检查连通性，或到“规则”确认事件路由。"},
};
function updateGovernanceBrief(name,patch){
  const brief=governanceBriefs[name];
  if(!brief)return;
  Object.assign(brief,patch);
  const strip=document.querySelector(`[data-governance-brief="${name}"]`);
  if(!strip)return;
  const value=strip.querySelector("[data-governance-value]");
  const note=strip.querySelector("[data-governance-note]");
  if(value)value.textContent=brief.value;
  if(note)note.textContent=brief.note;
}
function renderGovernanceBrief(name){
  const view=document.querySelector(`.view[data-screen="${name}"]`);
  const brief=governanceBriefs[name];
  if(!view||!brief||view.querySelector(`[data-governance-brief="${name}"]`))return;
  const strip=document.createElement("div");
  strip.className="governance-brief";
  strip.dataset.governanceBrief=name;
  strip.innerHTML=`<div class="governance-lead"><span>${brief.label}</span><strong data-governance-value>${brief.value}</strong><p data-governance-note>${brief.note}</p></div><div class="governance-next"><span>建议下一步</span><p>${brief.next}</p><button class="ghost" type="button" data-governance-action="${name}">${name==="notifications"?"检查通知通道":"调整查询条件"}</button></div>`;
  view.prepend(strip);
}
for(const name of Object.keys(governanceBriefs))renderGovernanceBrief(name);
document.addEventListener("click",event=>{const button=event.target.closest("[data-governance-action]");if(!button)return;const name=button.dataset.governanceAction;if(name==="notifications"){showConsoleView("notifications","通道");return;}const form=document.querySelector(`.view[data-screen="${name}"] form`);form?.querySelector("input,select,textarea")?.focus();});
function attentionPending(){const count=document.querySelector('.nav-button[data-view="users"] .count');return Boolean(count && !count.hidden && Number(count.textContent)>0);}
function primaryFor(name){if(name==="overview"&&attentionPending())return{label:"处理待关注用户",view:"users"};return{
  overview:{label:"查看用量",view:"usage"},
  usage:{label:"查看审计",view:"audit"},
  users:{label:"执行账户操作",drawer:true},
  devices:{label:"查看凭证",view:"credentials"},
  credentials:{label:"查看设备",view:"devices"},
  models:{label:"管理策略",tab:"策略"},
  resources:{label:"刷新同步",tab:"同步",submit:"#resource-sync-filter"},
  approvals:{label:"发起审批",drawer:"approval"},
  security:{label:"申请应急权限",drawer:"security"},
  operations:{label:"加载操作",submit:"#operation-filter"},
  audit:{label:"创建导出",drawer:"audit"},
  notifications:{label:"加载投递",submit:"#notification-delivery-filter"},
  content:{label:"搜索内容",submit:"#content-stream-filter"},
}[name]||{label:"查看用量",view:"usage"};}
function findingFor(name){if(name==="overview")return overviewFinding;if(name==="users"){const query=document.querySelector("#global-search")?.value.trim();if(query){const visible=[...document.querySelectorAll("#user-table tbody tr")].filter(row=>!row.hidden).length;return `找到 ${visible} 个匹配用户。`;}return screenFindings.users;}return screenFindings[name]||overviewFinding;}
function applyConsoleTab(name,label){if(name==="overview"&&label==="最近调用")document.querySelector("#recent-calls")?.scrollIntoView({block:"start"});if(name==="overview"&&label==="今日运行")document.querySelector('[data-screen="overview"]')?.scrollIntoView({block:"start"});if(name==="usage"&&label==="筛选"){const details=document.querySelector("#usage-filter")?.closest("details");if(details)details.open=true;document.querySelector("#usage-filter")?.scrollIntoView({block:"start"});document.querySelector("#usage-filter input,#usage-filter select")?.focus();}if(name==="usage"&&label==="趋势")document.querySelector("#usage-chart")?.scrollIntoView({block:"start"});if(name==="users"&&label==="组织")document.querySelector("#org-heading")?.scrollIntoView({block:"start"});if(name==="users"&&label==="用户")document.querySelector("#user-table")?.scrollIntoView({block:"start"});if(name==="models"&&label==="策略"){document.querySelector("#model-catalog")?.setAttribute("hidden","");document.querySelector("#policy-panel")?.removeAttribute("hidden");document.querySelector(".policy-editor")?.setAttribute("open","");}if(name==="models"&&label==="目录"){document.querySelector("#model-catalog")?.removeAttribute("hidden");document.querySelector("#policy-panel")?.setAttribute("hidden","");}if(name==="approvals"){const form=document.querySelector("#approval-filter");const select=form?.querySelector('[name="view"]');if(select){select.value=label==="我的申请"?"requested":"pending";form.requestSubmit();}}if(name==="security"&&label==="复核")openSecurityPanel("review");if(name==="security"&&label==="授权")openSecurityPanel("create");if(name==="notifications")showNotificationPanel(label);if(name==="resources")showResourcePanel(label);}
function showConsoleView(name,tabLabel){document.querySelectorAll(".view").forEach(view=>view.classList.toggle("active",view.dataset.screen===name));document.querySelectorAll(".nav-button").forEach(button=>button.setAttribute("aria-current",button.dataset.view===name?"page":"false"));const title=document.querySelector("#screen-title");if(title)title.textContent=consoleViews[name]||"系统管理控制台";const finding=document.querySelector("#screen-finding");if(finding)finding.textContent=findingFor(name);const action=primaryFor(name);const primary=document.querySelector("#primary-action");if(primary)primary.textContent=action.label;const tabs=consoleTabs[name]||[];const selected=tabs.includes(tabLabel)?tabLabel:tabs[0];const tabBar=document.querySelector("#context-tabs");if(tabBar)tabBar.innerHTML=tabs.map(item=>`<button class="tab" type="button" aria-selected="${item===selected}">${item}</button>`).join("");if(tabLabel)applyConsoleTab(name,selected);document.querySelector("#sidebar")?.classList.remove("open");}
function runPrimaryAction(){const name=document.querySelector(".view.active")?.dataset.screen||"overview";const action=primaryFor(name);if(name==="devices"||name==="credentials"){const view=document.querySelector(`.view[data-screen="${name}"]`);const selected=[...view.querySelectorAll("tbody tr:not([hidden]) [data-row-select]:checked")];if(selected.length){const target=selected[0].closest("tr").querySelector("[data-write-action]");if(target){target.click();return;}}showConsoleView(name==="devices"?"credentials":"devices");return;}if(action.drawer==="approval"){openApprovalCreate();return;}if(action.drawer==="security"){openSecurityPanel("create");return;}if(action.drawer==="audit"){openAuditExport();return;}if(action.drawer){setActionDrawer(true);return;}if(action.tab)showConsoleView(name,action.tab);if(action.submit){const selected=document.querySelector("#context-tabs .tab[aria-selected=true]")?.textContent.trim();const notificationSubmit={"投递":"#notification-delivery-filter","通道":"#notification-channel-filter","规则":"#notification-rule-filter"};const selector=name==="notifications"&&notificationSubmit[selected]?notificationSubmit[selected]:action.submit;document.querySelector(selector)?.requestSubmit();return;}if(action.focus){const node=document.querySelector(action.focus);node?.scrollIntoView({block:"start"});node?.querySelector("input,select,textarea")?.focus();return;}if(!action.tab&&action.view)showConsoleView(action.view);}
function setActionDrawer(open){
  const screen=document.querySelector(".view.active")?.dataset.screen;
  const opened=Boolean(open);
  const drawerWork=["approvals","security","audit","operations"].includes(screen);
  const approvalOpen=drawerWork&&opened;
  document.querySelector("#approval-host")?.toggleAttribute("hidden",!approvalOpen);
  document.querySelector("#operation-write-selection")?.toggleAttribute("hidden",!opened||approvalOpen);
  document.querySelector("#operation-write-form")?.toggleAttribute("hidden",!opened||approvalOpen);
  if(!approvalOpen){
    const title=document.querySelector("#action-drawer h2");
    if(title) title.textContent="执行账户操作";
  }
  const openedClass = Boolean(open);
  document.querySelector("#action-drawer")?.classList.toggle("open", openedClass);
  document.querySelector("#drawer-scrim")?.classList.toggle("open", openedClass);
  document.querySelector("#action-drawer")?.setAttribute("aria-hidden", String(!openedClass));
  if (!openedClass) {
    for (const id of ["#approval-create", "#approval-workspace", "#security-create", "#security-review", "#audit-export", "#operation-review"]) {
      const panel = document.querySelector(id);
      if (panel) panel.hidden = true;
    }
  }
}
function parkApprovalPanels(){
  const host=document.querySelector("#approval-host");
  for (const id of ["#approval-workspace","#approval-create","#security-create","#security-review","#audit-export","#operation-review"]) {
    const panel=document.querySelector(id);
    if (host && panel && !host.contains(panel)) host.append(panel);
  }
}
parkApprovalPanels();
showResourcePanel("目录");
document.addEventListener("click",(event)=>{const target=event.target.closest("[data-view],[data-goto],#primary-action,#open-nav,#refresh-page,#open-action,#close-drawer,#drawer-scrim,.row-action[data-write-action],#context-tabs .tab");if(!target)return;if(target.id==="refresh-page"){location.reload();return;}if(target.id==="open-nav"){document.querySelector("#sidebar")?.classList.add("open");return;}if(target.id==="open-action"||target.matches(".row-action[data-write-action]")){setActionDrawer(true);return;}if(target.id==="close-drawer"||target.id==="drawer-scrim"){setActionDrawer(false);return;}if(target.classList.contains("tab")){const name=document.querySelector(".view.active")?.dataset.screen;showConsoleView(name,target.textContent.trim());return;}if(target.id==="primary-action"){runPrimaryAction();return;}showConsoleView(target.dataset.view||target.dataset.goto);});
showConsoleView("overview");

document.querySelector("#global-search")?.addEventListener("input",(event)=>{const query=event.target.value.trim().toLowerCase();if(query)showConsoleView("users");document.querySelectorAll("#user-table tbody tr").forEach(row=>{row.hidden=Boolean(query)&&!row.textContent.toLowerCase().includes(query);});const visible=[...document.querySelectorAll("#user-table tbody tr")].filter(row=>!row.hidden).length;const finding=document.querySelector("#screen-finding");if(finding&&document.querySelector(".view.active")?.dataset.screen==="users")finding.textContent=query?`找到 ${visible} 个匹配用户。`:`仅显示当前组织范围内的身份。`;});

function listPanel(node){return node.closest(".view")?.querySelector("[data-list-controls]")||null;}
function visibleListRows(panel){return [...panel.closest(".view").querySelectorAll("tbody tr[data-device-row],tbody tr[data-credential-row]")].filter(row=>!row.hidden);}
function syncListSelection(panel){const rows=visibleListRows(panel);const selected=rows.filter(row=>row.querySelector("[data-row-select]")?.checked);const all=panel.querySelector("[data-select-all]");if(all){all.checked=rows.length>0&&selected.length===rows.length;all.indeterminate=selected.length>0&&selected.length<rows.length;}const button=document.querySelector("#primary-action");if(button){const screen=panel.dataset.listControls==="devices"?"devices":"credentials";button.textContent=selected.length?`处理所选 ${selected.length} 项`:(screen==="devices"?"查看凭证":"查看设备");}}
function filterList(panel){const query=panel.querySelector("[data-list-search]")?.value.trim().toLowerCase()||"";const status=panel.querySelector("[data-list-status]")?.value||"";const rows=[...panel.closest(".view").querySelectorAll("tbody tr[data-device-row],tbody tr[data-credential-row]")];let visible=0;for(const row of rows){const match=(!query||String(row.dataset.search||"").includes(query))&&(!status||row.dataset.status===status);row.hidden=!match;if(match)visible+=1;}const count=panel.querySelector("[data-list-count]");if(count)count.textContent=`${visible} ${panel.dataset.listControls==="devices"?"台设备":"个凭证"}`;syncListSelection(panel);}
function syncPrimaryAction(){if(document.querySelector("#action-drawer")?.classList.contains("open"))return;const name=document.querySelector(".view.active")?.dataset.screen||"overview";const button=document.querySelector("#primary-action");if(!button)return;if(name==="devices"||name==="credentials"){const panel=document.querySelector(`[data-screen="${name}"] [data-list-controls]`);if(panel){syncListSelection(panel);return;}}button.textContent=primaryFor(name).label;}
document.addEventListener("click",event=>{if(event.target.closest("[data-select-visible],#device-table [data-row-select],#credential-table [data-row-select]"))setTimeout(syncPrimaryAction,0);});
document.addEventListener("input",event=>{if(!event.target.matches("[data-list-search]"))return;const panel=listPanel(event.target);if(panel)filterList(panel);});
document.addEventListener("change",event=>{const panel=listPanel(event.target);if(!panel)return;if(event.target.matches("[data-list-status]")){filterList(panel);return;}if(event.target.matches("[data-select-all]")){for(const row of visibleListRows(panel)){const box=row.querySelector("[data-row-select]");if(box)box.checked=event.target.checked;}syncListSelection(panel);return;}if(event.target.matches("[data-row-select]"))syncListSelection(panel);});
document.addEventListener("click",event=>{const select=event.target.closest("[data-select-visible]");if(!select)return;const panel=listPanel(select);const rows=visibleListRows(panel);const shouldSelect=rows.some(row=>!row.querySelector("[data-row-select]")?.checked);for(const row of rows){const box=row.querySelector("[data-row-select]");if(box)box.checked=shouldSelect;}syncListSelection(panel);});
document.addEventListener("click",event=>{const cell=event.target.closest("#device-table tbody td,#credential-table tbody td");if(!cell||event.target.closest("button,input,label,a"))return;const box=cell.closest("tr").querySelector("[data-row-select]");if(!box)return;box.checked=!box.checked;syncListSelection(listPanel(cell));});
document.addEventListener("click",event=>{const box=event.target.closest("#device-table [data-row-select],#credential-table [data-row-select]");if(!box)return;syncListSelection(listPanel(box));});
