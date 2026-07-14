"use strict";

const PAGE_SIZE = 25;
const MAX_RENDERED_EVENTS = 200;

const session = {
  token: "",
  selectedRunId: null,
  offset: 0,
  total: 0,
  pageItems: 0,
  refreshTimer: null,
  refreshing: false,
  actionBusy: false,
  roles: new Set(),
  currentRun: null,
  currentApproval: null,
  canSubmit: false,
  canOperate: false,
  canApprove: false,
};

const elements = {
  tokenForm: document.querySelector("#token-form"),
  tokenInput: document.querySelector("#token-input"),
  lockButton: document.querySelector("#lock-button"),
  connectionState: document.querySelector(".connection-state"),
  connectionLabel: document.querySelector("#connection-label"),
  statusMessage: document.querySelector("#status-message"),
  runForm: document.querySelector("#run-form"),
  campaignName: document.querySelector("#campaign-name"),
  jobKind: document.querySelector("#job-kind"),
  idempotencyKey: document.querySelector("#idempotency-key"),
  maxAttempts: document.querySelector("#max-attempts"),
  runInput: document.querySelector("#run-input"),
  newKeyButton: document.querySelector("#new-key-button"),
  submitButton: document.querySelector("#submit-button"),
  refreshButton: document.querySelector("#refresh-button"),
  stateFilter: document.querySelector("#state-filter"),
  autoRefresh: document.querySelector("#auto-refresh"),
  runsBody: document.querySelector("#runs-body"),
  previousPage: document.querySelector("#previous-page"),
  nextPage: document.querySelector("#next-page"),
  pageSummary: document.querySelector("#page-summary"),
  detailState: document.querySelector("#detail-state"),
  detailRunId: document.querySelector("#detail-run-id"),
  detailCampaign: document.querySelector("#detail-campaign"),
  detailCreated: document.querySelector("#detail-created"),
  detailUpdated: document.querySelector("#detail-updated"),
  detailCheckpoint: document.querySelector("#detail-checkpoint"),
  detailInput: document.querySelector("#detail-input"),
  approvalState: document.querySelector("#approval-state"),
  approvalTool: document.querySelector("#approval-tool"),
  approvalTarget: document.querySelector("#approval-target"),
  approvalRisk: document.querySelector("#approval-risk"),
  approvalExpires: document.querySelector("#approval-expires"),
  approvalDecision: document.querySelector("#approval-decision"),
  workflowReason: document.querySelector("#workflow-reason"),
  workflowHelp: document.querySelector("#workflow-help"),
  approveButton: document.querySelector("#approve-button"),
  denyButton: document.querySelector("#deny-button"),
  resumeButton: document.querySelector("#resume-button"),
  cancelButton: document.querySelector("#cancel-button"),
  eventCount: document.querySelector("#event-count"),
  eventList: document.querySelector("#event-list"),
};

function announce(message, tone = "neutral") {
  elements.statusMessage.textContent = message;
  elements.statusMessage.classList.remove("error", "success");
  if (tone === "error" || tone === "success") {
    elements.statusMessage.classList.add(tone);
  }
}

function newIdempotencyKey() {
  const randomPart = globalThis.crypto && typeof globalThis.crypto.randomUUID === "function"
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  elements.idempotencyKey.value = `web-console-${randomPart}`;
}

function setConnected(connected, roles = []) {
  session.roles = new Set(connected ? roles : []);
  session.canOperate = connected && session.roles.has("operator");
  session.canApprove = connected && session.roles.has("approver");
  session.canSubmit = session.canOperate;
  elements.connectionState.classList.toggle("connected", connected);
  elements.connectionLabel.textContent = connected
    ? roles.map((role) => role.replace("-", " ")).join(" · ")
    : "Locked";
  elements.lockButton.disabled = !connected;
  elements.submitButton.disabled = !session.canSubmit;
  elements.refreshButton.disabled = !connected;
  elements.stateFilter.disabled = !connected;
  elements.autoRefresh.disabled = !connected;
  updateWorkflowControls();
}

function clearDetail() {
  session.selectedRunId = null;
  session.currentRun = null;
  session.currentApproval = null;
  elements.detailState.textContent = "No Run selected";
  elements.detailState.className = "state-badge state-neutral";
  elements.detailRunId.textContent = "—";
  elements.detailCampaign.textContent = "—";
  elements.detailCreated.textContent = "—";
  elements.detailUpdated.textContent = "—";
  elements.detailCheckpoint.textContent = "—";
  elements.detailInput.textContent = "Select a Run to inspect its authorized input.";
  elements.eventCount.textContent = "0 events";
  renderApproval(null);
  const empty = document.createElement("li");
  empty.className = "empty-event";
  empty.textContent = "No events loaded.";
  elements.eventList.replaceChildren(empty);
}

function clearRuns() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty-cell";
  cell.textContent = "Connect to load Runs.";
  row.append(cell);
  elements.runsBody.replaceChildren(row);
  session.offset = 0;
  session.total = 0;
  session.pageItems = 0;
  updatePagination();
}

function stopAutoRefresh() {
  if (session.refreshTimer !== null) {
    globalThis.clearInterval(session.refreshTimer);
    session.refreshTimer = null;
  }
  elements.autoRefresh.checked = false;
}

function lockConsole(message = "Console locked. The in-memory credential was cleared.") {
  session.token = "";
  session.actionBusy = false;
  session.canSubmit = false;
  elements.tokenInput.value = "";
  stopAutoRefresh();
  setConnected(false);
  clearRuns();
  clearDetail();
  announce(message);
}

function errorDetail(payload, status) {
  if (payload && typeof payload === "object" && "detail" in payload) {
    return typeof payload.detail === "string"
      ? payload.detail
      : JSON.stringify(payload.detail);
  }
  return `Control Plane request failed with HTTP ${status}.`;
}

async function apiRequest(path, options = {}) {
  if (!session.token) {
    throw new Error("Connect before calling the Control Plane API.");
  }
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${session.token}`);
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (response.status === 401) {
    lockConsole("Authentication failed. The in-memory credential was cleared.");
  }
  if (!response.ok) {
    throw new Error(errorDetail(payload, response.status));
  }
  return payload;
}

function formatTime(value) {
  if (!value) {
    return "—";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function shortId(value) {
  return value.length > 22 ? `${value.slice(0, 13)}…${value.slice(-6)}` : value;
}

function stateBadge(value) {
  const badge = document.createElement("span");
  badge.className = `state-badge state-${value}`;
  badge.textContent = value;
  return badge;
}

function textCell(value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value;
  if (className) {
    cell.className = className;
  }
  return cell;
}

function renderRuns(items) {
  if (items.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-cell";
    cell.textContent = "No Runs match this filter.";
    row.append(cell);
    elements.runsBody.replaceChildren(row);
    return;
  }

  const rows = items.map((run) => {
    const row = document.createElement("tr");
    row.classList.toggle("selected", run.run_id === session.selectedRunId);

    const campaignCell = document.createElement("td");
    const runName = document.createElement("span");
    runName.className = "run-name";
    const campaign = document.createElement("strong");
    campaign.textContent = run.campaign_name;
    const identifier = document.createElement("code");
    identifier.textContent = shortId(run.run_id);
    identifier.title = run.run_id;
    runName.append(campaign, identifier);
    campaignCell.append(runName);

    const stateCell = document.createElement("td");
    stateCell.append(stateBadge(run.state));

    const actionCell = document.createElement("td");
    const open = document.createElement("button");
    open.type = "button";
    open.className = "button button-quiet open-run";
    open.textContent = "Inspect";
    open.setAttribute("aria-label", `Inspect ${run.campaign_name}`);
    if (run.run_id === session.selectedRunId) {
      open.setAttribute("aria-current", "true");
    }
    open.addEventListener("click", () => selectRun(run.run_id));
    actionCell.append(open);

    row.append(campaignCell, stateCell, textCell(formatTime(run.updated_at)), actionCell);
    return row;
  });
  elements.runsBody.replaceChildren(...rows);
}

function updatePagination() {
  const first = session.total === 0 ? 0 : session.offset + 1;
  const last = Math.min(session.offset + session.pageItems, session.total);
  elements.pageSummary.textContent = `${first}–${last} of ${session.total} Runs`;
  elements.previousPage.disabled = !session.token || session.offset === 0;
  elements.nextPage.disabled = !session.token || session.offset + session.pageItems >= session.total;
}

async function loadRuns() {
  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(session.offset),
  });
  if (elements.stateFilter.value) {
    params.set("state", elements.stateFilter.value);
  }
  const data = await apiRequest(`/v1/runs?${params.toString()}`);
  session.total = data.total;
  session.pageItems = data.items.length;
  renderRuns(data.items);
  updatePagination();
}

function setDetailState(value) {
  elements.detailState.textContent = value;
  elements.detailState.className = `state-badge state-${value}`;
}

function isCancellableRun(run) {
  return run !== null && ["queued", "running", "awaiting-approval"].includes(run.state);
}

function updateWorkflowControls() {
  const run = session.currentRun;
  const approval = session.currentApproval;
  const pendingApproval = approval !== null && approval.state === "pending";
  const resumableApproval = approval !== null
    && approval.state === "approved"
    && run !== null
    && run.state === "awaiting-approval"
    && run.current_checkpoint_id === approval.checkpoint_id;
  const cancellable = isCancellableRun(run);
  const busy = session.actionBusy;

  elements.approveButton.disabled = busy || !session.canApprove || !pendingApproval;
  elements.denyButton.disabled = busy || !session.canApprove || !pendingApproval;
  elements.resumeButton.disabled = busy || !session.canOperate || !resumableApproval;
  elements.cancelButton.disabled = busy || !session.canOperate || !cancellable;
  elements.workflowReason.disabled = busy
    || !(session.canApprove && pendingApproval || session.canOperate && cancellable);

  if (run === null) {
    elements.workflowHelp.textContent = "Select a Run to load its current approval boundary.";
  } else if (pendingApproval && session.canApprove) {
    elements.workflowHelp.textContent = "Review the signed intent summary and record a decision reason.";
  } else if (resumableApproval && session.canOperate) {
    elements.workflowHelp.textContent = "The approval is active. Resume will create one continuation Job.";
  } else if (cancellable && session.canOperate) {
    elements.workflowHelp.textContent = "Cancellation fences dispatch and result commit; external side effects are not rolled back.";
  } else {
    elements.workflowHelp.textContent = "This credential has read-only access to the current workflow state.";
  }
}

function renderApproval(approval) {
  session.currentApproval = approval;
  if (approval === null) {
    elements.approvalState.textContent = "No approval";
    elements.approvalTool.textContent = "—";
    elements.approvalTarget.textContent = "—";
    elements.approvalRisk.textContent = "—";
    elements.approvalExpires.textContent = "—";
    elements.approvalDecision.textContent = "—";
    updateWorkflowControls();
    return;
  }

  elements.approvalState.textContent = approval.state;
  elements.approvalTool.textContent = approval.intent.tool_id;
  elements.approvalTarget.textContent = approval.intent.target;
  elements.approvalRisk.textContent = `T${approval.intent.risk_tier}`;
  elements.approvalExpires.textContent = formatTime(approval.intent.expires_at);
  elements.approvalDecision.textContent = approval.decided_by
    ? `${approval.decided_by}: ${approval.decision_reason || approval.state}`
    : approval.state;
  updateWorkflowControls();
}

function renderEvents(events) {
  const visible = events.slice(-MAX_RENDERED_EVENTS);
  const omitted = events.length - visible.length;
  elements.eventCount.textContent = omitted > 0
    ? `${events.length} events · ${omitted} older hidden`
    : `${events.length} ${events.length === 1 ? "event" : "events"}`;

  if (visible.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-event";
    empty.textContent = "No events recorded.";
    elements.eventList.replaceChildren(empty);
    return;
  }

  const nodes = visible.map((event) => {
    const item = document.createElement("li");
    item.className = "event-item";
    const heading = document.createElement("div");
    heading.className = "event-title";
    const title = document.createElement("strong");
    title.textContent = event.event_type;
    const sequence = document.createElement("span");
    sequence.className = "event-sequence";
    sequence.textContent = `#${event.sequence}`;
    heading.append(title, sequence);
    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.textContent = `${formatTime(event.occurred_at)} · ${event.actor}`;
    const payload = document.createElement("pre");
    payload.textContent = JSON.stringify(event.payload, null, 2);
    item.append(heading, meta, payload);
    return item;
  });
  elements.eventList.replaceChildren(...nodes);
}

async function loadDetail(runId) {
  const [run, events, approval] = await Promise.all([
    apiRequest(`/v1/runs/${encodeURIComponent(runId)}`),
    apiRequest(`/v1/runs/${encodeURIComponent(runId)}/events`),
    apiRequest(`/v1/runs/${encodeURIComponent(runId)}/approval`),
  ]);
  if (session.selectedRunId !== runId) {
    return;
  }
  session.currentRun = run;
  setDetailState(run.state);
  elements.detailRunId.textContent = run.run_id;
  elements.detailCampaign.textContent = run.campaign_name;
  elements.detailCreated.textContent = formatTime(run.created_at);
  elements.detailUpdated.textContent = formatTime(run.updated_at);
  elements.detailCheckpoint.textContent = run.current_checkpoint_id || "—";
  elements.detailInput.textContent = JSON.stringify(run.input, null, 2);
  renderApproval(approval);
  renderEvents(events);
}

async function selectRun(runId) {
  session.selectedRunId = runId;
  announce(`Loading ${shortId(runId)}…`);
  try {
    await Promise.all([loadRuns(), loadDetail(runId)]);
    announce(`Loaded ${shortId(runId)}.`, "success");
  } catch (error) {
    announce(error instanceof Error ? error.message : "Unable to load Run detail.", "error");
  }
}

async function refreshCurrent({ quiet = false } = {}) {
  if (!session.token || session.refreshing) {
    return;
  }
  session.refreshing = true;
  try {
    await loadRuns();
    if (session.selectedRunId) {
      await loadDetail(session.selectedRunId);
    }
    if (!quiet) {
      announce("Run state refreshed.", "success");
    }
  } catch (error) {
    announce(error instanceof Error ? error.message : "Refresh failed.", "error");
  } finally {
    session.refreshing = false;
  }
}

function requiredWorkflowReason() {
  const reason = elements.workflowReason.value.trim();
  if (!reason) {
    announce("Record a decision or cancellation reason before continuing.", "error");
    elements.workflowReason.focus();
    return null;
  }
  return reason;
}

async function refreshActionState(runId) {
  if (!session.token) {
    return;
  }
  await loadRuns();
  if (session.selectedRunId === runId) {
    await loadDetail(runId);
  }
}

async function performWorkflowAction(runId, pendingMessage, successMessage, operation) {
  if (session.actionBusy) {
    return;
  }
  session.actionBusy = true;
  updateWorkflowControls();
  announce(pendingMessage);
  try {
    await operation();
    elements.workflowReason.value = "";
    await refreshActionState(runId);
    announce(successMessage, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Workflow action failed.";
    try {
      await refreshActionState(runId);
    } catch {
      // Preserve the authoritative action error; the next manual refresh can retry state loading.
    }
    announce(message, "error");
  } finally {
    session.actionBusy = false;
    updateWorkflowControls();
  }
}

async function decideCurrentApproval(approve) {
  const run = session.currentRun;
  const approval = session.currentApproval;
  const reason = requiredWorkflowReason();
  if (run === null || approval === null || reason === null) {
    return;
  }
  await performWorkflowAction(
    run.run_id,
    approve ? "Recording approval decision…" : "Recording denial decision…",
    approve ? "Approval recorded." : "Approval denied and Run cancelled.",
    () => apiRequest(`/v1/approvals/${encodeURIComponent(approval.approval_id)}/decision`, {
      method: "POST",
      body: JSON.stringify({ approve, reason }),
    }),
  );
}

async function resumeCurrentCheckpoint() {
  const run = session.currentRun;
  const approval = session.currentApproval;
  if (run === null || approval === null) {
    return;
  }
  await performWorkflowAction(
    run.run_id,
    "Claiming the approved checkpoint…",
    "Checkpoint consumed and continuation Job queued.",
    () => apiRequest(`/v1/checkpoints/${encodeURIComponent(approval.checkpoint_id)}/resume`, {
      method: "POST",
      body: JSON.stringify({ approval_id: approval.approval_id }),
    }),
  );
}

async function cancelCurrentRun() {
  const run = session.currentRun;
  const reason = requiredWorkflowReason();
  if (run === null || reason === null) {
    return;
  }
  await performWorkflowAction(
    run.run_id,
    "Fencing Run dispatch and result commit…",
    "Run cancellation recorded.",
    () => apiRequest(`/v1/runs/${encodeURIComponent(run.run_id)}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  );
}

elements.tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const candidate = elements.tokenInput.value.trim();
  if (candidate.length < 32) {
    announce("A Control Plane bearer token must contain at least 32 characters.", "error");
    elements.tokenInput.focus();
    return;
  }
  session.token = candidate;
  elements.tokenInput.value = "";
  announce("Authenticating and loading Runs…");
  try {
    const principal = await apiRequest("/v1/session");
    const roles = [...principal.roles].sort();
    setConnected(true, roles);
    await loadRuns();
    announce(
      `Connected as ${principal.subject} (${roles.join(", ")}).`,
      "success",
    );
  } catch (error) {
    if (session.token) {
      lockConsole(error instanceof Error ? error.message : "Connection failed.");
      elements.statusMessage.classList.add("error");
    }
  }
});

elements.lockButton.addEventListener("click", () => lockConsole());
elements.newKeyButton.addEventListener("click", newIdempotencyKey);
elements.approveButton.addEventListener("click", () => decideCurrentApproval(true));
elements.denyButton.addEventListener("click", () => decideCurrentApproval(false));
elements.resumeButton.addEventListener("click", resumeCurrentCheckpoint);
elements.cancelButton.addEventListener("click", cancelCurrentRun);

elements.runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  let input;
  try {
    input = JSON.parse(elements.runInput.value);
  } catch {
    announce("Executor input must be valid JSON.", "error");
    elements.runInput.focus();
    return;
  }
  if (input === null || Array.isArray(input) || typeof input !== "object") {
    announce("Executor input must be a JSON object.", "error");
    elements.runInput.focus();
    return;
  }

  const request = {
    campaign_name: elements.campaignName.value,
    input,
    idempotency_key: elements.idempotencyKey.value,
    max_attempts: Number(elements.maxAttempts.value),
    job_kind: elements.jobKind.value,
  };
  elements.submitButton.disabled = true;
  announce("Submitting the idempotent Run request…");
  try {
    const submission = await apiRequest("/v1/runs", {
      method: "POST",
      body: JSON.stringify(request),
    });
    session.offset = 0;
    session.selectedRunId = submission.run.run_id;
    await Promise.all([loadRuns(), loadDetail(submission.run.run_id)]);
    announce(
      submission.created ? "Run submitted and queued." : "Existing idempotent Run loaded.",
      "success",
    );
  } catch (error) {
    announce(error instanceof Error ? error.message : "Run submission failed.", "error");
  } finally {
    elements.submitButton.disabled = !session.canSubmit;
  }
});

elements.refreshButton.addEventListener("click", () => refreshCurrent());
elements.stateFilter.addEventListener("change", () => {
  session.offset = 0;
  refreshCurrent();
});
elements.previousPage.addEventListener("click", () => {
  session.offset = Math.max(0, session.offset - PAGE_SIZE);
  refreshCurrent();
});
elements.nextPage.addEventListener("click", () => {
  if (session.offset + session.pageItems < session.total) {
    session.offset += PAGE_SIZE;
    refreshCurrent();
  }
});
elements.autoRefresh.addEventListener("change", () => {
  const enabled = elements.autoRefresh.checked;
  stopAutoRefresh();
  if (enabled && session.token) {
    elements.autoRefresh.checked = true;
    session.refreshTimer = globalThis.setInterval(() => refreshCurrent({ quiet: true }), 5_000);
  }
});

globalThis.addEventListener("pagehide", () => {
  session.token = "";
  stopAutoRefresh();
});

newIdempotencyKey();
setConnected(false);
updatePagination();
