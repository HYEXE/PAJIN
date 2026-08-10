"use strict";

import {
  ApiProtocolError,
  MAX_RENDERED_EVENTS,
  PAGE_SIZE,
  errorDetail,
  formatJson,
  isJsonMediaType,
  isRunState,
  parseJsonPayload,
  protocolFailure,
  runSubmissionBody,
  validateApproval,
  validateApprovalDecision,
  validateCancellation,
  validateDiscoveryView,
  validateEvents,
  validatePrincipal,
  validateResume,
  validateRun,
  validateRunList,
  validateSubmission,
} from "./protocol.js";
import {
  createEventNodes,
  createRunRows,
  createSurfaceNodes,
  createWaveNodes,
  eventCountLabel,
  formatTime,
  shortId,
} from "./render.js";

const MAX_EXECUTOR_INPUT_BYTES = 1_000_000;

class StaleRequestError extends Error {
  constructor() {
    super("The request belongs to an inactive console session.");
    this.name = "StaleRequestError";
  }
}

const session = {
  token: "",
  connected: false,
  authEpoch: 0,
  requestControllers: new Set(),
  selectedRunId: null,
  selectionEpoch: 0,
  listRequestId: 0,
  detailRequestId: 0,
  detailLoading: false,
  eventRequestId: 0,
  eventPageRunId: null,
  eventPageBefore: null,
  eventOldestSequence: null,
  eventAtLatest: true,
  eventHasOlder: false,
  eventLoading: false,
  offset: 0,
  total: 0,
  pageItems: 0,
  refreshTimer: null,
  refreshTask: null,
  actionBusy: false,
  actionSequence: 0,
  submissionBusy: false,
  submissionSequence: 0,
  discoveryRequestId: 0,
  discoveryLoading: false,
  roles: new Set(),
  subject: null,
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
  runsPanel: document.querySelector("#runs-panel"),
  detailPanel: document.querySelector("#detail-panel"),
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
  workflowControl: document.querySelector("#workflow-control"),
  approveButton: document.querySelector("#approve-button"),
  denyButton: document.querySelector("#deny-button"),
  resumeButton: document.querySelector("#resume-button"),
  cancelButton: document.querySelector("#cancel-button"),
  eventCount: document.querySelector("#event-count"),
  eventList: document.querySelector("#event-list"),
  latestEventsButton: document.querySelector("#latest-events-button"),
  olderEventsButton: document.querySelector("#older-events-button"),
  discoveryPanel: document.querySelector("#discovery-panel"),
  discoveryForm: document.querySelector("#discovery-form"),
  discoveryCampaign: document.querySelector("#discovery-campaign"),
  discoveryRunId: document.querySelector("#discovery-run-id"),
  discoveryLoadButton: document.querySelector("#discovery-load-button"),
  discoveryEmpty: document.querySelector("#discovery-empty"),
  discoveryResult: document.querySelector("#discovery-result"),
  discoveryCampaignValue: document.querySelector("#discovery-campaign-value"),
  discoveryRunValue: document.querySelector("#discovery-run-value"),
  discoverySurfaceSetValue: document.querySelector("#discovery-surface-set-value"),
  discoverySnapshotValue: document.querySelector("#discovery-snapshot-value"),
  surfaceCount: document.querySelector("#surface-count"),
  surfaceList: document.querySelector("#surface-list"),
  waveTimeline: document.querySelector("#wave-timeline"),
};

function setBusy(element, busy) {
  element.setAttribute("aria-busy", busy ? "true" : "false");
}

function resetBusyIndicators() {
  setBusy(elements.tokenForm, false);
  setBusy(elements.runForm, false);
  setBusy(elements.runsPanel, false);
  setBusy(elements.detailPanel, false);
  setBusy(elements.workflowControl, false);
  setBusy(elements.eventList, false);
  setBusy(elements.discoveryForm, false);
  setBusy(elements.discoveryPanel, false);
}

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

function setConnected(connected, roles = [], subject = null) {
  session.connected = connected;
  session.roles = new Set(connected ? roles : []);
  session.subject = connected ? subject : null;
  session.canOperate = connected && session.roles.has("operator");
  session.canApprove = connected && session.roles.has("approver");
  session.canSubmit = session.canOperate;
  elements.connectionState.classList.toggle("connected", connected);
  elements.connectionLabel.textContent = connected
    ? roles.map((role) => role.replace("-", " ")).join(" · ")
    : "Locked";
  elements.lockButton.disabled = !session.token;
  elements.submitButton.disabled = !session.canSubmit;
  elements.refreshButton.disabled = !connected;
  elements.stateFilter.disabled = !connected;
  elements.autoRefresh.disabled = !connected;
  elements.discoveryCampaign.disabled = !session.canOperate;
  elements.discoveryRunId.disabled = !session.canOperate;
  elements.discoveryLoadButton.disabled = !session.canOperate || session.discoveryLoading;
  if (!connected) {
    elements.discoveryEmpty.textContent = (
      "Connect with an Operator credential to inspect a verified Discovery Run."
    );
  } else if (!session.canOperate) {
    elements.discoveryEmpty.textContent = (
      "This projection requires an Operator credential; Approver and Auditor roles are read-denied."
    );
  }
  updateWorkflowControls();
  updateEventPaginationControls();
}

function updateEventPaginationControls() {
  const unavailable = !session.connected
    || session.eventLoading
    || session.eventPageRunId !== session.selectedRunId;
  elements.latestEventsButton.disabled = unavailable || session.eventAtLatest;
  elements.olderEventsButton.disabled = unavailable || !session.eventHasOlder;
}

function resetEventPagination(runId = null, { loading = false } = {}) {
  session.eventPageRunId = runId;
  session.eventPageBefore = null;
  session.eventOldestSequence = null;
  session.eventAtLatest = true;
  session.eventHasOlder = false;
  session.eventLoading = loading;
  setBusy(elements.eventList, loading);
  updateEventPaginationControls();
}

function clearDetail() {
  session.selectedRunId = null;
  session.selectionEpoch += 1;
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
  elements.workflowReason.value = "";
  elements.eventCount.textContent = "0 events";
  resetEventPagination();
  renderApproval(null);
  const empty = document.createElement("li");
  empty.className = "empty-event";
  empty.textContent = "No events loaded.";
  elements.eventList.replaceChildren(empty);
}

function clearDiscovery({ clearInputs = false, message = null } = {}) {
  if (clearInputs) {
    elements.discoveryCampaign.value = "";
    elements.discoveryRunId.value = "";
  }
  elements.discoveryResult.hidden = true;
  elements.discoveryEmpty.hidden = false;
  if (message !== null) {
    elements.discoveryEmpty.textContent = message;
  }
  elements.discoveryCampaignValue.textContent = "--";
  elements.discoveryRunValue.textContent = "--";
  elements.discoverySurfaceSetValue.textContent = "--";
  elements.discoverySnapshotValue.textContent = "--";
  elements.surfaceCount.textContent = "0 surfaces";
  elements.surfaceList.replaceChildren();
  elements.waveTimeline.replaceChildren();
}

function renderDiscovery(view) {
  const surfaceCount = view.surfaceSet.surfaceCount;
  elements.discoveryCampaignValue.textContent = view.campaign.name;
  elements.discoveryRunValue.textContent = view.hypothesisRun.runId;
  elements.discoverySurfaceSetValue.textContent = view.surfaceSet.surfaceSetId;
  elements.discoverySnapshotValue.textContent = String(view.surfaceSnapshot.revision);
  elements.surfaceCount.textContent = `${surfaceCount} ${surfaceCount === 1 ? "surface" : "surfaces"}`;
  elements.surfaceList.replaceChildren(
    ...createSurfaceNodes(document, view.surfaceSet.surfaces),
  );
  elements.waveTimeline.replaceChildren(...createWaveNodes(document, view.waves));
  elements.discoveryEmpty.hidden = true;
  elements.discoveryResult.hidden = false;
}

function prepareDetailLoading(runId) {
  session.currentRun = null;
  session.currentApproval = null;
  setDetailState("Loading");
  elements.detailRunId.textContent = runId;
  elements.detailCampaign.textContent = "—";
  elements.detailCreated.textContent = "—";
  elements.detailUpdated.textContent = "—";
  elements.detailCheckpoint.textContent = "—";
  elements.detailInput.textContent = "Loading authorized input…";
  elements.eventCount.textContent = "0 events";
  resetEventPagination(runId, { loading: true });
  renderApproval(null);
  const loading = document.createElement("li");
  loading.className = "empty-event";
  loading.textContent = "Loading events…";
  elements.eventList.replaceChildren(loading);
}

function renderDetailFailure(runId) {
  session.currentRun = null;
  session.currentApproval = null;
  setDetailState("Unavailable");
  elements.detailRunId.textContent = runId;
  elements.detailCampaign.textContent = "—";
  elements.detailCreated.textContent = "—";
  elements.detailUpdated.textContent = "—";
  elements.detailCheckpoint.textContent = "—";
  elements.detailInput.textContent = "Current Run detail is unavailable. Refresh to retry.";
  elements.eventCount.textContent = "0 events";
  resetEventPagination(runId);
  renderApproval(null);
  const unavailable = document.createElement("li");
  unavailable.className = "empty-event";
  unavailable.textContent = "Audit events are unavailable. Refresh to retry.";
  elements.eventList.replaceChildren(unavailable);
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

function renderRunsUnavailable() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty-cell";
  cell.textContent = "Runs are unavailable. Use Refresh to retry.";
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

function replaceCredential(token) {
  session.authEpoch += 1;
  session.token = token;
  for (const controller of session.requestControllers) {
    controller.abort();
  }
  session.requestControllers.clear();
  session.listRequestId += 1;
  session.detailRequestId += 1;
  session.detailLoading = false;
  session.eventRequestId += 1;
  session.selectionEpoch += 1;
  session.actionSequence += 1;
  session.actionBusy = false;
  session.submissionSequence += 1;
  session.submissionBusy = false;
  session.discoveryRequestId += 1;
  session.discoveryLoading = false;
  session.refreshTask = null;
  resetBusyIndicators();
}

function lockConsole(
  message = "Console locked. The in-memory credential was cleared.",
  tone = "neutral",
  { focusToken = true } = {},
) {
  replaceCredential("");
  elements.tokenInput.value = "";
  stopAutoRefresh();
  setConnected(false);
  clearRuns();
  clearDetail();
  clearDiscovery({ clearInputs: true });
  announce(message, tone);
  if (focusToken) {
    elements.tokenInput.focus();
  }
}

function requestIsCurrent(epoch, token) {
  return session.authEpoch === epoch && session.token === token && token !== "";
}

function isStaleRequest(error) {
  return error instanceof StaleRequestError;
}

async function apiRequest(path, options = {}) {
  if (!session.token) {
    throw new Error("Connect before calling the Control Plane API.");
  }
  const token = session.token;
  const epoch = session.authEpoch;
  const controller = new AbortController();
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${token}`);
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  session.requestControllers.add(controller);
  try {
    const response = await fetch(path, {
      ...options,
      headers,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    if (!requestIsCurrent(epoch, token)) {
      throw new StaleRequestError();
    }
    if (response.status === 401) {
      lockConsole("Authentication failed. The in-memory credential was cleared.", "error");
      throw new StaleRequestError();
    }

    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (isJsonMediaType(contentType) && response.status !== 204 && response.status !== 205) {
      payload = parseJsonPayload(await response.text(), response.status);
    }
    if (!requestIsCurrent(epoch, token)) {
      throw new StaleRequestError();
    }
    if (!response.ok) {
      throw new Error(errorDetail(payload, response.status));
    }
    if (response.status === 204 || response.status === 205 || !isJsonMediaType(contentType)) {
      throw new ApiProtocolError(
        `Control Plane returned an empty or non-JSON success response (HTTP ${response.status}).`,
      );
    }
    return payload;
  } catch (error) {
    if (!requestIsCurrent(epoch, token)) {
      throw new StaleRequestError();
    }
    throw error;
  } finally {
    session.requestControllers.delete(controller);
  }
}

function renderRuns(items) {
  elements.runsBody.replaceChildren(
    ...createRunRows(document, items, session.selectedRunId, selectRun),
  );
}

function updatePagination() {
  const first = session.total === 0 ? 0 : session.offset + 1;
  const last = Math.min(session.offset + session.pageItems, session.total);
  elements.pageSummary.textContent = `${first}–${last} of ${session.total} Runs`;
  elements.previousPage.disabled = !session.connected || session.offset === 0;
  elements.nextPage.disabled = !session.connected
    || session.offset + session.pageItems >= session.total;
}

async function loadRuns() {
  const requestId = ++session.listRequestId;
  const requestedOffset = session.offset;
  const requestedState = elements.stateFilter.value;
  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(requestedOffset),
  });
  if (requestedState) {
    params.set("state", requestedState);
  }
  setBusy(elements.runsPanel, true);
  try {
    const data = validateRunList(
      await apiRequest(`/v1/runs?${params.toString()}`),
      requestedOffset,
    );
    if (requestId !== session.listRequestId
      || requestedOffset !== session.offset
      || requestedState !== elements.stateFilter.value) {
      return false;
    }
    if (data.total === 0 && requestedOffset !== 0) {
      session.offset = 0;
    } else if (data.total > 0 && requestedOffset >= data.total) {
      session.offset = Math.floor((data.total - 1) / PAGE_SIZE) * PAGE_SIZE;
      return loadRuns();
    }
    session.total = data.total;
    session.pageItems = data.items.length;
    renderRuns(data.items);
    updatePagination();
    return true;
  } finally {
    if (requestId === session.listRequestId) {
      setBusy(elements.runsPanel, false);
    }
  }
}

function setDetailState(value) {
  elements.detailState.textContent = value;
  elements.detailState.className = isRunState(value)
    ? `state-badge state-${value}`
    : "state-badge state-neutral";
}

function isCancellableRun(run) {
  return run !== null && ["queued", "running", "awaiting-approval"].includes(run.state);
}

function updateWorkflowControls() {
  const run = session.currentRun;
  const approval = session.currentApproval;
  const approvalMatchesCurrentCheckpoint = approval !== null
    && run !== null
    && run.state === "awaiting-approval"
    && run.current_checkpoint_id === approval.checkpoint_id;
  const pendingApproval = approvalMatchesCurrentCheckpoint && approval.state === "pending";
  const selfRequestedApproval = pendingApproval
    && approval.requested_by === session.subject;
  const canDecide = session.canApprove && pendingApproval && !selfRequestedApproval;
  const resumableApproval = approvalMatchesCurrentCheckpoint && approval.state === "approved";
  const cancellable = isCancellableRun(run);
  const busy = session.actionBusy || session.detailLoading;

  setBusy(elements.workflowControl, busy);
  elements.approveButton.disabled = busy || !canDecide;
  elements.denyButton.disabled = busy || !canDecide;
  elements.resumeButton.disabled = busy || !session.canOperate || !resumableApproval;
  elements.cancelButton.disabled = busy || !session.canOperate || !cancellable;
  elements.workflowReason.disabled = busy
    || !(canDecide || session.canOperate && cancellable);

  if (run === null) {
    elements.workflowHelp.textContent = "Select a Run to load its current approval boundary.";
  } else if (selfRequestedApproval && session.canApprove) {
    elements.workflowHelp.textContent = "The approval requester cannot decide their own request.";
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

function renderEvents(events, runId, { atLatest = true, before = null } = {}) {
  session.eventPageRunId = runId;
  session.eventPageBefore = before;
  session.eventOldestSequence = events.length > 0 ? events[0].sequence : null;
  session.eventAtLatest = atLatest;
  session.eventHasOlder = session.eventOldestSequence !== null
    && session.eventOldestSequence > 1;
  elements.eventCount.textContent = eventCountLabel(events);
  updateEventPaginationControls();
  elements.eventList.replaceChildren(...createEventNodes(document, events));
}

function eventPagePath(runId, before = null) {
  const params = new URLSearchParams({ limit: String(MAX_RENDERED_EVENTS) });
  if (before !== null) {
    params.set("before", String(before));
  }
  return `/v1/runs/${encodeURIComponent(runId)}/events?${params.toString()}`;
}

async function loadDetail(runId) {
  const requestId = ++session.detailRequestId;
  const eventRequestId = ++session.eventRequestId;
  const eventBefore = session.eventPageRunId === runId && !session.eventAtLatest
    ? session.eventPageBefore
    : null;
  session.detailLoading = true;
  session.eventLoading = true;
  setBusy(elements.detailPanel, true);
  setBusy(elements.eventList, true);
  updateWorkflowControls();
  updateEventPaginationControls();
  try {
    const [run, events, approval] = await Promise.all([
      apiRequest(`/v1/runs/${encodeURIComponent(runId)}`),
      apiRequest(eventPagePath(runId, eventBefore)),
      apiRequest(`/v1/runs/${encodeURIComponent(runId)}/approval`),
    ]);
    const checkedRun = validateRun(run, { detail: true });
    if (checkedRun.run_id !== runId) {
      protocolFailure("Run detail");
    }
    const checkedEvents = validateEvents(events, runId, eventBefore);
    const checkedApproval = validateApproval(approval, runId);
    if (checkedApproval !== null
      && ["pending", "approved"].includes(checkedApproval.state)
      && (checkedRun.state !== "awaiting-approval"
        || checkedRun.current_checkpoint_id !== checkedApproval.checkpoint_id)) {
      protocolFailure("Run approval graph");
    }
    if (session.selectedRunId !== runId
      || requestId !== session.detailRequestId
      || eventRequestId !== session.eventRequestId) {
      return false;
    }
    session.currentRun = checkedRun;
    setDetailState(checkedRun.state);
    elements.detailRunId.textContent = checkedRun.run_id;
    elements.detailCampaign.textContent = checkedRun.campaign_name;
    elements.detailCreated.textContent = formatTime(checkedRun.created_at);
    elements.detailUpdated.textContent = formatTime(checkedRun.updated_at);
    elements.detailCheckpoint.textContent = checkedRun.current_checkpoint_id || "—";
    elements.detailInput.textContent = formatJson(checkedRun.input);
    renderApproval(checkedApproval);
    renderEvents(checkedEvents, runId, {
      atLatest: eventBefore === null,
      before: eventBefore,
    });
    return true;
  } catch (error) {
    if (!isStaleRequest(error)
      && session.selectedRunId === runId
      && requestId === session.detailRequestId
      && eventRequestId === session.eventRequestId) {
      renderDetailFailure(runId);
    }
    throw error;
  } finally {
    if (requestId === session.detailRequestId) {
      session.detailLoading = false;
      setBusy(elements.detailPanel, false);
      updateWorkflowControls();
    }
    if (eventRequestId === session.eventRequestId) {
      session.eventLoading = false;
      setBusy(elements.eventList, false);
      updateEventPaginationControls();
    }
  }
}

async function loadEventPage(before = null) {
  const runId = session.selectedRunId;
  if (runId === null || session.eventLoading) {
    return;
  }
  const requestId = ++session.eventRequestId;
  session.eventLoading = true;
  setBusy(elements.eventList, true);
  updateEventPaginationControls();
  announce(before === null ? "Loading latest audit events…" : "Loading older audit events…");
  try {
    const events = validateEvents(
      await apiRequest(eventPagePath(runId, before)),
      runId,
      before,
    );
    if (requestId !== session.eventRequestId || session.selectedRunId !== runId) {
      return;
    }
    renderEvents(events, runId, { atLatest: before === null, before });
    announce(before === null ? "Latest audit events loaded." : "Older audit events loaded.", "success");
  } catch (error) {
    if (!isStaleRequest(error)
      && requestId === session.eventRequestId
      && session.selectedRunId === runId) {
      announce(error instanceof Error ? error.message : "Unable to load audit events.", "error");
    }
  } finally {
    if (requestId === session.eventRequestId) {
      session.eventLoading = false;
      setBusy(elements.eventList, false);
      updateEventPaginationControls();
    }
  }
}

async function selectRun(runId) {
  if (session.selectedRunId !== runId) {
    elements.workflowReason.value = "";
  }
  session.selectedRunId = runId;
  const selectionEpoch = ++session.selectionEpoch;
  prepareDetailLoading(runId);
  announce(`Loading ${shortId(runId)}…`);
  try {
    const [, detailLoaded] = await Promise.all([loadRuns(), loadDetail(runId)]);
    if (detailLoaded
      && session.selectedRunId === runId
      && session.selectionEpoch === selectionEpoch) {
      announce(`Loaded ${shortId(runId)}.`, "success");
      elements.detailPanel.focus();
    }
  } catch (error) {
    if (!isStaleRequest(error)
      && session.selectedRunId === runId
      && session.selectionEpoch === selectionEpoch) {
      announce(error instanceof Error ? error.message : "Unable to load Run detail.", "error");
    }
  }
}

function refreshCurrent({ quiet = false } = {}) {
  if (!session.token || !session.connected) {
    return Promise.resolve();
  }
  const epoch = session.authEpoch;
  const token = session.token;
  if (session.refreshTask !== null && session.refreshTask.epoch === epoch) {
    if (!quiet) {
      session.refreshTask.requested = true;
      session.refreshTask.announceOnSuccess = true;
    }
    return session.refreshTask.promise;
  }

  const task = {
    epoch,
    requested: true,
    announceOnSuccess: !quiet,
    promise: null,
  };
  task.promise = (async () => {
    while (task.requested && requestIsCurrent(epoch, token) && session.connected) {
      task.requested = false;
      const announceOnSuccess = task.announceOnSuccess;
      task.announceOnSuccess = false;
      let refreshError = null;
      try {
        const selectedRunId = session.selectedRunId;
        await Promise.all([
          loadRuns(),
          selectedRunId === null ? Promise.resolve() : loadDetail(selectedRunId),
        ]);
      } catch (error) {
        if (isStaleRequest(error)) {
          return;
        }
        refreshError = error;
      }

      if (task.requested) {
        task.announceOnSuccess ||= announceOnSuccess;
        continue;
      }
      if (refreshError !== null) {
        announce(
          refreshError instanceof Error ? refreshError.message : "Refresh failed.",
          "error",
        );
      } else if (announceOnSuccess) {
        announce("Run state refreshed.", "success");
      }
    }
  })().finally(() => {
    if (session.refreshTask === task) {
      session.refreshTask = null;
    }
  });
  session.refreshTask = task;
  return task.promise;
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
  if (!session.token || !session.connected) {
    return;
  }
  await Promise.all([
    loadRuns(),
    session.selectedRunId === runId ? loadDetail(runId) : Promise.resolve(),
  ]);
}

async function performWorkflowAction(runId, pendingMessage, successMessage, operation) {
  if (session.actionBusy) {
    return;
  }
  const actionId = ++session.actionSequence;
  session.actionBusy = true;
  updateWorkflowControls();
  announce(pendingMessage);
  let result;
  try {
    result = await operation();
  } catch (error) {
    if (isStaleRequest(error) || session.actionSequence !== actionId) {
      return;
    }
    const message = error instanceof Error ? error.message : "Workflow action failed.";
    try {
      await refreshActionState(runId);
    } catch {
      // Preserve the authoritative action error; the next manual refresh can retry state loading.
    }
    if (session.actionSequence !== actionId) {
      return;
    }
    announce(message, "error");
    session.actionBusy = false;
    updateWorkflowControls();
    return;
  }

  elements.workflowReason.value = "";
  try {
    await refreshActionState(runId);
  } catch (error) {
    if (!isStaleRequest(error) && session.actionSequence === actionId) {
      announce(
        "The action response was validated, but refreshed state could not be loaded. "
          + "Use Refresh before taking another action.",
        "error",
      );
    }
    return;
  } finally {
    if (session.actionSequence === actionId) {
      session.actionBusy = false;
      updateWorkflowControls();
    }
  }

  if (session.actionSequence === actionId) {
    announce(
      typeof successMessage === "function" ? successMessage(result) : successMessage,
      "success",
    );
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
    approve ? "Approval recorded." : "Denial recorded; refreshed Run state loaded.",
    async () => validateApprovalDecision(
      await apiRequest(`/v1/approvals/${encodeURIComponent(approval.approval_id)}/decision`, {
        method: "POST",
        body: JSON.stringify({ approve, reason }),
      }),
      run.run_id,
      approval.approval_id,
      approve,
    ),
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
    async () => validateResume(
      await apiRequest(`/v1/checkpoints/${encodeURIComponent(approval.checkpoint_id)}/resume`, {
        method: "POST",
        body: JSON.stringify({ approval_id: approval.approval_id }),
      }),
      run.run_id,
      approval.checkpoint_id,
      approval.approval_id,
    ),
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
    (cancellation) => cancellation.applied
      ? "Run cancellation recorded."
      : "Run was already cancelled; current state loaded.",
    async () => validateCancellation(
      await apiRequest(`/v1/runs/${encodeURIComponent(run.run_id)}/cancel`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      }),
      run.run_id,
    ),
  );
}

elements.tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const candidate = elements.tokenInput.value;
  if (candidate.length < 32 || candidate.length > 4_096) {
    announce(
      "A Control Plane bearer token must contain between 32 and 4096 characters.",
      "error",
    );
    elements.tokenInput.focus();
    return;
  }
  replaceCredential(candidate);
  const authEpoch = session.authEpoch;
  setBusy(elements.tokenForm, true);
  stopAutoRefresh();
  setConnected(false);
  clearRuns();
  clearDetail();
  clearDiscovery({ clearInputs: true });
  elements.tokenInput.value = "";
  announce("Authenticating and loading Runs…");
  try {
    let principal;
    try {
      principal = validatePrincipal(await apiRequest("/v1/session"));
    } catch (error) {
      if (!isStaleRequest(error) && session.authEpoch === authEpoch && session.token) {
        lockConsole(error instanceof Error ? error.message : "Connection failed.", "error");
      }
      return;
    }

    const roles = [...principal.roles].sort();
    setConnected(true, roles, principal.subject);
    announce(`Authenticated as ${principal.subject}; loading Runs…`);
    try {
      await loadRuns();
    } catch (error) {
      if (!isStaleRequest(error) && session.authEpoch === authEpoch && session.connected) {
        const message = error instanceof Error ? error.message : "Unable to load Runs.";
        renderRunsUnavailable();
        announce(`Connected as ${principal.subject}, but Runs could not be loaded: ${message}`, "error");
      }
      return;
    }
    if (session.authEpoch === authEpoch) {
      announce(
        `Connected as ${principal.subject} (${roles.join(", ")}).`,
        "success",
      );
    }
  } finally {
    if (session.authEpoch === authEpoch) {
      setBusy(elements.tokenForm, false);
    }
  }
});

elements.lockButton.addEventListener("click", () => lockConsole());
elements.newKeyButton.addEventListener("click", newIdempotencyKey);
elements.approveButton.addEventListener("click", () => decideCurrentApproval(true));
elements.denyButton.addEventListener("click", () => decideCurrentApproval(false));
elements.resumeButton.addEventListener("click", resumeCurrentCheckpoint);
elements.cancelButton.addEventListener("click", cancelCurrentRun);
elements.latestEventsButton.addEventListener("click", () => loadEventPage());
elements.olderEventsButton.addEventListener("click", () => {
  if (session.eventOldestSequence !== null) {
    return loadEventPage(session.eventOldestSequence);
  }
});

elements.runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!session.canSubmit || session.submissionBusy) {
    return;
  }
  if (new TextEncoder().encode(elements.runInput.value).byteLength > MAX_EXECUTOR_INPUT_BYTES) {
    announce("Executor input exceeds the 1,000,000-byte JSON limit.", "error");
    elements.runInput.focus();
    return;
  }
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
  input = null;

  const campaignName = elements.campaignName.value;
  const idempotencyKey = elements.idempotencyKey.value;
  const maxAttempts = Number(elements.maxAttempts.value);
  const jobKind = elements.jobKind.value;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(campaignName)
    || idempotencyKey.length < 8
    || idempotencyKey.length > 200
    || !Number.isInteger(maxAttempts)
    || maxAttempts < 1
    || maxAttempts > 20
    || !["campaign", "tool-loop"].includes(jobKind)) {
    announce("Run fields do not satisfy the bounded Control Plane contract.", "error");
    return;
  }

  const requestBody = runSubmissionBody({
    campaignName,
    rawInput: elements.runInput.value,
    idempotencyKey,
    maxAttempts,
    jobKind,
  });
  const submissionId = ++session.submissionSequence;
  session.submissionBusy = true;
  setBusy(elements.runForm, true);
  elements.submitButton.disabled = true;
  announce("Submitting the idempotent Run request…");
  try {
    let submission;
    try {
      submission = validateSubmission(
        await apiRequest("/v1/runs", {
          method: "POST",
          body: requestBody,
        }),
        { campaignName, jobKind },
      );
    } catch (error) {
      if (!isStaleRequest(error) && session.submissionSequence === submissionId) {
        announce(error instanceof Error ? error.message : "Run submission failed.", "error");
      }
      return;
    }

    if (session.submissionSequence !== submissionId) {
      return;
    }
    const successMessage = submission.created
      ? "Run submitted and queued."
      : "Existing idempotent Run loaded.";
    session.offset = 0;
    session.selectedRunId = submission.run.run_id;
    elements.workflowReason.value = "";
    const selectionEpoch = ++session.selectionEpoch;
    prepareDetailLoading(submission.run.run_id);
    announce(successMessage, "success");

    const [listResult, detailResult] = await Promise.allSettled([
      loadRuns(),
      loadDetail(submission.run.run_id),
    ]);
    if (session.submissionSequence !== submissionId
      || session.selectedRunId !== submission.run.run_id
      || session.selectionEpoch !== selectionEpoch) {
      return;
    }
    const refreshFailure = [listResult, detailResult]
      .find((result) => result.status === "rejected");
    if (detailResult.status === "fulfilled" && detailResult.value) {
      elements.detailPanel.focus();
    }
    if (refreshFailure !== undefined) {
      if (!isStaleRequest(refreshFailure.reason)) {
        announce(
          `${successMessage} Current state could not be fully loaded; use Refresh to retry.`,
          "error",
        );
      }
      return;
    }
  } finally {
    if (session.submissionSequence === submissionId) {
      session.submissionBusy = false;
      setBusy(elements.runForm, false);
      elements.submitButton.disabled = !session.canSubmit;
    }
  }
});

elements.refreshButton.addEventListener("click", () => refreshCurrent());
elements.stateFilter.addEventListener("change", () => {
  session.offset = 0;
  refreshCurrent();
});

elements.discoveryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!session.canOperate || session.discoveryLoading) {
    return;
  }
  const campaign = elements.discoveryCampaign.value.trim();
  const runId = elements.discoveryRunId.value.trim();
  if (!/^[a-z0-9][a-z0-9-]{2,79}$/.test(campaign)) {
    announce("Discovery Campaign ID must be canonical lowercase text.", "error");
    elements.discoveryCampaign.focus();
    return;
  }
  if (!/^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$/.test(runId)) {
    announce("Enter one exact generated Hypothesis Run ID.", "error");
    elements.discoveryRunId.focus();
    return;
  }
  const requestId = ++session.discoveryRequestId;
  const authEpoch = session.authEpoch;
  session.discoveryLoading = true;
  setBusy(elements.discoveryForm, true);
  setBusy(elements.discoveryPanel, true);
  elements.discoveryLoadButton.disabled = true;
  clearDiscovery({ message: "Verifying sealed Discovery authorities..." });
  announce("Verifying the sealed Discovery Surface and wave authority...");
  try {
    const path = `/v1/discovery/campaigns/${encodeURIComponent(campaign)}`
      + `/hypothesis-runs/${encodeURIComponent(runId)}`;
    const view = validateDiscoveryView(await apiRequest(path), campaign, runId);
    if (session.discoveryRequestId !== requestId || session.authEpoch !== authEpoch) {
      throw new StaleRequestError();
    }
    renderDiscovery(view);
    announce(
      `Verified ${view.surfaceSet.surfaceCount} Attack Surface(s) across two sealed waves.`,
      "success",
    );
  } catch (error) {
    if (!isStaleRequest(error)
      && session.discoveryRequestId === requestId
      && session.authEpoch === authEpoch) {
      const message = error instanceof Error ? error.message : "Unable to load Discovery view.";
      clearDiscovery({ message: `Discovery view unavailable: ${message}` });
      announce(message, "error");
    }
  } finally {
    if (session.discoveryRequestId === requestId && session.authEpoch === authEpoch) {
      session.discoveryLoading = false;
      setBusy(elements.discoveryForm, false);
      setBusy(elements.discoveryPanel, false);
      elements.discoveryLoadButton.disabled = !session.canOperate;
    }
  }
});
elements.previousPage.addEventListener("click", () => {
  session.offset = Math.max(0, session.offset - PAGE_SIZE);
  refreshCurrent();
});
elements.nextPage.addEventListener("click", () => {
  if (session.offset + session.pageItems < session.total) {
    session.offset += PAGE_SIZE;
    return refreshCurrent();
  }
  return undefined;
});
elements.autoRefresh.addEventListener("change", () => {
  const enabled = elements.autoRefresh.checked;
  stopAutoRefresh();
  if (enabled && session.connected) {
    elements.autoRefresh.checked = true;
    session.refreshTimer = globalThis.setInterval(() => refreshCurrent({ quiet: true }), 5_000);
  }
});

globalThis.addEventListener("pagehide", () => {
  lockConsole(undefined, undefined, { focusToken: false });
});

newIdempotencyKey();
setConnected(false);
clearDiscovery({ clearInputs: true });
updatePagination();
