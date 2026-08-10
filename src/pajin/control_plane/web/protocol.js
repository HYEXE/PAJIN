"use strict";

export const PAGE_SIZE = 25;
export const MAX_RENDERED_EVENTS = 200;

const READ_ROLES = new Set(["operator", "approver", "auditor"]);
const KNOWN_ROLES = new Set([...READ_ROLES, "worker"]);
const RUN_STATES = new Set([
  "queued",
  "running",
  "awaiting-approval",
  "completed",
  "failed",
  "cancelled",
]);
const JOB_STATES = new Set([
  "queued",
  "leased",
  "succeeded",
  "failed",
  "dead-letter",
  "cancelled",
]);
const JOB_KINDS = new Set(["campaign", "tool-loop"]);
const APPROVAL_STATES = new Set([
  "pending",
  "approved",
  "denied",
  "consumed",
  "expired",
  "revoked",
]);
const SURFACE_LOCATOR_KINDS = new Set([
  "http-endpoint",
  "http-route",
  "http-internal-api",
  "http-authentication",
  "http-file-upload",
  "http-rag",
  "http-tenant-retrieval",
  "http-data-response",
  "mcp-server",
  "mcp-resource",
  "mcp-resource-template",
  "mcp-prompt",
  "mcp-tool",
  "mcp-url-tool",
  "tool-interface",
]);
const DISCOVERY_RUN_PATTERN = /^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export class ApiProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = "ApiProtocolError";
  }
}

class LosslessJsonNumber {
  constructor(source) {
    this.source = source;
    Object.freeze(this);
  }
}

export function errorDetail(payload, status) {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = typeof payload.detail === "string"
      ? payload.detail
      : formatJson(payload.detail);
    if (detail) {
      return detail.length > 2_000 ? `${detail.slice(0, 2_000)}…` : detail;
    }
  }
  return `Control Plane request failed with HTTP ${status}.`;
}

export function isJsonMediaType(contentType) {
  const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

export function parseJsonPayload(raw, status) {
  if (raw.length === 0) {
    throw new ApiProtocolError(`Control Plane returned invalid JSON with HTTP ${status}.`);
  }
  try {
    return JSON.parse(raw, (_key, value, context) => {
      if (typeof value !== "number") {
        return value;
      }
      if (Number.isSafeInteger(value)
        && !Object.is(value, -0)
        && (context === undefined
          || (typeof context.source === "string"
            && /^-?(?:0|[1-9][0-9]*)$/.test(context.source)))) {
        return value;
      }
      if (context === undefined
        || typeof context.source !== "string"
        || !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(context.source)) {
        throw new ApiProtocolError(
          "This browser cannot safely decode a lossless Control Plane JSON number.",
        );
      }
      return context.source !== "-0" && /^-?(?:0|[1-9][0-9]*)$/.test(context.source)
        ? BigInt(context.source)
        : new LosslessJsonNumber(context.source);
    });
  } catch (error) {
    if (error instanceof ApiProtocolError) {
      throw error;
    }
    throw new ApiProtocolError(`Control Plane returned invalid JSON with HTTP ${status}.`);
  }
}

export function formatJson(value, depth = 0) {
  if (value instanceof LosslessJsonNumber) {
    return value.source;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : Object.entries(value);
  if (entries.length === 0) {
    return Array.isArray(value) ? "[]" : "{}";
  }
  const padding = "  ".repeat(depth);
  const nestedPadding = "  ".repeat(depth + 1);
  const rendered = entries.map(([key, item]) => {
    const prefix = Array.isArray(value) ? "" : `${JSON.stringify(key)}: `;
    return `${nestedPadding}${prefix}${formatJson(item, depth + 1)}`;
  });
  const [open, close] = Array.isArray(value) ? ["[", "]"] : ["{", "}"];
  return `${open}\n${rendered.join(",\n")}\n${padding}${close}`;
}

export function isRunState(value) {
  return RUN_STATES.has(value);
}

export function protocolFailure(label) {
  throw new ApiProtocolError(`Control Plane returned an invalid ${label} response.`);
}

function expectRecord(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    protocolFailure(label);
  }
  return value;
}

function expectString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    protocolFailure(label);
  }
  return value;
}

function expectTimestamp(value, label) {
  const timestamp = expectString(value, label);
  if (Number.isNaN(new Date(timestamp).getTime())) {
    protocolFailure(label);
  }
  return timestamp;
}

function boundedJsonShape(value, label, depth = 0, budget = { nodes: 0 }) {
  budget.nodes += 1;
  if (budget.nodes > 1_000 || depth > 8) {
    protocolFailure(label);
  }
  if (value instanceof LosslessJsonNumber || typeof value === "bigint") {
    return;
  }
  if (value === null || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      protocolFailure(label);
    }
    return;
  }
  if (typeof value === "string") {
    if (value.length > 2_000) {
      protocolFailure(label);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) {
      protocolFailure(label);
    }
    value.forEach((item) => boundedJsonShape(item, label, depth + 1, budget));
    return;
  }
  const record = expectRecord(value, label);
  const entries = Object.entries(record);
  if (entries.length > 100 || entries.some(([key]) => key.length > 128)) {
    protocolFailure(label);
  }
  entries.forEach(([, item]) => boundedJsonShape(item, label, depth + 1, budget));
}

function boundedNumber(value, label, minimum, maximum) {
  const normalized = value instanceof LosslessJsonNumber ? Number(value.source) : value;
  if (typeof normalized !== "number"
    || !Number.isFinite(normalized)
    || normalized < minimum
    || normalized > maximum) {
    protocolFailure(label);
  }
  return normalized;
}

function validateDiscoveryRun(value, label) {
  const run = expectRecord(value, label);
  if (!DISCOVERY_RUN_PATTERN.test(run.runId)
    || !SHA256_PATTERN.test(run.rootDigest)
    || run.state !== "completed") {
    protocolFailure(label);
  }
  return run;
}

function validateSurface(value, surfaceSetId) {
  const surface = expectRecord(value, "Discovery Surface view");
  const locator = expectRecord(surface.locator, "Discovery Surface view");
  if (typeof surface.surfaceId !== "string"
    || !/^attack-surface_[a-f0-9]{64}$/.test(surface.surfaceId)
    || typeof surface.targetId !== "string"
    || surface.targetId.length === 0
    || surface.targetId.length > 200
    || !SURFACE_LOCATOR_KINDS.has(locator.kind)
    || !Number.isSafeInteger(surface.observationCount)
    || surface.observationCount < 1) {
    protocolFailure("Discovery Surface view");
  }
  boundedJsonShape(locator, "Discovery Surface view");
  surface.confidence = boundedNumber(
    surface.confidence,
    "Discovery Surface view",
    0,
    1,
  );
  const first = expectTimestamp(surface.firstObservedAt, "Discovery Surface view");
  const last = expectTimestamp(surface.lastObservedAt, "Discovery Surface view");
  if (new Date(first).getTime() > new Date(last).getTime()
    || !/^attack-surface-set_[a-f0-9]{64}$/.test(surfaceSetId)) {
    protocolFailure("Discovery Surface view");
  }
  return surface;
}

export function validateDiscoveryView(value, campaignName, hypothesisRunId) {
  const view = expectRecord(value, "Discovery Surface/Wave view");
  if (view.apiVersion
      !== "pajin.control-plane/verified-discovery-surface-wave-view/v1alpha1"
    || view.kind !== "VerifiedDiscoverySurfaceWaveView") {
    protocolFailure("Discovery Surface/Wave view");
  }
  const campaign = expectRecord(view.campaign, "Discovery Surface/Wave view");
  const hypothesisRun = validateDiscoveryRun(
    view.hypothesisRun,
    "Discovery Surface/Wave view",
  );
  const snapshot = expectRecord(view.surfaceSnapshot, "Discovery Surface/Wave view");
  const surfaceSet = expectRecord(view.surfaceSet, "Discovery Surface/Wave view");
  if (campaign.name !== campaignName
    || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(campaign.name)
    || !SHA256_PATTERN.test(campaign.digest)
    || hypothesisRun.runId !== hypothesisRunId
    || !/^surface-snapshot_[a-f0-9]{64}$/.test(snapshot.snapshotId)
    || !SHA256_PATTERN.test(snapshot.snapshotDigest)
    || snapshot.revision !== 1
    || !/^attack-surface-set_[a-f0-9]{64}$/.test(snapshot.surfaceSetId)
    || !DISCOVERY_RUN_PATTERN.test(snapshot.sourceRunId)
    || !SHA256_PATTERN.test(snapshot.sourceRootDigest)
    || !DISCOVERY_RUN_PATTERN.test(snapshot.projectionRunId)
    || !SHA256_PATTERN.test(snapshot.projectionRootDigest)
    || !SHA256_PATTERN.test(snapshot.artifactSha256)
    || surfaceSet.surfaceSetId !== snapshot.surfaceSetId
    || !Array.isArray(surfaceSet.surfaces)
    || surfaceSet.surfaces.length > 500
    || !Number.isSafeInteger(surfaceSet.surfaceCount)
    || surfaceSet.surfaceCount !== surfaceSet.surfaces.length
    || !Number.isSafeInteger(surfaceSet.observationCount)
    || surfaceSet.observationCount < surfaceSet.surfaceCount) {
    protocolFailure("Discovery Surface/Wave view");
  }
  expectTimestamp(surfaceSet.generatedAt, "Discovery Surface/Wave view");
  surfaceSet.surfaces.forEach((surface) => validateSurface(surface, surfaceSet.surfaceSetId));
  const surfaceIds = surfaceSet.surfaces.map((surface) => surface.surfaceId);
  if (new Set(surfaceIds).size !== surfaceIds.length
    || !Array.isArray(view.waves)
    || view.waves.length !== 2) {
    protocolFailure("Discovery Surface/Wave view");
  }
  const [recon, hypothesis] = view.waves.map((wave) => (
    expectRecord(wave, "Discovery Surface/Wave view")
  ));
  if (recon.kind !== "recon"
    || recon.runId !== snapshot.sourceRunId
    || recon.state !== "completed"
    || recon.stopCondition !== "single-wave-complete"
    || recon.taskCount !== 1
    || hypothesis.kind !== "hypothesis"
    || hypothesis.runId !== hypothesisRunId
    || hypothesis.state !== "completed"
    || typeof hypothesis.wavePlanId !== "string"
    || !/^hypothesis-wave-plan_[a-f0-9]{64}$/.test(hypothesis.wavePlanId)
    || hypothesis.stopCondition !== "hypothesis-wave-complete"
    || !Array.isArray(hypothesis.tasks)
    || hypothesis.tasks.length < 1
    || hypothesis.tasks.length > 100
    || hypothesis.taskCount !== hypothesis.tasks.length) {
    protocolFailure("Discovery Surface/Wave view");
  }
  for (const taskValue of hypothesis.tasks) {
    const task = expectRecord(taskValue, "Discovery Surface/Wave view");
    if (!/^attack-hypothesis_[a-f0-9]{64}$/.test(task.hypothesisId)
      || !surfaceIds.includes(task.surfaceId)
      || typeof task.specialistId !== "string"
      || task.specialistId.length === 0
      || typeof task.threatClass !== "string"
      || !/^[DMAS][0-9]+$/.test(task.threatClass)) {
      protocolFailure("Discovery Surface/Wave view");
    }
  }
  if (new Set(hypothesis.tasks.map((task) => task.hypothesisId)).size
      !== hypothesis.tasks.length) {
    protocolFailure("Discovery Surface/Wave view");
  }
  const boundary = expectRecord(view.authorityBoundary, "Discovery Surface/Wave view");
  if (boundary.surfaceSnapshotVerified !== true
    || boundary.canonicalGraphIncluded !== false
    || boundary.viewGrantsCapability !== false
    || boundary.viewGrantsPermit !== false
    || boundary.viewAuthorizesExecution !== false) {
    protocolFailure("Discovery Surface/Wave view");
  }
  return view;
}

export function validatePrincipal(value) {
  const principal = expectRecord(value, "session");
  const subject = expectString(principal.subject, "session");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(subject)
    || !Array.isArray(principal.roles)
    || principal.roles.length === 0
    || principal.roles.some((role) => typeof role !== "string" || !KNOWN_ROLES.has(role))
    || !principal.roles.some((role) => READ_ROLES.has(role))) {
    protocolFailure("session");
  }
  return { subject, roles: [...new Set(principal.roles)] };
}

export function validateRun(value, { detail = false } = {}) {
  const run = expectRecord(value, "Run");
  const runId = expectString(run.run_id, "Run");
  expectString(run.campaign_name, "Run");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(runId)
    || !isRunState(run.state)) {
    protocolFailure("Run");
  }
  if (run.current_checkpoint_id !== null && typeof run.current_checkpoint_id !== "string") {
    protocolFailure("Run");
  }
  expectTimestamp(run.created_at, "Run");
  expectTimestamp(run.updated_at, "Run");
  if (detail) {
    expectRecord(run.input, "Run");
  }
  return run;
}

export function validateRunList(value, expectedOffset) {
  const page = expectRecord(value, "Run list");
  if (!Array.isArray(page.items)
    || !Number.isSafeInteger(page.total)
    || page.total < 0
    || page.total > 0 && expectedOffset >= page.total
      && page.items.length > 0
    || page.total > expectedOffset && page.items.length === 0
    || !Number.isSafeInteger(page.limit)
    || page.limit !== PAGE_SIZE
    || page.offset !== expectedOffset
    || page.items.length > PAGE_SIZE
    || page.items.length > 0 && page.total < expectedOffset + page.items.length) {
    protocolFailure("Run list");
  }
  page.items.forEach((run) => validateRun(run));
  if (new Set(page.items.map((run) => run.run_id)).size !== page.items.length) {
    protocolFailure("Run list");
  }
  return page;
}

export function validateApproval(value, runId) {
  if (value === null) {
    return null;
  }
  const approval = expectRecord(value, "approval");
  expectString(approval.approval_id, "approval");
  if (approval.run_id !== runId
    || !APPROVAL_STATES.has(approval.state)
    || typeof approval.checkpoint_id !== "string"
    || approval.checkpoint_id.length === 0
    || typeof approval.requested_by !== "string"
    || approval.requested_by.length === 0
    || approval.decided_by !== null && typeof approval.decided_by !== "string"
    || approval.decision_reason !== null && typeof approval.decision_reason !== "string"
    || approval.decided_at !== null && (typeof approval.decided_at !== "string"
      || Number.isNaN(new Date(approval.decided_at).getTime()))
    || approval.consumed_by !== null && typeof approval.consumed_by !== "string"
    || approval.consumed_at !== null && (typeof approval.consumed_at !== "string"
      || Number.isNaN(new Date(approval.consumed_at).getTime()))) {
    protocolFailure("approval");
  }
  expectTimestamp(approval.requested_at, "approval");
  const intent = expectRecord(approval.intent, "approval");
  if (typeof intent.call_fingerprint !== "string"
    || !/^[0-9a-f]{64}$/.test(intent.call_fingerprint)) {
    protocolFailure("approval");
  }
  expectString(intent.tool_id, "approval");
  expectString(intent.target, "approval");
  expectTimestamp(intent.expires_at, "approval");
  if (!Number.isInteger(intent.risk_tier) || intent.risk_tier < 3 || intent.risk_tier > 4) {
    protocolFailure("approval");
  }
  return approval;
}

function validateJob(value, runId, { expectedKind = null, requireQueued = false } = {}) {
  const job = expectRecord(value, "Job");
  const jobId = expectString(job.job_id, "Job");
  if (!/^job_[0-9a-f]{32}$/.test(jobId)
    || job.run_id !== runId
    || !JOB_KINDS.has(job.kind)
    || expectedKind !== null && job.kind !== expectedKind
    || !JOB_STATES.has(job.state)
    || requireQueued && job.state !== "queued"
    || !Number.isSafeInteger(job.priority)
    || !Number.isSafeInteger(job.attempts)
    || job.attempts < 0
    || !Number.isSafeInteger(job.max_attempts)
    || job.max_attempts < 1
    || job.attempts > job.max_attempts
    || job.lease_owner !== null && typeof job.lease_owner !== "string"
    || job.lease_expires_at !== null && (typeof job.lease_expires_at !== "string"
      || Number.isNaN(new Date(job.lease_expires_at).getTime()))
    || job.heartbeat_at !== null && (typeof job.heartbeat_at !== "string"
      || Number.isNaN(new Date(job.heartbeat_at).getTime()))
    || job.result !== null && (Array.isArray(job.result)
      || typeof job.result !== "object")
    || job.error !== null && typeof job.error !== "string") {
    protocolFailure("Job");
  }
  expectRecord(job.payload, "Job");
  expectTimestamp(job.available_at, "Job");
  expectTimestamp(job.created_at, "Job");
  expectTimestamp(job.updated_at, "Job");
  return job;
}

export function validateEvents(value, runId, before = null) {
  if (!Array.isArray(value) || value.length > MAX_RENDERED_EVENTS) {
    protocolFailure("event list");
  }
  let previousSequence = 0;
  for (const valueEvent of value) {
    const event = expectRecord(valueEvent, "event list");
    if (event.run_id !== runId
      || !Number.isSafeInteger(event.sequence)
      || event.sequence <= previousSequence
      || before !== null && event.sequence >= before) {
      protocolFailure("event list");
    }
    expectString(event.event_type, "event list");
    expectString(event.actor, "event list");
    expectTimestamp(event.occurred_at, "event list");
    expectRecord(event.payload, "event list");
    previousSequence = event.sequence;
  }
  return value;
}

export function validateApprovalDecision(value, runId, approvalId, approve) {
  const approval = validateApproval(value, runId);
  if (approval === null
    || approval.approval_id !== approvalId
    || approval.state !== (approve ? "approved" : "denied")) {
    protocolFailure("approval decision");
  }
  return approval;
}

export function validateResume(value, runId, checkpointId, approvalId) {
  const resumed = expectRecord(value, "checkpoint resume");
  const run = validateRun(resumed.run, { detail: true });
  const job = validateJob(resumed.job, runId, { requireQueued: true });
  const checkpoint = expectRecord(resumed.checkpoint, "checkpoint resume");
  const approval = validateApproval(resumed.approval, runId);
  if (run.run_id !== runId
    || run.state !== "queued"
    || checkpoint.checkpoint_id !== checkpointId
    || checkpoint.run_id !== runId
    || typeof checkpoint.claimed_at !== "string"
    || Number.isNaN(new Date(checkpoint.claimed_at).getTime())
    || typeof checkpoint.claimed_by !== "string"
    || checkpoint.claimed_by.length === 0
    || checkpoint.continuation_job_id !== job.job_id
    || approval === null
    || approval.approval_id !== approvalId
    || approval.state !== "consumed") {
    protocolFailure("checkpoint resume");
  }
  return resumed;
}

export function validateCancellation(value, runId) {
  const cancellation = expectRecord(value, "Run cancellation");
  const run = validateRun(cancellation.run, { detail: true });
  if (run.run_id !== runId
    || run.state !== "cancelled"
    || typeof cancellation.applied !== "boolean"
    || !Array.isArray(cancellation.cancelled_job_ids)
    || cancellation.cancelled_job_ids.some((valueId) => typeof valueId !== "string")
    || !Array.isArray(cancellation.revoked_approval_ids)
    || cancellation.revoked_approval_ids.some((valueId) => typeof valueId !== "string")) {
    protocolFailure("Run cancellation");
  }
  return cancellation;
}

export function validateSubmission(value, { campaignName, jobKind }) {
  const submission = expectRecord(value, "Run submission");
  const run = validateRun(submission.run, { detail: true });
  const job = validateJob(submission.job, run.run_id, { expectedKind: jobKind });
  if (typeof submission.created !== "boolean"
    || run.campaign_name !== campaignName
    || submission.created && (run.state !== "queued" || job.state !== "queued")) {
    protocolFailure("Run submission");
  }
  return submission;
}

export function runSubmissionBody({ campaignName, rawInput, idempotencyKey, maxAttempts, jobKind }) {
  return `{${[
    `"campaign_name":${JSON.stringify(campaignName)}`,
    `"input":${rawInput}`,
    `"idempotency_key":${JSON.stringify(idempotencyKey)}`,
    `"max_attempts":${maxAttempts}`,
    `"job_kind":${JSON.stringify(jobKind)}`,
  ].join(",")}}`;
}
