"use strict";

export const PAGE_SIZE = 25;
export const MAX_RENDERED_EVENTS = 200;
export const REVIEW_QUEUE_LIMIT = 50;

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
const REVIEW_ATTENTION_PRIORITY = new Map([
  ["approval-expired", 0],
  ["approval-required", 1],
  ["resume-required", 2],
  ["execution-active", 3],
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
const GRAPH_SNAPSHOT_PATTERN = /^graph-snapshot_[a-f0-9]{64}$/;
const GRAPH_PROJECTION_PATTERN = /^graph-projection_[a-f0-9]{64}$/;
const GRAPH_CONSISTENCY_VIEW_PATTERN = /^graph-consistency-view_[a-f0-9]{64}$/;
const GRAPH_DECISION_PATTERN = /^graph-decision_[a-f0-9]{64}$/;
const GRAPH_DECISION_AUDIT_RECORD_PATTERN = (
  /^graph-decision-audit-record_[a-f0-9]{64}$/
);
const REPLAY_BATCH_PATTERN = /^replay-batch_[a-f0-9]{32}$/;
const REPLAY_PROJECTION_PATTERN = /^replay-projection_[a-f0-9]{32}$/;
const REPLAY_RUN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const WALKING_CONTROL_COMPARISON_PATTERN = (
  /^walking-control-comparison_[a-f0-9]{64}$/
);
const WALKING_EXECUTION_RUN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const GRAPH_NODE_PATTERN = /^graph-node_[a-f0-9]{64}$/;
const GRAPH_EDGE_PATTERN = /^graph-edge_[a-f0-9]{64}$/;
const GRAPH_NODE_KINDS = new Set([
  "Surface",
  "Hypothesis",
  "Action",
  "Observation",
  "Evidence",
  "CampaignFact",
]);
const GRAPH_ORIGINS = new Set(["trusted-core", "operator", "agent-derived", "target-derived"]);
const HYPOTHESIS_STATE_PRIORITY = new Map([
  ["contested", 0],
  ["supported", 1],
  ["open", 2],
  ["contradicted", 3],
]);
const HYPOTHESIS_ATTENTION_BANDS = new Map([
  ["contested", "conflict-review"],
  ["supported", "evidence-supported"],
  ["open", "evidence-needed"],
  ["contradicted", "contradicted-review"],
]);
const GRAPH_DECISION_KINDS = new Set([
  "plan",
  "task-assignment",
  "replan",
  "action-proposal",
  "stop",
]);
const GRAPH_RELATION_ENDPOINTS = new Map([
  ["motivates", ["Surface", "Hypothesis"]],
  ["tested-by", ["Hypothesis", "Action"]],
  ["produces", ["Action", "Observation"]],
  ["supported-by", ["Observation", "Evidence"]],
  ["supports", ["Observation", "Hypothesis"]],
  ["contradicts", ["Observation", "Hypothesis"]],
  ["discovers", ["Observation", "Surface"]],
  ["enables", ["Observation", "Hypothesis"]],
]);

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

function boundedDisplayString(value, label, maximum, { nullable = false } = {}) {
  if (nullable && value === null) {
    return null;
  }
  if (typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) {
    protocolFailure(label);
  }
  return value;
}

function validateGraphNode(value) {
  const node = expectRecord(value, "Canonical Graph view");
  if (!GRAPH_NODE_PATTERN.test(node.nodeId)
    || !GRAPH_NODE_KINDS.has(node.kind)) {
    protocolFailure("Canonical Graph view");
  }
  boundedDisplayString(node.displayKey, "Canonical Graph view", 200);
  boundedDisplayString(node.displayValue, "Canonical Graph view", 200, { nullable: true });
  if (node.origin !== null && !GRAPH_ORIGINS.has(node.origin)) {
    protocolFailure("Canonical Graph view");
  }
  boundedDisplayString(node.state, "Canonical Graph view", 100, { nullable: true });
  if (node.confidence !== null) {
    node.confidence = boundedNumber(node.confidence, "Canonical Graph view", 0, 1);
  }
  if (node.occurredAt !== null) {
    expectTimestamp(node.occurredAt, "Canonical Graph view");
  }
  return node;
}

function validateGraphEndpoint(value, nodes) {
  const endpoint = expectRecord(value, "Canonical Graph view");
  const node = nodes.get(endpoint.nodeId);
  if (!GRAPH_NODE_PATTERN.test(endpoint.nodeId)
    || !GRAPH_NODE_KINDS.has(endpoint.kind)
    || node === undefined
    || node.kind !== endpoint.kind) {
    protocolFailure("Canonical Graph view");
  }
  return endpoint;
}

export function validateCanonicalGraphView(value, campaignName, snapshotId) {
  const view = expectRecord(value, "Canonical Graph view");
  if (view.apiVersion !== "pajin.control-plane/verified-canonical-graph-view/v1alpha1"
    || view.kind !== "VerifiedCanonicalGraphView"
    || view.campaignId !== campaignName
    || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(view.campaignId)) {
    protocolFailure("Canonical Graph view");
  }
  const snapshot = expectRecord(view.snapshot, "Canonical Graph view");
  const projection = expectRecord(view.projection, "Canonical Graph view");
  if (snapshot.snapshotId !== snapshotId
    || !GRAPH_SNAPSHOT_PATTERN.test(snapshot.snapshotId)
    || !SHA256_PATTERN.test(snapshot.snapshotDigest)
    || (snapshot.previousSnapshotDigest !== null
      && !SHA256_PATTERN.test(snapshot.previousSnapshotDigest))
    || !new Set(["checkpoint", "handoff", "replan", "recovery"]).has(snapshot.reason)
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(snapshot.creatorId)
    || !SHA256_PATTERN.test(snapshot.creatorDigest)
    || projection.graphSchemaVersion !== "pajin.dev/canonical-graph/v1alpha1"
    || !Number.isSafeInteger(projection.revision)
    || projection.revision < 0
    || (projection.revision === 0) !== (projection.eventLogHeadDigest === null)
    || (projection.eventLogHeadDigest !== null
      && !SHA256_PATTERN.test(projection.eventLogHeadDigest))
    || !GRAPH_PROJECTION_PATTERN.test(projection.projectionId)
    || !SHA256_PATTERN.test(projection.projectionDigest)
    || !SHA256_PATTERN.test(projection.nodeProjectionDigest)
    || !SHA256_PATTERN.test(projection.edgeProjectionDigest)) {
    protocolFailure("Canonical Graph view");
  }
  expectTimestamp(snapshot.createdAt, "Canonical Graph view");
  if (!Array.isArray(view.nodes)
    || view.nodes.length > 500
    || !Array.isArray(view.edges)
    || view.edges.length > 1_000
    || !Number.isSafeInteger(view.nodeCount)
    || view.nodeCount !== view.nodes.length
    || !Number.isSafeInteger(view.edgeCount)
    || view.edgeCount !== view.edges.length) {
    protocolFailure("Canonical Graph view");
  }
  const nodes = new Map();
  for (const nodeValue of view.nodes) {
    const node = validateGraphNode(nodeValue);
    if (nodes.has(node.nodeId)) {
      protocolFailure("Canonical Graph view");
    }
    nodes.set(node.nodeId, node);
  }
  const edgeIds = new Set();
  for (const edgeValue of view.edges) {
    const edge = expectRecord(edgeValue, "Canonical Graph view");
    const expectedKinds = GRAPH_RELATION_ENDPOINTS.get(edge.relation);
    const source = validateGraphEndpoint(edge.source, nodes);
    const target = validateGraphEndpoint(edge.target, nodes);
    if (!GRAPH_EDGE_PATTERN.test(edge.edgeId)
      || edgeIds.has(edge.edgeId)
      || expectedKinds === undefined
      || source.kind !== expectedKinds[0]
      || target.kind !== expectedKinds[1]
      || source.nodeId === target.nodeId
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(edge.authorityId)
      || !SHA256_PATTERN.test(edge.authorityDigest)) {
      protocolFailure("Canonical Graph view");
    }
    edgeIds.add(edge.edgeId);
  }
  const boundary = expectRecord(view.authorityBoundary, "Canonical Graph view");
  if (boundary.canonicalGraphSnapshotVerified !== true
    || boundary.currentSnapshotVerified !== true
    || boundary.contentRedacted !== true
    || boundary.viewAuthorizesAdmission !== false
    || boundary.viewGrantsCapability !== false
    || boundary.viewGrantsPermit !== false
    || boundary.viewAuthorizesExecution !== false) {
    protocolFailure("Canonical Graph view");
  }
  return view;
}

export function validateHypothesisAttentionRanking(value, campaignName, snapshotId) {
  const view = expectRecord(value, "Hypothesis attention ranking");
  if (view.apiVersion
      !== "pajin.control-plane/verified-hypothesis-attention-ranking-view/v1alpha1"
    || view.kind !== "VerifiedHypothesisAttentionRankingView"
    || view.campaignId !== campaignName
    || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(view.campaignId)
    || view.snapshotId !== snapshotId
    || !GRAPH_SNAPSHOT_PATTERN.test(view.snapshotId)
    || !SHA256_PATTERN.test(view.snapshotDigest)
    || view.snapshotId !== `graph-snapshot_${view.snapshotDigest}`
    || !GRAPH_PROJECTION_PATTERN.test(view.projectionId)
    || !SHA256_PATTERN.test(view.projectionDigest)
    || view.projectionId !== `graph-projection_${view.projectionDigest}`
    || !GRAPH_CONSISTENCY_VIEW_PATTERN.test(view.consistencyViewId)
    || !SHA256_PATTERN.test(view.consistencyViewDigest)
    || view.consistencyViewId
      !== `graph-consistency-view_${view.consistencyViewDigest}`
    || view.rankingMethod !== "canonical-state-confidence-review-attention/v1"
    || !Number.isSafeInteger(view.hypothesisCount)
    || view.hypothesisCount < 0
    || view.hypothesisCount > 500
    || !Array.isArray(view.hypotheses)
    || view.hypotheses.length !== view.hypothesisCount) {
    protocolFailure("Hypothesis attention ranking");
  }

  const nodeIds = new Set();
  let previous = null;
  for (const [index, hypothesisValue] of view.hypotheses.entries()) {
    const hypothesis = expectRecord(hypothesisValue, "Hypothesis attention ranking");
    const priority = HYPOTHESIS_STATE_PRIORITY.get(hypothesis.state);
    const expectedBand = HYPOTHESIS_ATTENTION_BANDS.get(hypothesis.state);
    if (hypothesis.rank !== index + 1
      || !GRAPH_NODE_PATTERN.test(hypothesis.nodeId)
      || nodeIds.has(hypothesis.nodeId)
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(hypothesis.hypothesisType)
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(hypothesis.producerId)
      || !GRAPH_ORIGINS.has(hypothesis.origin)
      || priority === undefined
      || hypothesis.attentionBand !== expectedBand
      || !Number.isSafeInteger(hypothesis.supportingObservationCount)
      || hypothesis.supportingObservationCount < 0
      || !Number.isSafeInteger(hypothesis.contradictingObservationCount)
      || hypothesis.contradictingObservationCount < 0) {
      protocolFailure("Hypothesis attention ranking");
    }
    hypothesis.confidence = boundedNumber(
      hypothesis.confidence,
      "Hypothesis attention ranking",
      0,
      1,
    );
    const supports = hypothesis.supportingObservationCount;
    const contradictions = hypothesis.contradictingObservationCount;
    if ((hypothesis.state === "contested" && (supports === 0 || contradictions === 0))
      || (hypothesis.state === "supported" && (supports === 0 || contradictions !== 0))
      || (hypothesis.state === "open" && (supports !== 0 || contradictions !== 0))
      || (hypothesis.state === "contradicted" && (supports !== 0 || contradictions === 0))) {
      protocolFailure("Hypothesis attention ranking");
    }
    if (previous !== null
      && (priority < previous.priority
        || (priority === previous.priority
          && hypothesis.confidence > previous.confidence)
        || (priority === previous.priority
          && hypothesis.confidence === previous.confidence
          && hypothesis.nodeId <= previous.nodeId))) {
      protocolFailure("Hypothesis attention ranking");
    }
    nodeIds.add(hypothesis.nodeId);
    previous = { priority, confidence: hypothesis.confidence, nodeId: hypothesis.nodeId };
  }

  const boundary = expectRecord(view.authorityBoundary, "Hypothesis attention ranking");
  if (boundary.canonicalGraphSnapshotVerified !== true
    || boundary.currentSnapshotVerified !== true
    || boundary.consistencyViewVerified !== true
    || boundary.deterministicReviewOrder !== true
    || boundary.contentRedacted !== true
    || boundary.viewSelectsHypothesis !== false
    || boundary.viewRecordsDecision !== false
    || boundary.viewSchedulesWork !== false
    || boundary.viewAuthorizesExecution !== false) {
    protocolFailure("Hypothesis attention ranking");
  }
  return view;
}

export function validateGraphDecisionAuditView(value, campaignName, snapshotId) {
  const view = expectRecord(value, "Graph Decision audit view");
  if (view.apiVersion
      !== "pajin.control-plane/verified-graph-decision-audit-view/v1alpha1"
    || view.kind !== "VerifiedGraphDecisionAuditView"
    || view.campaignId !== campaignName
    || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(view.campaignId)
    || view.snapshotId !== snapshotId
    || !GRAPH_SNAPSHOT_PATTERN.test(view.snapshotId)
    || !SHA256_PATTERN.test(view.snapshotDigest)
    || view.snapshotId !== `graph-snapshot_${view.snapshotDigest}`
    || !GRAPH_PROJECTION_PATTERN.test(view.projectionId)
    || !SHA256_PATTERN.test(view.projectionDigest)
    || view.projectionId !== `graph-projection_${view.projectionDigest}`
    || view.auditSchemaVersion !== 1
    || !SHA256_PATTERN.test(view.auditSchemaDigest)
    || !SHA256_PATTERN.test(view.recorderDigest)
    || !Number.isSafeInteger(view.totalRecordCount)
    || view.totalRecordCount < 0
    || !Number.isSafeInteger(view.currentSnapshotDecisionCount)
    || view.currentSnapshotDecisionCount < 0
    || view.currentSnapshotDecisionCount > 500
    || view.currentSnapshotDecisionCount > view.totalRecordCount
    || (view.totalRecordCount === 0) !== (view.auditHeadDigest === null)
    || (view.auditHeadDigest !== null && !SHA256_PATTERN.test(view.auditHeadDigest))
    || !Array.isArray(view.decisions)
    || view.decisions.length !== view.currentSnapshotDecisionCount
    || Object.hasOwn(view, "recorderId")) {
    protocolFailure("Graph Decision audit view");
  }

  const sequences = new Set();
  const recordIds = new Set();
  const decisionIds = new Set();
  let previousSequence = 0;
  for (const decisionValue of view.decisions) {
    const decision = expectRecord(decisionValue, "Graph Decision audit view");
    if (!Number.isSafeInteger(decision.sequence)
      || decision.sequence < 1
      || decision.sequence > view.totalRecordCount
      || decision.sequence <= previousSequence
      || sequences.has(decision.sequence)
      || !GRAPH_DECISION_AUDIT_RECORD_PATTERN.test(decision.recordId)
      || !SHA256_PATTERN.test(decision.recordDigest)
      || decision.recordId !== `graph-decision-audit-record_${decision.recordDigest}`
      || recordIds.has(decision.recordId)
      || (decision.sequence === 1) !== (decision.previousRecordDigest === null)
      || (decision.previousRecordDigest !== null
        && !SHA256_PATTERN.test(decision.previousRecordDigest))
      || !GRAPH_DECISION_PATTERN.test(decision.decisionId)
      || !SHA256_PATTERN.test(decision.decisionDigest)
      || decision.decisionId !== `graph-decision_${decision.decisionDigest}`
      || decisionIds.has(decision.decisionId)
      || !GRAPH_DECISION_KINDS.has(decision.decisionKind)
      || !SHA256_PATTERN.test(decision.decisionPayloadDigest)
      || !SHA256_PATTERN.test(decision.actorDigest)
      || decision.recorderDigest !== view.recorderDigest
      || Object.hasOwn(decision, "actorId")
      || Object.hasOwn(decision, "recorderId")
      || Object.hasOwn(decision, "payload")) {
      protocolFailure("Graph Decision audit view");
    }
    expectTimestamp(decision.decisionCreatedAt, "Graph Decision audit view");
    expectTimestamp(decision.recordedAt, "Graph Decision audit view");
    if (new Date(decision.recordedAt).getTime()
      < new Date(decision.decisionCreatedAt).getTime()) {
      protocolFailure("Graph Decision audit view");
    }
    sequences.add(decision.sequence);
    recordIds.add(decision.recordId);
    decisionIds.add(decision.decisionId);
    previousSequence = decision.sequence;
  }
  if (view.decisions.length > 0
    && view.decisions.at(-1).recordDigest !== view.auditHeadDigest) {
    protocolFailure("Graph Decision audit view");
  }

  const boundary = expectRecord(view.authorityBoundary, "Graph Decision audit view");
  if (boundary.canonicalGraphSnapshotVerified !== true
    || boundary.currentSnapshotVerified !== true
    || boundary.completeAuditChainVerified !== true
    || boundary.historicalSnapshotBindingsVerified !== true
    || boundary.appendOnlyHistoricalRetention !== true
    || boundary.identifiersRedacted !== true
    || boundary.viewSelectsHypothesis !== false
    || boundary.viewRecordsDecision !== false
    || boundary.viewSchedulesWork !== false
    || boundary.viewApprovesAction !== false
    || boundary.viewGrantsCapability !== false
    || boundary.viewGrantsPermit !== false
    || boundary.viewAuthorizesExecution !== false) {
    protocolFailure("Graph Decision audit view");
  }
  return view;
}

export function validateReplayEvidenceComparison(value, batchId) {
  const view = expectRecord(value, "Replay evidence comparison");
  if (view.apiVersion
      !== "pajin.control-plane/verified-replay-evidence-comparison-view/v1alpha1"
    || view.kind !== "VerifiedReplayEvidenceComparisonView"
    || view.batchId !== batchId
    || !REPLAY_BATCH_PATTERN.test(view.batchId)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(view.campaignName)
    || !new Set(["confirmation", "remediation-retest"]).has(view.purpose)
    || !REPLAY_PROJECTION_PATTERN.test(view.projectionId)
    || !SHA256_PATTERN.test(view.inputAuthorityDigest)
    || !SHA256_PATTERN.test(view.projectionArtifactDigest)
    || view.comparisonMode !== "exact-coordinates-no-semantic-diff"
    || !Array.isArray(view.lanes)
    || view.lanes.length !== 4
    || Object.hasOwn(view, "publishedBy")
    || Object.hasOwn(view, "createdBy")) {
    protocolFailure("Replay evidence comparison");
  }

  const expectedStages = ["original", "replay", "control", "retest"];
  const expectedRoles = view.purpose === "remediation-retest"
    ? [
      "remediation-baseline",
      "sealed-remediation-replay",
      "controls-not-bound",
      "sealed-retest-parent-and-assessment",
    ]
    : [
      "original-source",
      "sealed-confirmation-replay",
      "controls-not-bound",
      "retest-not-applicable",
    ];
  const expectedAvailability = view.purpose === "remediation-retest"
    ? ["verified-reference", "verified-reference", "not-in-authority", "verified-reference"]
    : ["verified-reference", "verified-reference", "not-in-authority", "not-applicable"];
  const allRunIds = new Set();
  const allRootDigests = new Set();
  for (const [index, laneValue] of view.lanes.entries()) {
    const lane = expectRecord(laneValue, "Replay evidence comparison");
    const available = lane.availability === "verified-reference";
    if (lane.stage !== expectedStages[index]
      || lane.authorityRole !== expectedRoles[index]
      || lane.availability !== expectedAvailability[index]
      || !Number.isSafeInteger(lane.executionCount)
      || lane.executionCount < 0
      || lane.executionCount > 1_000
      || !Array.isArray(lane.runIds)
      || !Array.isArray(lane.rootDigests)
      || !Array.isArray(lane.evidenceDigests)
      || lane.runIds.length !== lane.executionCount
      || lane.rootDigests.length !== lane.executionCount
      || lane.evidenceDigests.length !== lane.executionCount
      || available !== (lane.executionCount > 0)
      || lane.runIds.some((runId) => !REPLAY_RUN_PATTERN.test(runId))
      || lane.rootDigests.some((digest) => !SHA256_PATTERN.test(digest))
      || lane.evidenceDigests.some((digest) => !SHA256_PATTERN.test(digest))
      || new Set(lane.runIds).size !== lane.runIds.length
      || new Set(lane.rootDigests).size !== lane.rootDigests.length
      || new Set(lane.evidenceDigests).size !== lane.evidenceDigests.length
      || Object.hasOwn(lane, "artifactId")
      || Object.hasOwn(lane, "candidateId")
      || Object.hasOwn(lane, "claim")
      || Object.hasOwn(lane, "content")
      || Object.hasOwn(lane, "path")) {
      protocolFailure("Replay evidence comparison");
    }
    for (const runId of lane.runIds) {
      if (allRunIds.has(runId)) protocolFailure("Replay evidence comparison");
      allRunIds.add(runId);
    }
    for (const digest of lane.rootDigests) {
      if (allRootDigests.has(digest)) protocolFailure("Replay evidence comparison");
      allRootDigests.add(digest);
    }
  }

  const boundary = expectRecord(view.authorityBoundary, "Replay evidence comparison");
  if (boundary.durableProjectionBindingVerified !== true
    || boundary.exactLineageCoordinatesVerified !== true
    || boundary.identifiersAndContentRedacted !== true
    || boundary.controlEvidenceIncluded !== false
    || boundary.semanticEvidenceCompared !== false
    || boundary.viewEvaluatesValidation !== false
    || boundary.viewAttestsRemediation !== false
    || boundary.viewConfirmsFinding !== false
    || boundary.viewAuthorizesExecution !== false) {
    protocolFailure("Replay evidence comparison");
  }
  return view;
}

function hasExactKeys(record, expected) {
  const keys = Object.keys(record).sort();
  const canonical = [...expected].sort();
  return keys.length === canonical.length
    && keys.every((key, index) => key === canonical[index]);
}

function exactProductRecord(value, label, keys) {
  const record = expectRecord(value, label);
  if (!hasExactKeys(record, keys)) {
    protocolFailure(label);
  }
  return record;
}

function validateProductDigestRef(value, label, idKey, idPattern, digestKey) {
  const reference = exactProductRecord(value, label, [idKey, digestKey]);
  if (!idPattern.test(reference[idKey]) || !SHA256_PATTERN.test(reference[digestKey])) {
    protocolFailure(label);
  }
  return reference;
}

function sameProductRef(left, right, idKey, digestKey) {
  return left[idKey] === right[idKey] && left[digestKey] === right[digestKey];
}

function validateProductInteger(value, label, minimum) {
  let normalized;
  if (value instanceof LosslessJsonNumber) {
    if (!/^(0|[1-9][0-9]*)$/.test(value.source)) protocolFailure(label);
    normalized = BigInt(value.source);
  } else if (typeof value === "bigint") {
    normalized = value;
  } else if (Number.isSafeInteger(value) && !Object.is(value, -0)) {
    normalized = BigInt(value);
  } else {
    protocolFailure(label);
  }
  if (normalized < BigInt(minimum) || normalized > 9_223_372_036_854_775_807n) {
    protocolFailure(label);
  }
  return normalized;
}

export function validateWebMeasuredProductProjection(value) {
  const label = "Measured Web product";
  boundedJsonShape(value, label);
  const view = exactProductRecord(value, label, [
    "apiVersion", "kind", "flowId", "flowDigest", "sourceRunId",
    "sourceAuthorityId", "sourceAuthorityDigest", "scope", "evidence", "floor",
    "finding", "report", "authorityBoundary",
  ]);
  if (view.apiVersion !== "pajin.dev/web-measured-product-flow-projection/v1alpha1"
    || view.kind !== "WebMeasuredProductFlowProjection"
    || !/^web-measured-product-flow:[a-f0-9]{64}$/.test(view.flowId)
    || !SHA256_PATTERN.test(view.flowDigest)
    || view.flowId !== `web-measured-product-flow:${view.flowDigest}`
    || !/^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$/.test(view.sourceRunId)
    || !/^web-controlled-validation:[a-f0-9]{64}$/.test(view.sourceAuthorityId)
    || !SHA256_PATTERN.test(view.sourceAuthorityDigest)
    || view.sourceAuthorityId !== `web-controlled-validation:${view.sourceAuthorityDigest}`) {
    protocolFailure(label);
  }

  const scope = exactProductRecord(view.scope, label, [
    "measuredCase", "sourceMeasurement", "scopeState", "campaignScopeAvailable",
    "scopeExpanded", "profileInferred",
  ]);
  const measuredCase = validateProductDigestRef(
    scope.measuredCase,
    label,
    "authorityId",
    /^web-measured-case_[a-f0-9]{64}$/,
    "authorityDigest",
  );
  const sourceMeasurement = validateProductDigestRef(
    scope.sourceMeasurement,
    label,
    "authorityId",
    /^web-zap-source-measurement:[a-f0-9]{64}$/,
    "authorityDigest",
  );
  if (measuredCase.authorityId !== `web-measured-case_${measuredCase.authorityDigest}`
    || sourceMeasurement.authorityId
      !== `web-zap-source-measurement:${sourceMeasurement.authorityDigest}`
    || scope.scopeState !== "measured-case-bounded-campaign-scope-unavailable"
    || scope.campaignScopeAvailable !== false
    || scope.scopeExpanded !== false
    || scope.profileInferred !== false) {
    protocolFailure(label);
  }

  const evidence = exactProductRecord(view.evidence, label, [
    "floorEvaluation", "finding", "denialControlObservationId",
    "denialControlObservationDigest", "sourceEvidenceRequirementCount",
    "controlledValidationEvidenceRequirementCount", "evidenceState",
    "denialControlSatisfied", "targetCleanupVerified", "evidenceContentIncluded",
    "filesystemCoordinatesIncluded",
  ]);
  const evidenceEvaluation = validateProductDigestRef(
    evidence.floorEvaluation,
    label,
    "evaluationId",
    /^web-validation-floor-evaluation_[a-f0-9]{64}$/,
    "evaluationDigest",
  );
  const evidenceFinding = validateProductDigestRef(
    evidence.finding,
    label,
    "findingId",
    /^web-benchmark-finding_[a-f0-9]{64}$/,
    "findingDigest",
  );
  if (evidence.floorEvaluation.evaluationId
      !== `web-validation-floor-evaluation_${evidence.floorEvaluation.evaluationDigest}`
    || evidence.finding.findingId
      !== `web-benchmark-finding_${evidence.finding.findingDigest}`
    || !/^web-observed-policy-denial:[a-f0-9]{64}$/.test(
      evidence.denialControlObservationId,
    )
    || !SHA256_PATTERN.test(evidence.denialControlObservationDigest)
    || evidence.denialControlObservationId
      !== `web-observed-policy-denial:${evidence.denialControlObservationDigest}`
    || evidence.sourceEvidenceRequirementCount !== 6
    || evidence.controlledValidationEvidenceRequirementCount !== 10
    || evidence.evidenceState !== "content-free-authority-references-verified"
    || evidence.denialControlSatisfied !== true
    || evidence.targetCleanupVerified !== true
    || evidence.evidenceContentIncluded !== false
    || evidence.filesystemCoordinatesIncluded !== false) {
    protocolFailure(label);
  }

  const floor = exactProductRecord(view.floor, label, [
    "floorPolicy", "projectionPolicy", "evaluation", "metrics", "publicMetricCount",
    "requiredMetricCount", "notApplicableMetricCount", "floorState",
    "denialControlSatisfied", "targetCleanupVerified", "benchmarkValidationFloorSatisfied",
  ]);
  const floorPolicy = exactProductRecord(floor.floorPolicy, label, [
    "policyId", "policyVersion", "policyDigest",
  ]);
  const floorProjectionPolicy = validateProductDigestRef(
    floor.projectionPolicy,
    label,
    "projectionId",
    /^web-benchmark-finding_[a-f0-9]{64}$/,
    "projectionDigest",
  );
  const floorEvaluation = validateProductDigestRef(
    floor.evaluation,
    label,
    "evaluationId",
    /^web-validation-floor-evaluation_[a-f0-9]{64}$/,
    "evaluationDigest",
  );
  if (floorPolicy.policyId !== "web-002a:p0-d1-validation-floor"
    || floorPolicy.policyVersion !== "1.0.0"
    || !SHA256_PATTERN.test(floorPolicy.policyDigest)
    || floorProjectionPolicy.projectionId
      !== `web-benchmark-finding_${floorProjectionPolicy.projectionDigest}`
    || floorEvaluation.evaluationId
      !== `web-validation-floor-evaluation_${floorEvaluation.evaluationDigest}`
    || !Array.isArray(floor.metrics)
    || floor.metrics.length !== 14
    || floor.publicMetricCount !== 14
    || floor.requiredMetricCount !== 11
    || floor.notApplicableMetricCount !== 3
    || floor.floorState !== "satisfied-independent-controlled-validation"
    || floor.denialControlSatisfied !== true
    || floor.targetCleanupVerified !== true
    || floor.benchmarkValidationFloorSatisfied !== true) {
    protocolFailure(label);
  }

  const metricIds = new Set();
  let requiredMetricCount = 0;
  let notApplicableMetricCount = 0;
  const expectedMetrics = [
    [
      "common.ground-truth-coverage",
      "1eee24d549cdeff887511583969e2cd4562d18e7d87b3a3d70329560780a4185",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.detection-recall",
      "97b6046f00a70bd353f7ad4c274c37a9e0780bd125bdaaafa902767d33fa9f87",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.task-success-rate",
      "5e92974a3b37e0589f2375b830d03a2f7302291943b6719bb5e723cc053554f3",
      "ratio", "not-applicable", "not-applicable",
      "detection-recall-is-primary-outcome", "common",
    ],
    [
      "common.false-positive-rate",
      "c780b515030aa6bb0a1c092965622f17581e99a13d2ab791758bd47f16d1e49c",
      "ratio", "required", "at-most", null, "common",
    ],
    [
      "common.detection-precision",
      "f526b0ab93f59adb99ee24c93783ef0ec960850b5217d0aa2969386c686b7f89",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.replay-or-reanalysis-success-rate",
      "22c5fba7eabafdc50ac5d578fe2fe4af2a290351adcc29e1e7dd10fafa668bb3",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.time-to-first-valid-result",
      "a0f32aca21af1cd7379775e466dfcccdefa4fe88d0391c879fceadd3c68c5039",
      "seconds", "required", "measurement-required-no-quality-threshold", null, "common",
    ],
    [
      "common.total-request-units",
      "07648da173a70528396bafa9c0afd7adedad20424d0a0c7bdb28890ac80ef79a",
      "count", "required", "measurement-required-no-quality-threshold", null, "common",
    ],
    [
      "common.total-tool-calls",
      "7e4ff3993110b201a9f812cba0d738a2301e34af332b0dd564e9432b805610d3",
      "count", "required", "measurement-required-no-quality-threshold", null, "common",
    ],
    [
      "common.total-cost-usd",
      "d0a8ee68983e2e876449be2364823742bff3dc18f4e5010c16c72f5e73952917",
      "usd", "not-applicable", "not-applicable", "no-monetary-cost-model", "common",
    ],
    [
      "common.evidence-completeness",
      "afea19a584fe1d769ba73aedf2aac0403bf65daa79fc9252de3fee1f935379dc",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.policy-denial-correctness",
      "d4fde6367f319e007a1671bf45460b1a62861a8545bf77e196e2d310d8aa6cbd",
      "ratio", "required", "at-least", null, "common",
    ],
    [
      "common.cleanup-success-rate",
      "963bdacfe4228e78f70519ee7c350ac2a1c1f636b84977c085b19841dea35ffd",
      "ratio", "not-applicable", "not-applicable", "read-only-no-cleanup-required", "common",
    ],
    [
      "web.http-operation-coverage",
      "bf9df605bbe9138ec764e0410f75f0e0219174b0718580e3907b9aac4ba3c257",
      "ratio", "required", "at-least", null, "domain-specific",
    ],
  ];
  const fixedMetricRationals = new Map([
    ["common.ground-truth-coverage", [1n, 1n]],
    ["common.detection-recall", [1n, 1n]],
    ["common.false-positive-rate", [0n, 1n]],
    ["common.detection-precision", [1n, 1n]],
    ["common.replay-or-reanalysis-success-rate", [1n, 1n]],
    ["common.evidence-completeness", [16n, 16n]],
    ["common.policy-denial-correctness", [1n, 1n]],
    ["web.http-operation-coverage", [1n, 1n]],
  ]);
  for (const [index, metricValue] of floor.metrics.entries()) {
    const [
      expectedId,
      expectedDigest,
      expectedUnit,
      expectedApplicability,
      expectedComparison,
      expectedReason,
      expectedCategory,
    ] = expectedMetrics[index];
    const metricObservation = exactProductRecord(metricValue, label, [
      "metric", "unit", "applicability", "comparison", "numerator", "denominator",
      "notApplicableReason", "satisfied",
    ]);
    const metric = exactProductRecord(metricObservation.metric, label, [
      "metricId", "metricVersion", "metricDigest", "category", "domainClassification",
    ]);
    if (metric.metricId !== expectedId
      || metric.metricVersion !== "1.0.0"
      || metric.metricDigest !== expectedDigest
      || metric.category !== expectedCategory
      || metricIds.has(metric.metricId)
      || metricObservation.unit !== expectedUnit
      || metricObservation.applicability !== expectedApplicability
      || metricObservation.comparison !== expectedComparison
      || metricObservation.notApplicableReason !== expectedReason
      || metricObservation.satisfied !== true) {
      protocolFailure(label);
    }
    metricIds.add(metric.metricId);
    if (metric.category === "common") {
      if (metric.domainClassification !== null) protocolFailure(label);
    } else if (metric.category === "domain-specific") {
      const domain = exactProductRecord(metric.domainClassification, label, [
        "classificationId", "classificationVersion", "classificationDigest", "domain",
      ]);
      if (domain.classificationId !== "pajin.security-domain.web"
        || domain.classificationVersion !== "1.0.0"
        || domain.classificationDigest
          !== "6e38cf99e549ba35287f9b259b9470d2a59bbc93d5a3b9f47599bd83ca8c5081"
        || domain.domain !== "web") {
        protocolFailure(label);
      }
    } else {
      protocolFailure(label);
    }
    if (metricObservation.applicability === "required") {
      const numerator = validateProductInteger(metricObservation.numerator, label, 0);
      const denominator = validateProductInteger(metricObservation.denominator, label, 1);
      if (metricObservation.comparison === "not-applicable") {
        protocolFailure(label);
      }
      const fixedRational = fixedMetricRationals.get(metric.metricId);
      if (fixedRational !== undefined
        && (numerator !== fixedRational[0] || denominator !== fixedRational[1])) {
        protocolFailure(label);
      }
      if (metric.metricId === "common.time-to-first-valid-result"
        && denominator !== 1_000_000n) {
        protocolFailure(label);
      }
      if (metric.metricId === "common.total-request-units"
        && (numerator < 4n || denominator !== 1n)) {
        protocolFailure(label);
      }
      if (metric.metricId === "common.total-tool-calls"
        && (numerator < 2n || denominator !== 1n)) {
        protocolFailure(label);
      }
      requiredMetricCount += 1;
    } else if (metricObservation.applicability === "not-applicable") {
      if (metricObservation.comparison !== "not-applicable"
        || metricObservation.numerator !== null
        || metricObservation.denominator !== null
        || metricObservation.notApplicableReason === null) {
        protocolFailure(label);
      }
      notApplicableMetricCount += 1;
    } else {
      protocolFailure(label);
    }
  }
  if (requiredMetricCount !== 11 || notApplicableMetricCount !== 3) {
    protocolFailure(label);
  }

  const finding = exactProductRecord(view.finding, label, [
    "finding", "evaluation", "projectionPolicy", "sourceMeasurement", "claimCeiling",
    "findingState", "impactAssurance", "severityAssurance",
    "benchmarkGroundTruthMatchConfirmed", "productFindingConfirmed",
    "genericProductionVulnerabilityConfirmed", "negativeSecurityConclusionAuthorized",
  ]);
  const findingRef = validateProductDigestRef(
    finding.finding,
    label,
    "findingId",
    /^web-benchmark-finding_[a-f0-9]{64}$/,
    "findingDigest",
  );
  const findingEvaluation = validateProductDigestRef(
    finding.evaluation,
    label,
    "evaluationId",
    /^web-validation-floor-evaluation_[a-f0-9]{64}$/,
    "evaluationDigest",
  );
  const findingProjectionPolicy = validateProductDigestRef(
    finding.projectionPolicy,
    label,
    "projectionId",
    /^web-benchmark-finding_[a-f0-9]{64}$/,
    "projectionDigest",
  );
  const findingSource = validateProductDigestRef(
    finding.sourceMeasurement,
    label,
    "authorityId",
    /^web-zap-source-measurement:[a-f0-9]{64}$/,
    "authorityDigest",
  );
  if (findingRef.findingId !== `web-benchmark-finding_${findingRef.findingDigest}`
    || findingEvaluation.evaluationId
      !== `web-validation-floor-evaluation_${findingEvaluation.evaluationDigest}`
    || findingProjectionPolicy.projectionId
      !== `web-benchmark-finding_${findingProjectionPolicy.projectionDigest}`
    || findingSource.authorityId
      !== `web-zap-source-measurement:${findingSource.authorityDigest}`
    || finding.claimCeiling !== "benchmark-ground-truth-match"
    || finding.findingState
      !== "confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated"
    || finding.impactAssurance !== "not-evaluated-information-only"
    || finding.severityAssurance !== "not-evaluated-information-only"
    || finding.benchmarkGroundTruthMatchConfirmed !== true
    || finding.productFindingConfirmed !== true
    || finding.genericProductionVulnerabilityConfirmed !== false
    || finding.negativeSecurityConclusionAuthorized !== false
    || !sameProductRef(sourceMeasurement, findingSource, "authorityId", "authorityDigest")
    || !sameProductRef(evidenceEvaluation, floorEvaluation, "evaluationId", "evaluationDigest")
    || !sameProductRef(evidenceEvaluation, findingEvaluation, "evaluationId", "evaluationDigest")
    || !sameProductRef(evidenceFinding, findingRef, "findingId", "findingDigest")
    || !sameProductRef(
      floorProjectionPolicy,
      findingProjectionPolicy,
      "projectionId",
      "projectionDigest",
    )) {
    protocolFailure(label);
  }

  const report = exactProductRecord(view.report, label, [
    "reportState", "reportAvailable", "reportCreationAuthorized",
    "reportDeliveryAuthorized", "externalDeliveryAuthorized",
  ]);
  if (report.reportState !== "unavailable-bounded-finding-not-report-authority"
    || report.reportAvailable !== false
    || report.reportCreationAuthorized !== false
    || report.reportDeliveryAuthorized !== false
    || report.externalDeliveryAuthorized !== false) {
    protocolFailure(label);
  }

  const boundaryTrue = [
    "sourceAuthorityContextuallyVerified", "readOnlyProjection", "evidenceContentRedacted",
  ];
  const boundaryFalse = [
    "web002cGraphPredecessorRequired", "campaignScopeAvailable", "scopeExpanded",
    "profileInferred", "privateGroundTruthDisclosed", "expectedReferenceDisclosed",
    "rawSarifDisclosed", "controlledQueryDisclosed", "responseBodyDisclosed",
    "transcriptDisclosed", "rawEvidenceDisclosed", "routeDetailsDisclosed",
    "filesystemCoordinatesDisclosed", "graphIncluded", "graphMutationAuthorized",
    "reportCreationAuthorized", "reportDeliveryAuthorized", "externalDeliveryAuthorized",
    "capabilityActivationAuthorized", "permitIssuanceAuthorized", "routeReuseAuthorized",
    "additionalExecutionAuthorized", "targetSideEffectPerformed", "providerSideEffectPerformed",
    "dockerSideEffectPerformed", "workerSideEffectPerformed", "networkSideEffectPerformed",
    "credentialSideEffectPerformed", "externalSystemSideEffectPerformed",
    "httpEntrypointAvailable", "uiEntrypointAvailable",
  ];
  const boundary = exactProductRecord(
    view.authorityBoundary,
    label,
    [...boundaryTrue, ...boundaryFalse],
  );
  if (boundaryTrue.some((key) => boundary[key] !== true)
    || boundaryFalse.some((key) => boundary[key] !== false)) {
    protocolFailure(label);
  }
  return view;
}

export function validateWalkingControlComparison(value, comparisonId) {
  const label = "Walking Control comparison";
  const view = expectRecord(value, label);
  if (view.apiVersion
      !== "pajin.control-plane/verified-walking-control-comparison-view/v1alpha1"
    || view.kind !== "VerifiedWalkingControlComparisonView"
    || view.comparisonId !== comparisonId
    || !WALKING_CONTROL_COMPARISON_PATTERN.test(view.comparisonId)
    || view.comparisonDigest !== view.comparisonId.slice(-64)
    || !SHA256_PATTERN.test(view.comparisonDigest)
    || !SHA256_PATTERN.test(view.assessmentDigest)
    || !SHA256_PATTERN.test(view.campaignDigest)
    || !SHA256_PATTERN.test(view.claimDigest)
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(view.profileId)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$/.test(view.profileVersion)
    || view.achievedDepth !== "repeated-controlled-validity-replay"
    || view.validationState !== "profile-floor-satisfied-not-confirmed"
    || view.controlContrast !== "contrast-observed"
    || view.comparisonMode
      !== "exact-execution-coordinates-with-verified-control-contrast"
    || !Array.isArray(view.lanes)
    || view.lanes.length !== 4
    || !hasExactKeys(view, [
      "apiVersion", "kind", "comparisonId", "comparisonDigest", "assessmentDigest",
      "campaignDigest", "claimDigest", "profileId", "profileVersion", "achievedDepth",
      "validationState", "controlContrast", "comparisonMode", "lanes", "authorityBoundary",
    ])) {
    protocolFailure(label);
  }

  const expectedStages = ["original", "replay", "control", "retest"];
  const expectedAvailability = [
    "verified-reference", "verified-reference", "verified-reference", "not-in-authority",
  ];
  const expectedRoles = [
    "sealed-source-execution",
    "sealed-repeated-validity-replay",
    "sealed-baseline-negative-counterfactual",
    "retest-not-bound",
  ];
  const expectedCounts = [1, 2, 3, 0];
  const coordinateRoles = [
    "original-source",
    "primary-replay",
    "additional-replay",
    "baseline-control",
    "negative-control",
    "counterfactual-control",
  ];
  const controlKinds = [null, null, null, "baseline", "negative-control", "counterfactual"];
  const runIds = new Set();
  const rootDigests = new Set();
  const executionDigests = new Set();
  let ordinal = 0;
  for (const [laneIndex, laneValue] of view.lanes.entries()) {
    const lane = expectRecord(laneValue, label);
    if (lane.stage !== expectedStages[laneIndex]
      || lane.availability !== expectedAvailability[laneIndex]
      || lane.authorityRole !== expectedRoles[laneIndex]
      || lane.executionCount !== expectedCounts[laneIndex]
      || !Array.isArray(lane.coordinates)
      || lane.coordinates.length !== lane.executionCount
      || !hasExactKeys(lane, [
        "stage", "availability", "authorityRole", "executionCount", "coordinates",
      ])) {
      protocolFailure(label);
    }
    for (const coordinateValue of lane.coordinates) {
      const coordinate = expectRecord(coordinateValue, label);
      if (coordinate.ordinal !== ordinal
        || coordinate.role !== coordinateRoles[ordinal]
        || coordinate.controlKind !== controlKinds[ordinal]
        || !WALKING_EXECUTION_RUN_PATTERN.test(coordinate.runId)
        || !SHA256_PATTERN.test(coordinate.rootDigest)
        || !SHA256_PATTERN.test(coordinate.executionDigest)
        || runIds.has(coordinate.runId)
        || rootDigests.has(coordinate.rootDigest)
        || executionDigests.has(coordinate.executionDigest)
        || !hasExactKeys(coordinate, [
          "ordinal", "role", "controlKind", "runId", "rootDigest", "executionDigest",
        ])) {
        protocolFailure(label);
      }
      runIds.add(coordinate.runId);
      rootDigests.add(coordinate.rootDigest);
      executionDigests.add(coordinate.executionDigest);
      ordinal += 1;
    }
  }
  if (ordinal !== 6) protocolFailure(label);

  const boundary = expectRecord(view.authorityBoundary, label);
  if (boundary.val004cSealedPredecessorsVerified !== true
    || boundary.exactExecutionLineageVerified !== true
    || boundary.controlContrastVerified !== true
    || boundary.identifiersAndContentRedacted !== true
    || boundary.retestEvidenceIncluded !== false
    || boundary.viewCreatesValidationAssessment !== false
    || boundary.viewAttestsProfileSelection !== false
    || boundary.viewAttestsRemediation !== false
    || boundary.viewConfirmsFinding !== false
    || boundary.viewAuthorizesExecution !== false
    || !hasExactKeys(boundary, [
      "val004cSealedPredecessorsVerified", "exactExecutionLineageVerified",
      "controlContrastVerified", "identifiersAndContentRedacted", "retestEvidenceIncluded",
      "viewCreatesValidationAssessment", "viewAttestsProfileSelection",
      "viewAttestsRemediation", "viewConfirmsFinding", "viewAuthorizesExecution",
    ])) {
    protocolFailure(label);
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

export function validateHumanReviewQueue(value) {
  const label = "Human Review queue";
  const queue = expectRecord(value, label);
  if (queue.api_version !== "pajin.control-plane.human-review-queue/v1"
    || !hasExactKeys(queue, [
      "api_version", "generated_at", "items", "limit", "has_more", "authority",
    ])
    || queue.limit !== REVIEW_QUEUE_LIMIT
    || typeof queue.has_more !== "boolean"
    || !Array.isArray(queue.items)
    || queue.items.length > REVIEW_QUEUE_LIMIT) {
    protocolFailure(label);
  }
  const generatedAt = new Date(expectTimestamp(queue.generated_at, label)).getTime();
  let previousPriority = -1;
  const runIds = new Set();
  for (const rawItem of queue.items) {
    const item = expectRecord(rawItem, label);
    if (!hasExactKeys(item, [
      "run_id", "campaign_name", "run_state", "updated_at", "checkpoint_id",
      "attention", "approval", "kill_switch_candidate",
    ])) {
      protocolFailure(label);
    }
    const runId = expectString(item.run_id, label);
    expectString(item.campaign_name, label);
    expectTimestamp(item.updated_at, label);
    const priority = REVIEW_ATTENTION_PRIORITY.get(item.attention);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(runId)
      || runIds.has(runId)
      || priority === undefined
      || priority < previousPriority
      || item.kill_switch_candidate !== true) {
      protocolFailure(label);
    }
    runIds.add(runId);
    previousPriority = priority;

    if (item.attention === "execution-active") {
      if (!["queued", "running"].includes(item.run_state)
        || item.checkpoint_id !== null
        || item.approval !== null) {
        protocolFailure(label);
      }
      continue;
    }
    const approval = expectRecord(item.approval, label);
    if (item.run_state !== "awaiting-approval"
      || typeof item.checkpoint_id !== "string"
      || item.checkpoint_id.length === 0
      || !hasExactKeys(approval, [
        "approval_id", "state", "requested_by", "requested_at", "tool_id", "target",
        "risk_tier", "expires_at",
      ])
      || !/^approval_[0-9a-f]{32}$/.test(expectString(approval.approval_id, label))
      || !["pending", "approved"].includes(approval.state)
      || !Number.isInteger(approval.risk_tier)
      || approval.risk_tier < 3
      || approval.risk_tier > 4) {
      protocolFailure(label);
    }
    expectString(approval.requested_by, label);
    expectTimestamp(approval.requested_at, label);
    expectString(approval.tool_id, label);
    expectString(approval.target, label);
    const expiresAt = new Date(expectTimestamp(approval.expires_at, label)).getTime();
    const expired = expiresAt <= generatedAt;
    if (item.attention === "approval-expired") {
      if (!expired) protocolFailure(label);
    } else if (item.attention === "approval-required") {
      if (expired || approval.state !== "pending") protocolFailure(label);
    } else if (item.attention === "resume-required"
      && (expired || approval.state !== "approved")) {
      protocolFailure(label);
    }
  }
  const authority = expectRecord(queue.authority, label);
  if (!hasExactKeys(authority, [
    "queue_snapshot_only", "approval_decision_authority", "checkpoint_resume_authority",
    "cancellation_authority", "execution_authority",
  ])
    || authority.queue_snapshot_only !== true
    || authority.approval_decision_authority !== false
    || authority.checkpoint_resume_authority !== false
    || authority.cancellation_authority !== false
    || authority.execution_authority !== false) {
    protocolFailure(label);
  }
  return queue;
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
