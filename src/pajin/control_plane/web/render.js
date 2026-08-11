"use strict";

import { formatJson } from "./protocol.js";

export function formatTime(value) {
  if (!value) {
    return "—";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

export function shortId(value) {
  return value.length > 22 ? `${value.slice(0, 13)}…${value.slice(-6)}` : value;
}

function stateBadge(documentRef, value) {
  const badge = documentRef.createElement("span");
  badge.className = `state-badge state-${value}`;
  badge.textContent = value;
  return badge;
}

function textCell(documentRef, value, className = "") {
  const cell = documentRef.createElement("td");
  cell.textContent = value;
  if (className) {
    cell.className = className;
  }
  return cell;
}

export function createRunRows(documentRef, items, selectedRunId, selectRun) {
  if (items.length === 0) {
    const row = documentRef.createElement("tr");
    const cell = documentRef.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-cell";
    cell.textContent = "No Runs match this filter.";
    row.append(cell);
    return [row];
  }

  return items.map((run) => {
    const row = documentRef.createElement("tr");
    row.classList.toggle("selected", run.run_id === selectedRunId);

    const campaignCell = documentRef.createElement("td");
    const runName = documentRef.createElement("span");
    runName.className = "run-name";
    const campaign = documentRef.createElement("strong");
    campaign.textContent = run.campaign_name;
    const identifier = documentRef.createElement("code");
    identifier.textContent = shortId(run.run_id);
    identifier.title = run.run_id;
    runName.append(campaign, identifier);
    campaignCell.append(runName);

    const stateCell = documentRef.createElement("td");
    stateCell.append(stateBadge(documentRef, run.state));

    const actionCell = documentRef.createElement("td");
    const open = documentRef.createElement("button");
    open.type = "button";
    open.className = "button button-quiet open-run";
    open.textContent = "Inspect";
    open.setAttribute("aria-label", `Inspect ${run.campaign_name}`);
    if (run.run_id === selectedRunId) {
      open.setAttribute("aria-current", "true");
    }
    open.addEventListener("click", () => selectRun(run.run_id));
    actionCell.append(open);

    row.append(
      campaignCell,
      stateCell,
      textCell(documentRef, formatTime(run.updated_at)),
      actionCell,
    );
    return row;
  });
}

export function createHumanReviewQueueNodes(documentRef, items, selectRun) {
  if (items.length === 0) {
    const empty = documentRef.createElement("li");
    empty.className = "review-queue-card empty-review-queue";
    empty.textContent = "No active Runs currently require human workflow attention.";
    return [empty];
  }
  return items.map((item) => {
    const node = documentRef.createElement("li");
    node.className = "review-queue-card";

    const heading = documentRef.createElement("div");
    heading.className = "review-queue-card-head";
    const campaign = documentRef.createElement("strong");
    campaign.textContent = item.campaign_name;
    const attention = documentRef.createElement("span");
    attention.className = `review-attention attention-${item.attention}`;
    attention.textContent = item.attention;
    heading.append(campaign, attention);

    const lifecycle = documentRef.createElement("p");
    lifecycle.className = "review-queue-lifecycle";
    lifecycle.textContent = [
      item.run_state,
      `Run ${shortId(item.run_id)}`,
      `updated ${formatTime(item.updated_at)}`,
    ].join(" / ");
    node.append(heading, lifecycle);

    if (item.approval !== null) {
      const approval = documentRef.createElement("p");
      approval.className = "review-queue-approval";
      approval.textContent = [
        `${item.approval.tool_id} -> ${item.approval.target}`,
        `T${item.approval.risk_tier}`,
        `${item.approval.state} until ${formatTime(item.approval.expires_at)}`,
      ].join(" / ");
      node.append(approval);
    }

    const actions = documentRef.createElement("div");
    actions.className = "review-queue-card-actions";
    const boundary = documentRef.createElement("span");
    boundary.textContent = "Kill switch candidate / authority checked on action";
    const inspect = documentRef.createElement("button");
    inspect.type = "button";
    inspect.className = "button button-quiet";
    inspect.textContent = "Inspect controls";
    inspect.setAttribute("aria-label", `Inspect controls for ${item.campaign_name}`);
    inspect.addEventListener("click", () => selectRun(item.run_id));
    actions.append(boundary, inspect);
    node.append(actions);
    return node;
  });
}

export function eventCountLabel(events) {
  if (events.length === 0) {
    return "0 events";
  }
  const noun = events.length === 1 ? "event" : "events";
  return `#${events[0].sequence}–#${events.at(-1).sequence} · ${events.length} ${noun}`;
}

export function createEventNodes(documentRef, events) {
  if (events.length === 0) {
    const empty = documentRef.createElement("li");
    empty.className = "empty-event";
    empty.textContent = "No events recorded.";
    return [empty];
  }

  return events.map((event) => {
    const item = documentRef.createElement("li");
    item.className = "event-item";
    const heading = documentRef.createElement("div");
    heading.className = "event-title";
    const title = documentRef.createElement("strong");
    title.textContent = event.event_type;
    const sequence = documentRef.createElement("span");
    sequence.className = "event-sequence";
    sequence.textContent = `#${event.sequence}`;
    heading.append(title, sequence);
    const meta = documentRef.createElement("div");
    meta.className = "event-meta";
    meta.textContent = `${formatTime(event.occurred_at)} · ${event.actor}`;
    const payload = documentRef.createElement("pre");
    payload.textContent = formatJson(event.payload);
    item.append(heading, meta, payload);
    return item;
  });
}

function locatorLabel(locator) {
  if (locator.kind === "tool-interface") {
    return `${locator.registry_id} / ${locator.tool_id}@${locator.tool_version}`;
  }
  if (locator.kind === "http-endpoint") {
    return `${locator.method} ${locator.url}`;
  }
  if (locator.kind === "http-route") {
    return `${locator.method} ${locator.base_url}${locator.path_template}`;
  }
  if (locator.route && typeof locator.route === "object") {
    return locatorLabel(locator.route);
  }
  if (locator.kind === "mcp-server") {
    return `${locator.server_id} / MCP ${locator.protocol_version}`;
  }
  if (typeof locator.server_id === "string") {
    const member = locator.tool_name || locator.prompt_name || locator.uri_scheme || locator.kind;
    return `${locator.server_id} / ${member}`;
  }
  return locator.kind;
}

export function createSurfaceNodes(documentRef, surfaces) {
  return surfaces.map((surface) => {
    const item = documentRef.createElement("li");
    item.className = "surface-card";
    const heading = documentRef.createElement("div");
    heading.className = "surface-card-head";
    const title = documentRef.createElement("strong");
    title.textContent = surface.targetId;
    const kind = documentRef.createElement("span");
    kind.className = "surface-kind";
    kind.textContent = surface.locator.kind;
    heading.append(title, kind);
    const locator = documentRef.createElement("p");
    locator.className = "surface-locator";
    locator.textContent = locatorLabel(surface.locator);
    const metadata = documentRef.createElement("p");
    metadata.className = "surface-meta";
    metadata.textContent = [
      shortId(surface.surfaceId),
      `${surface.observationCount} observation(s)`,
      `${Math.round(surface.confidence * 100)}% confidence`,
      `last ${formatTime(surface.lastObservedAt)}`,
    ].join(" / ");
    item.append(heading, locator, metadata);
    return item;
  });
}

export function createWaveNodes(documentRef, waves) {
  return waves.map((wave) => {
    const item = documentRef.createElement("li");
    item.className = "wave-card";
    const heading = documentRef.createElement("div");
    heading.className = "wave-card-head";
    const title = documentRef.createElement("strong");
    title.textContent = wave.kind === "recon" ? "Recon wave" : "Hypothesis wave";
    const state = documentRef.createElement("span");
    state.className = "state-badge state-completed";
    state.textContent = wave.state;
    heading.append(title, state);
    const metadata = documentRef.createElement("p");
    metadata.className = "wave-meta";
    metadata.textContent = [shortId(wave.runId), wave.stopCondition, `${wave.taskCount} task(s)`]
      .join(" / ");
    item.append(heading, metadata);
    if (wave.kind === "hypothesis") {
      const tasks = documentRef.createElement("ol");
      tasks.className = "wave-task-list";
      for (const task of wave.tasks) {
        const taskItem = documentRef.createElement("li");
        taskItem.className = "wave-task";
        taskItem.textContent = [
          task.threatClass,
          shortId(task.hypothesisId),
          shortId(task.surfaceId),
          task.specialistId,
        ].join(" / ");
        tasks.append(taskItem);
      }
      item.append(tasks);
    }
    return item;
  });
}

function emptyGraphItem(documentRef, text, className) {
  const item = documentRef.createElement("li");
  item.className = className;
  item.textContent = text;
  return [item];
}

export function createGraphNodeNodes(documentRef, nodes) {
  if (nodes.length === 0) {
    return emptyGraphItem(documentRef, "This current Snapshot has no admitted nodes.", "graph-node-card");
  }
  return nodes.map((node) => {
    const item = documentRef.createElement("li");
    item.className = "graph-node-card";
    const heading = documentRef.createElement("div");
    heading.className = "graph-node-card-head";
    const title = documentRef.createElement("strong");
    title.textContent = node.displayKey;
    const kind = documentRef.createElement("span");
    kind.className = "graph-node-kind";
    kind.textContent = node.kind;
    heading.append(title, kind);
    const value = documentRef.createElement("p");
    value.className = "graph-node-value";
    value.textContent = node.displayValue || "Redacted canonical member";
    const metadata = documentRef.createElement("p");
    metadata.className = "graph-node-meta";
    const parts = [shortId(node.nodeId)];
    if (node.origin) parts.push(node.origin);
    if (node.state) parts.push(node.state);
    if (node.confidence !== null) parts.push(`${Math.round(node.confidence * 100)}% confidence`);
    if (node.occurredAt) parts.push(formatTime(node.occurredAt));
    metadata.textContent = parts.join(" / ");
    item.append(heading, value, metadata);
    return item;
  });
}

export function createGraphEdgeNodes(documentRef, edges) {
  if (edges.length === 0) {
    return emptyGraphItem(
      documentRef,
      "This current Snapshot has no admitted relationships.",
      "graph-edge-card",
    );
  }
  return edges.map((edge) => {
    const item = documentRef.createElement("li");
    item.className = "graph-edge-card";
    const relation = documentRef.createElement("strong");
    relation.textContent = edge.relation;
    const endpoints = documentRef.createElement("p");
    endpoints.className = "graph-edge-endpoints";
    endpoints.textContent = [
      `${edge.source.kind} ${shortId(edge.source.nodeId)}`,
      "->",
      `${edge.target.kind} ${shortId(edge.target.nodeId)}`,
    ].join(" ");
    const authority = documentRef.createElement("p");
    authority.className = "graph-edge-authority";
    authority.textContent = `${shortId(edge.edgeId)} / ${edge.authorityId}`;
    item.append(relation, endpoints, authority);
    return item;
  });
}

export function createHypothesisAttentionNodes(documentRef, hypotheses) {
  if (hypotheses.length === 0) {
    return emptyGraphItem(
      documentRef,
      "This current Snapshot has no canonical Hypotheses to rank.",
      "hypothesis-ranking-card",
    );
  }
  return hypotheses.map((hypothesis) => {
    const item = documentRef.createElement("li");
    item.className = "hypothesis-ranking-card";

    const rank = documentRef.createElement("span");
    rank.className = "hypothesis-ranking-rank";
    rank.textContent = String(hypothesis.rank).padStart(2, "0");

    const content = documentRef.createElement("div");
    content.className = "hypothesis-ranking-content";
    const heading = documentRef.createElement("div");
    heading.className = "hypothesis-ranking-card-head";
    const title = documentRef.createElement("strong");
    title.textContent = hypothesis.hypothesisType;
    const state = stateBadge(documentRef, hypothesis.state);
    heading.append(title, state);

    const band = documentRef.createElement("p");
    band.className = "hypothesis-ranking-band";
    band.textContent = hypothesis.attentionBand;
    const metadata = documentRef.createElement("p");
    metadata.className = "hypothesis-ranking-meta";
    metadata.textContent = [
      hypothesis.producerId,
      hypothesis.origin,
      `${Math.round(hypothesis.confidence * 100)}% producer confidence`,
    ].join(" / ");
    const evidence = documentRef.createElement("p");
    evidence.className = "hypothesis-ranking-evidence";
    evidence.textContent = [
      `${hypothesis.supportingObservationCount} supporting observation(s)`,
      `${hypothesis.contradictingObservationCount} contradicting observation(s)`,
      shortId(hypothesis.nodeId),
    ].join(" / ");
    content.append(heading, band, metadata, evidence);
    item.append(rank, content);
    return item;
  });
}

export function createDecisionAuditNodes(documentRef, decisions) {
  if (decisions.length === 0) {
    return emptyGraphItem(
      documentRef,
      "No complete Decisions were recorded for this current Snapshot.",
      "decision-audit-card",
    );
  }
  return decisions.map((decision) => {
    const item = documentRef.createElement("li");
    item.className = "decision-audit-card";

    const sequence = documentRef.createElement("span");
    sequence.className = "decision-audit-sequence";
    sequence.textContent = `#${decision.sequence}`;

    const content = documentRef.createElement("div");
    content.className = "decision-audit-content";
    const heading = documentRef.createElement("div");
    heading.className = "decision-audit-card-head";
    const title = documentRef.createElement("strong");
    title.textContent = decision.decisionKind;
    const recorded = documentRef.createElement("span");
    recorded.className = "decision-audit-time";
    recorded.textContent = formatTime(decision.recordedAt);
    heading.append(title, recorded);

    const identities = documentRef.createElement("p");
    identities.className = "decision-audit-identities";
    identities.textContent = [
      `Decision ${shortId(decision.decisionId)}`,
      `Record ${shortId(decision.recordId)}`,
    ].join(" / ");
    const digests = documentRef.createElement("p");
    digests.className = "decision-audit-digests";
    digests.textContent = [
      `payload ${shortId(decision.decisionPayloadDigest)}`,
      `actor ${shortId(decision.actorDigest)}`,
      `recorder ${shortId(decision.recorderDigest)}`,
    ].join(" / ");
    const created = documentRef.createElement("p");
    created.className = "decision-audit-created";
    created.textContent = `Decision created ${formatTime(decision.decisionCreatedAt)}`;
    content.append(heading, identities, digests, created);
    item.append(sequence, content);
    return item;
  });
}

export function createReplayComparisonLaneNodes(documentRef, lanes) {
  return lanes.map((lane) => {
    const item = documentRef.createElement("li");
    item.className = "replay-comparison-card";
    if (lane.availability !== "verified-reference") {
      item.classList.add("is-unavailable");
    }

    const heading = documentRef.createElement("div");
    heading.className = "replay-comparison-card-head";
    const stage = documentRef.createElement("strong");
    stage.textContent = lane.stage;
    const availability = documentRef.createElement("span");
    availability.className = "replay-comparison-availability";
    availability.textContent = lane.availability;
    heading.append(stage, availability);

    const role = documentRef.createElement("p");
    role.className = "replay-comparison-role";
    role.textContent = lane.authorityRole;
    const coordinateSummary = documentRef.createElement("p");
    coordinateSummary.className = "replay-comparison-coordinates";
    if (lane.executionCount === 0) {
      coordinateSummary.textContent = "No coordinates in this authority";
      item.append(heading, role, coordinateSummary);
      return item;
    }

    coordinateSummary.textContent = `${lane.executionCount} execution coordinate(s)`;
    const coordinates = documentRef.createElement("ol");
    coordinates.className = "validation-coordinate-list";
    for (let index = 0; index < lane.executionCount; index += 1) {
      const coordinate = documentRef.createElement("li");
      coordinate.className = "validation-coordinate";
      const coordinateLabel = documentRef.createElement("strong");
      coordinateLabel.textContent = `Execution ${index + 1}`;
      const identity = documentRef.createElement("span");
      identity.textContent = [
        `Run ${shortId(lane.runIds[index])}`,
        `root ${shortId(lane.rootDigests[index])}`,
        `evidence ${shortId(lane.evidenceDigests[index])}`,
      ].join(" / ");
      coordinate.append(coordinateLabel, identity);
      coordinates.append(coordinate);
    }
    item.append(heading, role, coordinateSummary, coordinates);
    return item;
  });
}

export function createWalkingControlComparisonLaneNodes(documentRef, lanes) {
  return lanes.map((lane) => {
    const item = documentRef.createElement("li");
    item.className = "replay-comparison-card";
    if (lane.availability !== "verified-reference") {
      item.classList.add("is-unavailable");
    }

    const heading = documentRef.createElement("div");
    heading.className = "replay-comparison-card-head";
    const stage = documentRef.createElement("strong");
    stage.textContent = lane.stage;
    const availability = documentRef.createElement("span");
    availability.className = "replay-comparison-availability";
    availability.textContent = lane.availability;
    heading.append(stage, availability);

    const role = documentRef.createElement("p");
    role.className = "replay-comparison-role";
    role.textContent = lane.authorityRole;
    item.append(heading, role);

    if (lane.coordinates.length === 0) {
      const unavailable = documentRef.createElement("p");
      unavailable.className = "replay-comparison-coordinates";
      unavailable.textContent = "No Retest coordinate in this authority";
      item.append(unavailable);
      return item;
    }

    const coordinates = documentRef.createElement("ol");
    coordinates.className = "validation-coordinate-list";
    for (const coordinate of lane.coordinates) {
      const coordinateItem = documentRef.createElement("li");
      coordinateItem.className = "validation-coordinate";
      const coordinateRole = documentRef.createElement("strong");
      coordinateRole.textContent = coordinate.controlKind
        ? `${coordinate.role} / ${coordinate.controlKind}`
        : coordinate.role;
      const identity = documentRef.createElement("span");
      identity.textContent = [
        `#${coordinate.ordinal}`,
        `Run ${shortId(coordinate.runId)}`,
        `root ${shortId(coordinate.rootDigest)}`,
        `execution ${shortId(coordinate.executionDigest)}`,
      ].join(" / ");
      coordinateItem.append(coordinateRole, identity);
      coordinates.append(coordinateItem);
    }
    item.append(coordinates);
    return item;
  });
}
