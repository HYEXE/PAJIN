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
