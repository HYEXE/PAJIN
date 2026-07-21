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
