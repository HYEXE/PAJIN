import { validateHistoricalGraphPage } from "./protocol.js";
import { createGraphNodeNodes, createGraphEdgeNodes } from "./render.js";

const BASE = "/v1/graph-browser/campaigns";
const CAMPAIGN = /^[a-z0-9][a-z0-9-]{2,79}$/;
const SNAPSHOT = /^graph-snapshot_[a-f0-9]{64}$/;
const DIGEST = /^[a-f0-9]{64}$/;

export function validateHistoryCatalog(value, campaign, previous = null) {
  if (!value || value.apiVersion !== "pajin.control-plane/graph-history-catalog/v1"
    || value.campaignId !== campaign || !DIGEST.test(value.stateDigest)
    || value.historicalReadOnly !== true || !Number.isSafeInteger(value.total) || value.total < 0
    || !Number.isSafeInteger(value.offset) || value.offset < 0 || value.offset % 25
    || value.limit !== 25 || value.offset >= Math.max(1, value.total)
    || !Array.isArray(value.items) || value.items.length !== Math.min(25, value.total - value.offset)
    || (value.currentSnapshotId !== null && !SNAPSHOT.test(value.currentSnapshotId))
    || ((value.offset + 25 < value.total)
      ? typeof value.nextCursor !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(value.nextCursor)
      : value.nextCursor !== null)
    || (previous && (value.stateDigest !== previous.stateDigest || value.offset !== previous.offset + 25))) {
    throw new Error("The history catalog changed or does not match this Campaign. Reload its history.");
  }
  value.items.forEach((item, index) => {
    if (item.ordinal !== value.total - value.offset - index || !SNAPSHOT.test(item.snapshot_id)
      || item.snapshot_id !== `graph-snapshot_${item.snapshot_digest}`
      || !Number.isSafeInteger(item.revision) || item.revision < 0
      || !Number.isSafeInteger(item.node_count) || item.node_count < 0 || item.node_count > 100000
      || !Number.isSafeInteger(item.edge_count) || item.edge_count < 0 || item.edge_count > 200000
      || !Number.isFinite(Date.parse(item.created_at))
      || !["checkpoint", "handoff", "replan", "recovery"].includes(item.reason)) {
      throw new Error("The stored Snapshot summary is invalid.");
    }
  });
  return value;
}

export function createGraphBrowser({ document, request, isOperator, authEpoch }) {
  const element = (name) => document.querySelector(`#graph-browser-${name}`);
  const state = { sequence: 0, busy: false, catalog: null, page: null, campaign: "" };
  const textNode = (tag, text) => { const node = document.createElement(tag); node.textContent = text; return node; };
  function updateAccess() {
    const allowed = isOperator();
    element("panel").setAttribute("aria-busy", String(state.busy));
    element("refresh").disabled = !allowed || state.busy;
    element("campaign").disabled = !allowed;
    element("reload").disabled = !allowed || state.busy || !state.campaign;
    element("older").disabled = !allowed || state.busy || !state.catalog?.nextCursor;
    element("previous").disabled = !allowed || state.busy || !state.page || state.page.index === 0;
    element("next").disabled = !allowed || state.busy || !state.page?.view.nextCursor;
    element("list").querySelectorAll("button").forEach((button) => { button.disabled = !allowed || state.busy; });
  }
  function clearSelection() {
    state.sequence += 1;
    state.busy = false;
    state.catalog = state.page = null;
    element("list").replaceChildren();
    element("nodes").replaceChildren(); element("edges").replaceChildren();
    element("result").hidden = true;
    element("summary").textContent = "";
  }
  function clear() {
    clearSelection(); state.campaign = "";
    element("campaign").replaceChildren(textNode("option", "Choose a registered Campaign"));
    element("campaign").value = "";
    element("status").textContent = "Connect as an Operator, then load registered Campaigns.";
    updateAccess();
  }
  async function run(message, action) {
    if (!isOperator() || state.busy) return;
    const sequence = ++state.sequence, epoch = authEpoch();
    const current = () => sequence === state.sequence && epoch === authEpoch() && isOperator();
    state.busy = true; element("status").textContent = message; updateAccess();
    try { await action(current); }
    catch (error) {
      if (current()) element("status").textContent = `${error instanceof Error ? error.message : "History could not be loaded."} Reload this Campaign to try again.`;
    } finally { if (current()) { state.busy = false; updateAccess(); } }
  }
  function showPage(view) {
    element("nodes").replaceChildren(...(view.nodes.length ? createGraphNodeNodes(document, view.nodes) : [textNode("li", "No nodes on this page.")]));
    element("edges").replaceChildren(...(view.edges.length ? createGraphEdgeNodes(document, view.edges) : [textNode("li", "No relationships on this page.")]));
    element("nodes").start = element("edges").start = view.pageOffset + 1;
    element("summary").textContent = `Historical read · ${view.campaignId} · revision ${view.projection.revision} · ${view.isCurrent ? "latest at verification" : "earlier Snapshot"} · page ${view.pageOffset / view.pageSize + 1} of ${Math.max(1, Math.ceil(Math.max(view.nodeCount, view.edgeCount) / view.pageSize))}`;
    element("identity").textContent = `${view.snapshot.snapshotId} · ${view.snapshot.createdAt}`;
    element("result").hidden = false;
  }
  async function page(query, index, current) {
    const previous = state.page?.view ?? null;
    const raw = await request(`${BASE}/${encodeURIComponent(state.campaign)}/snapshots/${query.id}/pages?state=${query.state}&limit=100`
      + (query.cursors[index] ? `&cursor=${encodeURIComponent(query.cursors[index])}` : ""));
    if (!current()) return;
    const view = validateHistoricalGraphPage(raw, state.campaign, query.id, { state: query.state, offset: index * 100, limit: 100, previous });
    state.page = { ...query, index, view }; showPage(view);
    element("status").textContent = "Historical Snapshot verified. This view grants no execution authority.";
  }
  async function catalog(cursor, current) {
    const previous = cursor ? state.catalog : null;
    const raw = await request(`${BASE}/${encodeURIComponent(state.campaign)}/snapshots?limit=25`
      + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
    if (!current()) return;
    const value = validateHistoryCatalog(raw, state.campaign, previous);
    state.catalog = value;
    element("list").replaceChildren(...value.items.map((item) => {
      const row = document.createElement("li");
      const button = textNode("button", `${item.created_at} · revision ${item.revision} · ${item.reason}${item.snapshot_id === value.currentSnapshotId ? " · latest" : ""}`);
      button.type = "button"; button.className = "button button-quiet";
      button.addEventListener("click", () => run("Verifying the selected historical Snapshot…", async (valid) => {
        state.page = null; element("result").hidden = true;
        await page({ id: item.snapshot_id, state: value.stateDigest, cursors: [null] }, 0, valid);
      }));
      row.append(button); return row;
    }));
    element("status").textContent = value.total ? `${value.total} stored Snapshots. Showing ${value.offset + 1}–${value.offset + value.items.length}.` : "No stored Snapshots in this Campaign.";
  }
  element("refresh").addEventListener("click", () => run("Loading registered Campaigns…", async (current) => {
    const value = await request(BASE);
    if (!current()) return;
    if (value?.apiVersion !== "pajin.control-plane/graph-campaigns/v1" || value.executionAuthorized !== false
      || !Array.isArray(value.campaigns) || value.campaigns.length > 100
      || value.campaigns.some((id, index) => !CAMPAIGN.test(id) || (index > 0 && value.campaigns[index - 1] >= id))) {
      throw new Error("The registered Campaign list is invalid.");
    }
    state.catalog = state.page = null; state.campaign = "";
    element("list").replaceChildren(); element("result").hidden = true;
    const empty = textNode("option", "Choose a registered Campaign"); empty.value = "";
    element("campaign").replaceChildren(empty, ...value.campaigns.map((id) => {
      const option = textNode("option", id); option.value = id; return option;
    }));
    element("campaign").value = "";
    element("status").textContent = value.campaigns.length ? "Choose a Campaign to browse its verified history." : "No Campaigns are registered for browsing in this deployment.";
  }));
  element("campaign").addEventListener("change", () => {
    clearSelection(); state.campaign = element("campaign").value; updateAccess();
    if (CAMPAIGN.test(state.campaign)) run("Verifying Campaign history…", (current) => catalog(null, current));
    else element("status").textContent = "Choose a registered Campaign.";
  });
  element("reload").addEventListener("click", () => {
    if (state.busy) return;
    clearSelection(); updateAccess();
    if (state.campaign) run("Rechecking Campaign history…", (current) => catalog(null, current));
  });
  element("older").addEventListener("click", () => run("Verifying older history…", (current) => catalog(state.catalog.nextCursor, current)));
  for (const [name, delta] of [["next", 1], ["previous", -1]]) {
    element(name).addEventListener("click", () => run("Verifying historical Graph page…", async (current) => {
      const selected = state.page;
      if (!selected) return;
      const query = { ...selected, cursors: delta > 0 ? [...selected.cursors.slice(0, selected.index + 1), selected.view.nextCursor] : selected.cursors };
      await page(query, selected.index + delta, current);
      if (current()) element("summary").focus();
    }));
  }
  clear(); return { clear, updateAccess };
}
