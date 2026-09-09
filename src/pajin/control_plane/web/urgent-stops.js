const EVENT_ID = /^event_[a-f0-9]{32}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const REASONS = {
  "credential-material-exposure": "Credential material exposure",
  "scope-boundary-violation": "Scope boundary violation",
  "unsafe-side-effect": "Unsafe side effect",
};

function validateAck(value, alert) {
  if (!value || value.alertId !== alert.alertId
    || value.applicationDigest !== alert.application.applicationDigest
    || !IDENTIFIER.test(value.actor) || !Number.isFinite(Date.parse(value.acknowledgedAt))) {
    throw new Error("The acknowledgment response does not match this alert.");
  }
  return value;
}

export function validateUrgentStopPage(value) {
  if (!value || !Array.isArray(value.items) || value.items.length > 100
    || (value.nextCursor !== null && !EVENT_ID.test(value.nextCursor))) {
    throw new Error("The urgent stop response does not match the alert contract.");
  }
  const ids = new Set();
  for (const alert of value.items) {
    const applied = alert?.application;
    const decision = applied?.decision;
    if (!EVENT_ID.test(alert?.alertId) || ids.has(alert.alertId)
      || applied?.apiVersion !== "pajin.dev/urgent-stop-application/v1"
      || applied.state !== "control-plane-cancelled" || !DIGEST.test(applied.applicationDigest)
      || !IDENTIFIER.test(applied.binding?.runId) || !Number.isFinite(Date.parse(applied.appliedAt))
      || decision?.decisionState !== "admitted-not-applied"
      || !Object.hasOwn(REASONS, decision.observationType)
      || ["executionAuthorized", "permitGranted", "capabilityGranted", "scopeExpansionAuthorized"]
        .some((key) => decision[key] !== false)
      || ["fencedWorkers", "observedWorkers", "quiescedWorkers", "drainedWorkers", "incompleteWorkers"]
        .some((key) => !Number.isSafeInteger(alert[key]) || alert[key] < 0)
      || alert.observedWorkers > alert.fencedWorkers
      || alert.quiescedWorkers > alert.drainedWorkers
      || alert.drainedWorkers + alert.incompleteWorkers > alert.observedWorkers) {
      throw new Error("The urgent stop response has inconsistent state.");
    }
    if (alert.acknowledgment !== null) validateAck(alert.acknowledgment, alert);
    ids.add(alert.alertId);
  }
  return value;
}

export function createUrgentStops({ document, request, access, authEpoch }) {
  const element = (name) => document.querySelector(`#urgent-stops-${name}`);
  const panel = element("panel");
  const status = element("status");
  const list = element("list");
  const state = { sequence: 0, busy: false, items: [], next: null, atLatest: true };
  const node = (tag, text, className = "") => {
    const value = document.createElement(tag);
    value.textContent = text;
    value.className = className;
    return value;
  };
  function updateAccess() {
    const enabled = access().connected && !state.busy;
    element("refresh").disabled = !enabled;
    element("more").disabled = !enabled || state.next === null;
    element("more").hidden = state.next === null;
    list.querySelectorAll("button").forEach((button) => {
      button.disabled = !enabled || !access().operator;
    });
    panel.setAttribute("aria-busy", String(state.busy));
  }
  function clear() {
    state.sequence += 1;
    state.busy = false;
    state.items = [];
    state.next = null;
    state.atLatest = true;
    list.replaceChildren();
    status.textContent = "Connect to view urgent stops.";
    updateAccess();
  }
  function render() {
    list.replaceChildren();
    for (const alert of state.items) {
      const card = node("article", "", "urgent-stop-card");
      card.append(node("h3", REASONS[alert.application.decision.observationType]));
      card.append(node("p", `Run ${alert.application.binding.runId}`, "mono"));
      card.append(node("p", `Run cancelled at ${new Date(alert.application.appliedAt).toLocaleString()}.`));
      card.append(node("p", alert.fencedWorkers === 0
        ? "No cancelled Worker lease is recorded. Cleanup status is unknown."
        : `${alert.drainedWorkers} of ${alert.fencedWorkers} Workers reported stopped execution; `
        + `${alert.quiescedWorkers} also reported completed local cleanup. `
        + `${alert.fencedWorkers - alert.observedWorkers} reports pending; ${alert.incompleteWorkers} reported incomplete cleanup.`));
      if (alert.acknowledgment) {
        card.append(node("p", `Acknowledged by ${alert.acknowledgment.actor}.`));
      } else {
        const button = node("button", "Acknowledge alert", "button button-quiet");
        button.type = "button";
        button.addEventListener("click", () => acknowledge(alert));
        card.append(button);
      }
      list.append(card);
    }
    const pending = state.items.filter((item) => item.acknowledgment === null).length;
    status.textContent = state.items.length
      ? `${state.items.length} urgent stop${state.items.length === 1 ? "" : "s"} shown; ${pending} awaiting acknowledgment on this page.`
      : "No urgent stops recorded.";
    updateAccess();
  }
  async function refresh({ more = false, quiet = false } = {}) {
    if (!access().connected || state.busy || (quiet && !state.atLatest)) return;
    const sequence = ++state.sequence;
    const epoch = authEpoch();
    const current = () => state.sequence === sequence && authEpoch() === epoch && access().connected;
    const cursor = more ? state.next : null;
    if (more && cursor === null) return;
    state.busy = true;
    updateAccess();
    try {
      const page = validateUrgentStopPage(await request(`/v1/urgent-stops?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`));
      if (!current()) return;
      const changed = JSON.stringify(state.items) !== JSON.stringify(page.items);
      state.items = page.items;
      state.next = page.nextCursor;
      state.atLatest = !more;
      if (changed || !quiet) render();
    } catch (error) {
      if (!current()) return;
      state.items = [];
      state.next = null;
      list.replaceChildren();
      status.textContent = "Urgent stops unavailable. Refresh to retry.";
    } finally {
      if (current()) { state.busy = false; updateAccess(); }
    }
  }
  async function acknowledge(alert) {
    if (!access().connected || !access().operator || state.busy) return;
    const sequence = ++state.sequence;
    const epoch = authEpoch();
    const current = () => state.sequence === sequence && authEpoch() === epoch && access().connected;
    state.busy = true;
    updateAccess();
    try {
      const response = await request(`/v1/urgent-stops/${alert.alertId}/acknowledgment`, {
        method: "POST", body: JSON.stringify({ applicationDigest: alert.application.applicationDigest }),
      });
      if (!current()) return;
      alert.acknowledgment = validateAck(response, alert);
      state.busy = false;
      render();
      status.textContent = "Alert acknowledged. This Run remains cancelled.";
      element("refresh").focus();
    } catch (error) {
      if (current()) status.textContent = "Acknowledgment could not be verified. Refresh before retrying.";
    } finally {
      if (current()) { state.busy = false; updateAccess(); }
    }
  }
  element("refresh").addEventListener("click", () => refresh());
  element("more").addEventListener("click", () => refresh({ more: true }));
  clear();
  return { clear, refresh, updateAccess };
}
