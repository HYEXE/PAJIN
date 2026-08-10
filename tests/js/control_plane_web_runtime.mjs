import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

class FakeClassList {
  constructor() {
    this.values = new Set();
  }

  add(...names) {
    names.forEach((name) => this.values.add(name));
  }

  remove(...names) {
    names.forEach((name) => this.values.delete(name));
  }

  toggle(name, force) {
    const enabled = force === undefined ? !this.values.has(name) : Boolean(force);
    if (enabled) {
      this.values.add(name);
    } else {
      this.values.delete(name);
    }
    return enabled;
  }

  contains(name) {
    return this.values.has(name);
  }
}

let focusedElement = null;

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.value = "";
    this.textContent = "";
    this.className = "";
    this.disabled = false;
    this.checked = false;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.classList = new FakeClassList();
    this.focused = false;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  async dispatch(type) {
    if (type === "click" && this.disabled) {
      return;
    }
    const event = { preventDefault() {} };
    for (const listener of this.listeners.get(type) || []) {
      await listener(event);
    }
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = [...children];
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  focus() {
    if (focusedElement !== null) {
      focusedElement.focused = false;
    }
    focusedElement = this;
    this.focused = true;
  }
}

const selectors = [
  "#token-form",
  "#token-input",
  "#lock-button",
  ".connection-state",
  "#connection-label",
  "#status-message",
  "#run-form",
  "#runs-panel",
  "#detail-panel",
  "#campaign-name",
  "#job-kind",
  "#idempotency-key",
  "#max-attempts",
  "#run-input",
  "#new-key-button",
  "#submit-button",
  "#refresh-button",
  "#state-filter",
  "#auto-refresh",
  "#runs-body",
  "#previous-page",
  "#next-page",
  "#page-summary",
  "#detail-state",
  "#detail-run-id",
  "#detail-campaign",
  "#detail-created",
  "#detail-updated",
  "#detail-checkpoint",
  "#detail-input",
  "#approval-state",
  "#approval-tool",
  "#approval-target",
  "#approval-risk",
  "#approval-expires",
  "#approval-decision",
  "#workflow-reason",
  "#workflow-help",
  "#workflow-control",
  "#approve-button",
  "#deny-button",
  "#resume-button",
  "#cancel-button",
  "#event-count",
  "#event-list",
  "#latest-events-button",
  "#older-events-button",
  "#discovery-panel",
  "#discovery-form",
  "#discovery-campaign",
  "#discovery-run-id",
  "#discovery-load-button",
  "#discovery-empty",
  "#discovery-result",
  "#discovery-campaign-value",
  "#discovery-run-value",
  "#discovery-surface-set-value",
  "#discovery-snapshot-value",
  "#surface-count",
  "#surface-list",
  "#wave-timeline",
  "#graph-panel",
  "#graph-form",
  "#graph-campaign",
  "#graph-snapshot-id",
  "#graph-load-button",
  "#graph-empty",
  "#graph-result",
  "#graph-campaign-value",
  "#graph-revision-value",
  "#graph-node-count-value",
  "#graph-edge-count-value",
  "#graph-snapshot-value",
  "#graph-projection-value",
  "#graph-node-list",
  "#graph-edge-list",
];
const elements = new Map(selectors.map((selector) => [selector, new FakeElement()]));
elements.get("#campaign-name").value = "web-console-test";
elements.get("#job-kind").value = "campaign";
elements.get("#idempotency-key").value = "runtime-idempotency-key";
elements.get("#max-attempts").value = "3";
elements.get("#run-input").value = "{}";
elements.get("#discovery-campaign").value = "runtime-campaign";
elements.get("#discovery-run-id").value = "run_20260810T010203Z_1234abcd";
elements.get("#graph-campaign").value = "runtime-campaign";
elements.get("#graph-snapshot-id").value = `graph-snapshot_${"c".repeat(64)}`;

globalThis.document = {
  querySelector(selector) {
    const element = elements.get(selector);
    assert.ok(element, `unexpected selector: ${selector}`);
    return element;
  },
  createElement(tagName) {
    return new FakeElement(tagName);
  },
};

const globalListeners = new Map();
globalThis.addEventListener = (type, listener) => {
  const listeners = globalListeners.get(type) || [];
  listeners.push(listener);
  globalListeners.set(type, listeners);
};

let timerSequence = 0;
globalThis.setInterval = () => ++timerSequence;
globalThis.clearInterval = () => {};

const fetchHandlers = [];
const fetchCalls = [];

function enqueueFetch(matcher, responder) {
  fetchHandlers.push({ matcher, responder });
}

globalThis.fetch = async (url, options) => {
  const normalizedUrl = String(url);
  fetchCalls.push({ url: normalizedUrl, options });
  const index = fetchHandlers.findIndex(({ matcher }) => (
    typeof matcher === "string" ? matcher === normalizedUrl : matcher(normalizedUrl, options)
  ));
  assert.notEqual(index, -1, `unexpected fetch: ${normalizedUrl}`);
  const [{ responder }] = fetchHandlers.splice(index, 1);
  return responder(normalizedUrl, options);
};

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const timestamp = "2026-07-19T00:00:00Z";

function runView(id, campaignName, state = "queued") {
  return {
    run_id: id,
    campaign_name: campaignName,
    state,
    input: {},
    current_checkpoint_id: state === "awaiting-approval" ? `checkpoint-${id}` : null,
    created_at: timestamp,
    updated_at: timestamp,
  };
}

function runSummary(id, campaignName, state = "queued") {
  const { input: _input, ...summary } = runView(id, campaignName, state);
  return summary;
}

function runList(items, total = items.length, offset = 0) {
  return { items, total, limit: 25, offset };
}

function discoveryView() {
  const sourceRunId = "run_20260810T000001Z_11111111";
  const hypothesisRunId = "run_20260810T010203Z_1234abcd";
  const surfaceSetId = `attack-surface-set_${"4".repeat(64)}`;
  const surfaceId = `attack-surface_${"5".repeat(64)}`;
  return {
    apiVersion: "pajin.control-plane/verified-discovery-surface-wave-view/v1alpha1",
    kind: "VerifiedDiscoverySurfaceWaveView",
    campaign: { name: "runtime-campaign", digest: "1".repeat(64) },
    hypothesisRun: { runId: hypothesisRunId, rootDigest: "2".repeat(64), state: "completed" },
    surfaceSnapshot: {
      snapshotId: `surface-snapshot_${"3".repeat(64)}`,
      snapshotDigest: "3".repeat(64),
      revision: 1,
      surfaceSetId,
      sourceRunId,
      sourceRootDigest: "6".repeat(64),
      projectionRunId: "run_20260810T000002Z_22222222",
      projectionRootDigest: "7".repeat(64),
      artifactSha256: "8".repeat(64),
    },
    surfaceSet: {
      surfaceSetId,
      generatedAt: timestamp,
      surfaceCount: 1,
      observationCount: 1,
      surfaces: [{
        surfaceId,
        targetId: "runtime-target",
        locator: {
          kind: "tool-interface",
          registry_id: "runtime.registry",
          tool_id: "runtime.tool",
          tool_version: "1.0.0",
          input_schema_digest: "9".repeat(64),
        },
        confidence: 1,
        observationCount: 1,
        firstObservedAt: timestamp,
        lastObservedAt: timestamp,
      }],
    },
    waves: [{
      kind: "recon",
      runId: sourceRunId,
      state: "completed",
      stopCondition: "single-wave-complete",
      taskCount: 1,
    }, {
      kind: "hypothesis",
      runId: hypothesisRunId,
      state: "completed",
      wavePlanId: `hypothesis-wave-plan_${"a".repeat(64)}`,
      stopCondition: "hypothesis-wave-complete",
      taskCount: 1,
      tasks: [{
        hypothesisId: `attack-hypothesis_${"b".repeat(64)}`,
        surfaceId,
        specialistId: "hypothesis-specialist:runtime",
        threatClass: "A02",
      }],
    }],
    authorityBoundary: {
      surfaceSnapshotVerified: true,
      canonicalGraphIncluded: false,
      viewGrantsCapability: false,
      viewGrantsPermit: false,
      viewAuthorizesExecution: false,
    },
  };
}

function canonicalGraphView() {
  const snapshotId = `graph-snapshot_${"c".repeat(64)}`;
  const actionId = `graph-node_${"1".repeat(64)}`;
  const observationId = `graph-node_${"2".repeat(64)}`;
  const evidenceId = `graph-node_${"3".repeat(64)}`;
  return {
    apiVersion: "pajin.control-plane/verified-canonical-graph-view/v1alpha1",
    kind: "VerifiedCanonicalGraphView",
    campaignId: "runtime-campaign",
    snapshot: {
      snapshotId,
      snapshotDigest: "c".repeat(64),
      previousSnapshotDigest: null,
      reason: "checkpoint",
      createdAt: timestamp,
      creatorId: "pajin.graph.runtime-snapshot-authority",
      creatorDigest: "d".repeat(64),
    },
    projection: {
      graphSchemaVersion: "pajin.dev/canonical-graph/v1alpha1",
      revision: 1,
      eventLogHeadDigest: "e".repeat(64),
      projectionId: `graph-projection_${"f".repeat(64)}`,
      projectionDigest: "f".repeat(64),
      nodeProjectionDigest: "4".repeat(64),
      edgeProjectionDigest: "5".repeat(64),
    },
    nodeCount: 3,
    edgeCount: 2,
    nodes: [{
      nodeId: actionId,
      kind: "Action",
      displayKey: "graph.observe",
      displayValue: "capability:graph-observe",
      origin: null,
      state: "succeeded",
      confidence: null,
      occurredAt: timestamp,
    }, {
      nodeId: observationId,
      kind: "Observation",
      displayKey: "surface-confirmed",
      displayValue: "pajin.graph.runtime-producer",
      origin: "target-derived",
      state: null,
      confidence: 0.9,
      occurredAt: timestamp,
    }, {
      nodeId: evidenceId,
      kind: "Evidence",
      displayKey: "application/json",
      displayValue: "internal",
      origin: null,
      state: null,
      confidence: null,
      occurredAt: null,
    }],
    edges: [{
      edgeId: `graph-edge_${"6".repeat(64)}`,
      relation: "produces",
      source: { nodeId: actionId, kind: "Action" },
      target: { nodeId: observationId, kind: "Observation" },
      authorityId: "pajin.graph.admission-authority",
      authorityDigest: "a".repeat(64),
    }, {
      edgeId: `graph-edge_${"7".repeat(64)}`,
      relation: "supported-by",
      source: { nodeId: observationId, kind: "Observation" },
      target: { nodeId: evidenceId, kind: "Evidence" },
      authorityId: "pajin.graph.admission-authority",
      authorityDigest: "a".repeat(64),
    }],
    authorityBoundary: {
      canonicalGraphSnapshotVerified: true,
      currentSnapshotVerified: true,
      contentRedacted: true,
      viewAuthorizesAdmission: false,
      viewGrantsCapability: false,
      viewGrantsPermit: false,
      viewAuthorizesExecution: false,
    },
  };
}

function jobView(run, { state = "queued", kind = "campaign" } = {}) {
  return {
    job_id: `job_${"a".repeat(32)}`,
    run_id: run.run_id,
    kind,
    state,
    payload: { input: run.input },
    priority: 0,
    attempts: 0,
    max_attempts: 3,
    available_at: timestamp,
    lease_owner: null,
    lease_expires_at: null,
    heartbeat_at: null,
    result: null,
    error: null,
    created_at: timestamp,
    updated_at: timestamp,
  };
}

function approvalFor(run, state = "pending", requestedBy = "worker") {
  return {
    approval_id: `approval-${run.run_id}`,
    run_id: run.run_id,
    checkpoint_id: run.current_checkpoint_id,
    intent: {
      call_fingerprint: "a".repeat(64),
      tool_id: "runtime-tool",
      target: "https://example.invalid/target",
      risk_tier: 3,
      expires_at: "2030-01-01T00:00:00Z",
    },
    state,
    requested_by: requestedBy,
    requested_at: timestamp,
    decided_by: null,
    decided_at: null,
    decision_reason: null,
    consumed_by: null,
    consumed_at: null,
  };
}

function eventFor(run, sequence = 1) {
  return {
    event_id: `event-${run.run_id}-${sequence}`,
    run_id: run.run_id,
    sequence,
    event_type: "run.submitted",
    actor: "operator",
    payload: {},
    occurred_at: timestamp,
  };
}

async function settle() {
  for (let index = 0; index < 8; index += 1) {
    await Promise.resolve();
  }
}

async function submitToken(token) {
  elements.get("#token-input").value = token;
  await elements.get("#token-form").dispatch("submit");
}

function enqueueConnection(role, items = []) {
  enqueueFetch("/v1/session", () => jsonResponse({
    subject: `${role}-subject`,
    roles: [role],
  }));
  enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList(items)));
}

const applicationPath = process.argv[2];
assert.ok(applicationPath, "app.js path is required");
const applicationUrl = pathToFileURL(applicationPath);
const protocol = await import(new URL("./protocol.js", applicationUrl).href);
const rendering = await import(new URL("./render.js", applicationUrl).href);

assert.equal(protocol.PAGE_SIZE, 25);
assert.equal(protocol.MAX_RENDERED_EVENTS, 200);
assert.equal(protocol.isRunState("awaiting-approval"), true);
assert.equal(protocol.isRunState("plausible-but-invalid"), false);
const losslessPayload = protocol.parseJsonPayload(
  '{"exact":9007199254740993,"overflow":1e400,"negativeZero":-0}',
  200,
);
assert.equal(
  protocol.formatJson(losslessPayload),
  '{\n  "exact": 9007199254740993,\n  "overflow": 1e400,\n  "negativeZero": -0\n}',
);
assert.throws(
  () => protocol.validatePrincipal({ subject: "worker-only", roles: ["worker"] }),
  protocol.ApiProtocolError,
);
const validCanonicalGraphView = canonicalGraphView();
assert.equal(
  protocol.validateCanonicalGraphView(
    validCanonicalGraphView,
    "runtime-campaign",
    `graph-snapshot_${"c".repeat(64)}`,
  ),
  validCanonicalGraphView,
);
assert.throws(
  () => protocol.validateCanonicalGraphView(
    {
      ...canonicalGraphView(),
      authorityBoundary: {
        ...canonicalGraphView().authorityBoundary,
        currentSnapshotVerified: false,
      },
    },
    "runtime-campaign",
    `graph-snapshot_${"c".repeat(64)}`,
  ),
  protocol.ApiProtocolError,
);
const validDiscoveryView = discoveryView();
assert.equal(
  protocol.validateDiscoveryView(
    validDiscoveryView,
    "runtime-campaign",
    "run_20260810T010203Z_1234abcd",
  ),
  validDiscoveryView,
);
assert.throws(
  () => protocol.validateDiscoveryView(
    {
      ...discoveryView(),
      authorityBoundary: {
        ...discoveryView().authorityBoundary,
        canonicalGraphIncluded: true,
      },
    },
    "runtime-campaign",
    "run_20260810T010203Z_1234abcd",
  ),
  protocol.ApiProtocolError,
);
assert.equal(rendering.eventCountLabel([]), "0 events");
assert.equal(
  rendering.eventCountLabel([{ sequence: 7 }]),
  "#7–#7 · 1 event",
);

await import(applicationUrl.href);

const validToken = (suffix) => `runtime-token-${suffix}-${"x".repeat(32)}`;

enqueueConnection("operator");
await submitToken(validToken("operator"));
assert.equal(elements.get("#connection-label").textContent, "operator");
assert.equal(elements.get("#submit-button").disabled, false);
assert.equal(elements.get("#token-form").attributes.get("aria-busy"), "false");
assert.equal(elements.get("#runs-panel").attributes.get("aria-busy"), "false");
assert.equal(elements.get("#discovery-load-button").disabled, false);
assert.equal(elements.get("#graph-load-button").disabled, false);

elements.get("#discovery-campaign").value = "runtime-campaign";
elements.get("#discovery-run-id").value = "run_20260810T010203Z_1234abcd";
enqueueFetch(
  "/v1/discovery/campaigns/runtime-campaign/hypothesis-runs/run_20260810T010203Z_1234abcd",
  () => jsonResponse(discoveryView()),
);
await elements.get("#discovery-form").dispatch("submit");
assert.equal(elements.get("#discovery-result").hidden, false);
assert.equal(elements.get("#discovery-empty").hidden, true);
assert.equal(elements.get("#surface-count").textContent, "1 surface");
assert.equal(elements.get("#surface-list").children.length, 1);
assert.equal(elements.get("#wave-timeline").children.length, 2);
assert.equal(elements.get("#discovery-form").attributes.get("aria-busy"), "false");

elements.get("#graph-campaign").value = "runtime-campaign";
elements.get("#graph-snapshot-id").value = `graph-snapshot_${"c".repeat(64)}`;
enqueueFetch(
  `/v1/graphs/campaigns/runtime-campaign/snapshots/graph-snapshot_${"c".repeat(64)}`,
  () => jsonResponse(canonicalGraphView()),
);
await elements.get("#graph-form").dispatch("submit");
assert.equal(elements.get("#graph-result").hidden, false);
assert.equal(elements.get("#graph-empty").hidden, true);
assert.equal(elements.get("#graph-node-count-value").textContent, "3");
assert.equal(elements.get("#graph-edge-count-value").textContent, "2");
assert.equal(elements.get("#graph-node-list").children.length, 3);
assert.equal(elements.get("#graph-edge-list").children.length, 2);
assert.equal(elements.get("#graph-form").attributes.get("aria-busy"), "false");

enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList([], 1)),
);
await elements.get("#refresh-button").dispatch("click");
assert.match(elements.get("#status-message").textContent, /invalid Run list response/);
assert.equal(elements.get("#status-message").classList.contains("success"), false);

enqueueFetch("/v1/session", () => new Response(null, { status: 204 }));
await submitToken(validToken("empty-success"));
assert.equal(elements.get("#connection-label").textContent, "Locked");
assert.match(elements.get("#status-message").textContent, /empty or non-JSON success response/);
assert.equal(elements.get("#status-message").classList.contains("error"), true);
assert.equal(elements.get("#token-input").focused, true);

enqueueFetch("/v1/session", () => new Response("not-json", {
  status: 401,
  headers: { "content-type": "text/plain" },
}));
await submitToken(validToken("unauthorized"));
assert.equal(elements.get("#connection-label").textContent, "Locked");
assert.match(elements.get("#status-message").textContent, /Authentication failed/);
assert.equal(elements.get("#status-message").classList.contains("error"), true);
assert.equal(elements.get("#token-input").value, "");
assert.equal(elements.get("#token-input").focused, true);

enqueueFetch("/v1/session", () => new Response("{invalid", {
  status: 200,
  headers: { "content-type": "application/json" },
}));
await submitToken(validToken("invalid-json"));
assert.equal(elements.get("#connection-label").textContent, "Locked");
assert.match(elements.get("#status-message").textContent, /invalid JSON/);
assert.equal(elements.get("#token-input").focused, true);

enqueueFetch("/v1/session", () => jsonResponse({ subject: "partial", roles: ["operator"] }));
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse({ detail: "list unavailable" }, 503));
await submitToken(validToken("partial-connection"));
assert.equal(elements.get("#connection-label").textContent, "operator");
assert.match(elements.get("#status-message").textContent, /Connected as partial.*list unavailable/);
assert.equal(
  elements.get("#runs-body").children[0].children[0].textContent,
  "Runs are unavailable. Use Refresh to retry.",
);
await elements.get("#lock-button").dispatch("click");
assert.equal(elements.get("#token-input").focused, true);

const firstAuthentication = deferred();
const secondAuthentication = deferred();
enqueueFetch("/v1/session", () => firstAuthentication.promise);
enqueueFetch("/v1/session", () => secondAuthentication.promise);
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList([])));
const firstLogin = submitToken(validToken("old-approver"));
await settle();
const secondLogin = submitToken(validToken("new-operator"));
await settle();
secondAuthentication.resolve(jsonResponse({ subject: "new", roles: ["operator"] }));
await secondLogin;
firstAuthentication.resolve(new Response("stale unauthorized", {
  status: 401,
  headers: { "content-type": "text/plain" },
}));
await firstLogin;
assert.equal(elements.get("#connection-label").textContent, "operator");
assert.equal(elements.get("#submit-button").disabled, false);

const pendingAuthentication = deferred();
enqueueFetch("/v1/session", () => pendingAuthentication.promise);
const pendingLogin = submitToken(validToken("pending"));
await settle();
assert.equal(elements.get("#lock-button").disabled, false);
elements.get("#lock-button").focus();
await elements.get("#lock-button").dispatch("click");
assert.equal(elements.get("#token-input").focused, true);
pendingAuthentication.resolve(jsonResponse({ subject: "late", roles: ["approver"] }));
await pendingLogin;
assert.equal(elements.get("#connection-label").textContent, "Locked");

const runA = runView("run-a", "first-campaign");
const runB = runView("run-b", "second-campaign");
enqueueConnection("operator", [runSummary(runA.run_id, runA.campaign_name), runSummary(runB.run_id, runB.campaign_name)]);
await submitToken(validToken("races"));

// Exercise the original disclosure timing directly. The fake fetch deliberately
// ignores AbortSignal so the generation guard, rather than transport cooperation,
// must prevent a successful old Run response from repopulating the locked Console.
const staleLockedRuns = deferred();
enqueueFetch("/v1/runs?limit=25&offset=0", (_url, options) => {
  assert.equal(options.signal.aborted, false);
  return staleLockedRuns.promise;
});
const lockedRefresh = elements.get("#refresh-button").dispatch("click");
await settle();
const lockedRequest = fetchCalls.at(-1);
assert.equal(lockedRequest.url, "/v1/runs?limit=25&offset=0");
await elements.get("#lock-button").dispatch("click");
assert.equal(lockedRequest.options.signal.aborted, true);
staleLockedRuns.resolve(jsonResponse(runList([
  runSummary("run-stale-after-lock", "must-not-reappear"),
])));
await lockedRefresh;
assert.equal(elements.get("#connection-label").textContent, "Locked");
assert.equal(elements.get("#page-summary").textContent, "0–0 of 0 Runs");
assert.equal(
  elements.get("#runs-body").children[0].children[0].textContent,
  "Connect to load Runs.",
);

enqueueConnection("operator", [runSummary(runA.run_id, runA.campaign_name), runSummary(runB.run_id, runB.campaign_name)]);
await submitToken(validToken("post-lock"));

elements.get("#run-input").value = "{\"exactInteger\":9007199254740993}";
enqueueFetch(
  (url, options) => url === "/v1/runs" && options.method === "POST",
  (_url, options) => {
    assert.match(options.body, /"exactInteger":9007199254740993/);
    return new Response(null, { status: 204 });
  },
);
await elements.get("#run-form").dispatch("submit");
elements.get("#run-input").value = "{}";
assert.match(elements.get("#status-message").textContent, /empty or non-JSON success response/);
assert.equal(elements.get("#status-message").classList.contains("success"), false);

const invalidCreatedRun = runView("run-invalid-created-state", "web-console-test", "running");
enqueueFetch(
  (url, options) => url === "/v1/runs" && options.method === "POST",
  () => jsonResponse({
    created: true,
    run: invalidCreatedRun,
    job: jobView(invalidCreatedRun, { state: "leased" }),
  }),
);
await elements.get("#run-form").dispatch("submit");
assert.match(elements.get("#status-message").textContent, /invalid Run submission response/);
assert.equal(elements.get("#status-message").classList.contains("success"), false);

const oldRefresh = deferred();
enqueueFetch("/v1/runs?limit=25&offset=0", () => oldRefresh.promise);
const refresh = elements.get("#refresh-button").dispatch("click");
await settle();
elements.get("#state-filter").value = "running";
await elements.get("#state-filter").dispatch("change");
enqueueFetch(
  "/v1/runs?limit=25&offset=0&state=running",
  () => jsonResponse(runList([runSummary("run-latest", "latest-campaign", "running")], 1)),
);
oldRefresh.resolve(jsonResponse(runList([
  runSummary("run-stale", "stale-campaign"),
  runSummary("run-other", "other-campaign"),
], 2)));
await refresh;
assert.equal(elements.get("#page-summary").textContent, "1–1 of 1 Runs");
assert.equal(
  elements.get("#runs-body").children[0].children[0].children[0].children[0].textContent,
  "latest-campaign",
);

elements.get("#state-filter").value = "";
const twentyFiveRuns = Array.from({ length: 25 }, (_, index) => (
  runSummary(`run-page-${index}`, `campaign-${index}`)
));
enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList(twentyFiveRuns, 26)),
);
await elements.get("#refresh-button").dispatch("click");
enqueueFetch(
  "/v1/runs?limit=25&offset=25",
  () => jsonResponse(runList([], 10, 25)),
);
enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)),
);
await elements.get("#next-page").dispatch("click");
await settle();
assert.equal(elements.get("#page-summary").textContent, "1–10 of 10 Runs");

const firstOpenButton = elements.get("#runs-body").children[0].children[3].children[0];
const secondOpenButton = elements.get("#runs-body").children[1].children[3].children[0];
const detailA = deferred();
const eventsA = deferred();
const approvalA = deferred();
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)));
enqueueFetch(`/v1/runs/${twentyFiveRuns[0].run_id}`, () => detailA.promise);
enqueueFetch(`/v1/runs/${twentyFiveRuns[0].run_id}/events?limit=200`, () => eventsA.promise);
enqueueFetch(`/v1/runs/${twentyFiveRuns[0].run_id}/approval`, () => approvalA.promise);
elements.get("#workflow-reason").value = "reason for a previously selected Run";
const selectFirst = firstOpenButton.dispatch("click");
await settle();
assert.equal(elements.get("#cancel-button").disabled, true);
assert.equal(elements.get("#workflow-reason").value, "");
assert.equal(elements.get("#detail-panel").attributes.get("aria-busy"), "true");
assert.equal(elements.get("#workflow-control").attributes.get("aria-busy"), "true");
assert.equal(elements.get("#event-list").attributes.get("aria-busy"), "true");

const selectedSecond = runView(twentyFiveRuns[1].run_id, twentyFiveRuns[1].campaign_name);
const exactIntegerDetail = JSON.stringify({
  ...selectedSecond,
  input: {
    exactInteger: "EXACT_INTEGER_PLACEHOLDER",
    overflowExponent: "OVERFLOW_EXPONENT_PLACEHOLDER",
    underflowExponent: "UNDERFLOW_EXPONENT_PLACEHOLDER",
    preciseDecimal: "PRECISE_DECIMAL_PLACEHOLDER",
    negativeZero: "NEGATIVE_ZERO_PLACEHOLDER",
  },
})
  .replace('"EXACT_INTEGER_PLACEHOLDER"', "9007199254740993")
  .replace('"OVERFLOW_EXPONENT_PLACEHOLDER"', "1e400")
  .replace('"UNDERFLOW_EXPONENT_PLACEHOLDER"', "1e-400")
  .replace('"PRECISE_DECIMAL_PLACEHOLDER"', "0.1234567890123456789")
  .replace('"NEGATIVE_ZERO_PLACEHOLDER"', "-0");
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)));
enqueueFetch(`/v1/runs/${selectedSecond.run_id}`, () => new Response(exactIntegerDetail, {
  status: 200,
  headers: { "content-type": "application/json" },
}));
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(selectedSecond, 201)]),
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}/approval`, () => jsonResponse(null));
elements.get("#workflow-reason").value = "reason for the first Run";
await secondOpenButton.dispatch("click");
detailA.resolve(jsonResponse(runView(twentyFiveRuns[0].run_id, twentyFiveRuns[0].campaign_name)));
eventsA.resolve(jsonResponse([eventFor(runView(twentyFiveRuns[0].run_id, twentyFiveRuns[0].campaign_name))]));
approvalA.resolve(jsonResponse(null));
await selectFirst;
assert.equal(elements.get("#detail-run-id").textContent, selectedSecond.run_id);
assert.equal(elements.get("#detail-campaign").textContent, selectedSecond.campaign_name);
assert.equal(elements.get("#workflow-reason").value, "");
assert.match(elements.get("#detail-input").textContent, /9007199254740993/);
assert.doesNotMatch(elements.get("#detail-input").textContent, /9007199254740992/);
assert.match(elements.get("#detail-input").textContent, /"overflowExponent": 1e400/);
assert.match(elements.get("#detail-input").textContent, /"underflowExponent": 1e-400/);
assert.match(elements.get("#detail-input").textContent, /"preciseDecimal": 0\.1234567890123456789/);
assert.match(elements.get("#detail-input").textContent, /"negativeZero": -0/);
assert.match(elements.get("#status-message").textContent, new RegExp(selectedSecond.run_id));
assert.equal(elements.get("#detail-panel").focused, true);
assert.equal(elements.get("#detail-panel").attributes.get("aria-busy"), "false");
assert.equal(elements.get("#event-list").attributes.get("aria-busy"), "false");
assert.equal(elements.get("#older-events-button").disabled, false);

const detailRefresh = deferred();
const eventRefresh = deferred();
const approvalRefresh = deferred();
enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)),
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}`, () => detailRefresh.promise);
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200`,
  () => eventRefresh.promise,
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}/approval`, () => approvalRefresh.promise);
const pendingDetailRefresh = elements.get("#refresh-button").dispatch("click");
await settle();
assert.equal(elements.get("#cancel-button").disabled, true);
assert.equal(elements.get("#detail-panel").attributes.get("aria-busy"), "true");
detailRefresh.resolve(jsonResponse(selectedSecond));
eventRefresh.resolve(jsonResponse([eventFor(selectedSecond, 201)]));
approvalRefresh.resolve(jsonResponse(null));
await pendingDetailRefresh;
assert.equal(elements.get("#cancel-button").disabled, false);
assert.equal(elements.get("#detail-panel").attributes.get("aria-busy"), "false");

enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200&before=201`,
  () => jsonResponse([eventFor(selectedSecond)]),
);
await elements.get("#older-events-button").dispatch("click");
assert.equal(elements.get("#event-count").textContent, "#1–#1 · 1 event");
assert.equal(elements.get("#older-events-button").disabled, true);
assert.equal(elements.get("#latest-events-button").disabled, false);
enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)),
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}`, () => jsonResponse(selectedSecond));
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200&before=201`,
  () => jsonResponse([eventFor(selectedSecond)]),
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}/approval`, () => jsonResponse(null));
await elements.get("#refresh-button").dispatch("click");
assert.equal(elements.get("#event-count").textContent, "#1–#1 · 1 event");
assert.equal(elements.get("#latest-events-button").disabled, false);
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(selectedSecond, 201)]),
);
await elements.get("#latest-events-button").dispatch("click");
assert.equal(elements.get("#event-count").textContent, "#201–#201 · 1 event");
assert.equal(elements.get("#latest-events-button").disabled, true);

enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse(runList(twentyFiveRuns.slice(0, 10), 10)),
);
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}`,
  () => jsonResponse({ detail: "detail unavailable" }, 503),
);
enqueueFetch(
  `/v1/runs/${selectedSecond.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(selectedSecond, 201)]),
);
enqueueFetch(`/v1/runs/${selectedSecond.run_id}/approval`, () => jsonResponse(null));
await elements.get("#refresh-button").dispatch("click");
assert.equal(elements.get("#detail-state").textContent, "Unavailable");
assert.equal(elements.get("#cancel-button").disabled, true);
assert.equal(elements.get("#detail-panel").attributes.get("aria-busy"), "false");
assert.match(elements.get("#status-message").textContent, /detail unavailable/);
assert.match(elements.get("#detail-input").textContent, /unavailable/);

const pendingRun = runView("run-awaiting", "approval-campaign", "awaiting-approval");
await elements.get("#lock-button").dispatch("click");
enqueueConnection("approver", [runSummary(pendingRun.run_id, pendingRun.campaign_name, pendingRun.state)]);
await submitToken(validToken("approver"));
const approverOpen = elements.get("#runs-body").children[0].children[3].children[0];
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList([
  runSummary(pendingRun.run_id, pendingRun.campaign_name, pendingRun.state),
])));
enqueueFetch(`/v1/runs/${pendingRun.run_id}`, () => jsonResponse(pendingRun));
enqueueFetch(
  `/v1/runs/${pendingRun.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(pendingRun)]),
);
enqueueFetch(`/v1/runs/${pendingRun.run_id}/approval`, () => jsonResponse(approvalFor(pendingRun)));
await approverOpen.dispatch("click");
assert.equal(elements.get("#approve-button").disabled, false);
assert.equal(elements.get("#deny-button").disabled, false);
assert.equal(elements.get("#resume-button").disabled, true);
assert.equal(elements.get("#cancel-button").disabled, true);
elements.get("#workflow-reason").value = "runtime approval reason";
enqueueFetch(
  `/v1/approvals/${approvalFor(pendingRun).approval_id}/decision`,
  () => new Response(null, { status: 204 }),
);
enqueueFetch("/v1/runs?limit=25&offset=0", () => jsonResponse(runList([
  runSummary(pendingRun.run_id, pendingRun.campaign_name, pendingRun.state),
])));
enqueueFetch(`/v1/runs/${pendingRun.run_id}`, () => jsonResponse(pendingRun));
enqueueFetch(
  `/v1/runs/${pendingRun.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(pendingRun)]),
);
enqueueFetch(
  `/v1/runs/${pendingRun.run_id}/approval`,
  () => jsonResponse(approvalFor(pendingRun, "pending", "approver-subject")),
);
await elements.get("#approve-button").dispatch("click");
assert.match(elements.get("#status-message").textContent, /empty or non-JSON success response/);
assert.equal(elements.get("#status-message").classList.contains("success"), false);
assert.equal(elements.get("#approve-button").disabled, true);
assert.match(elements.get("#workflow-help").textContent, /cannot decide their own request/);
assert.equal(elements.get("#workflow-reason").value, "runtime approval reason");

await elements.get("#lock-button").dispatch("click");
assert.equal(elements.get("#workflow-reason").value, "");
enqueueConnection("operator");
await submitToken(validToken("submission-refresh-failure"));
const submittedRun = runView("run-submitted-refresh-failure", "web-console-test");
enqueueFetch(
  (url, options) => url === "/v1/runs" && options.method === "POST",
  () => jsonResponse({
    created: true,
    run: submittedRun,
    job: jobView(submittedRun),
  }),
);
enqueueFetch(
  "/v1/runs?limit=25&offset=0",
  () => jsonResponse({ detail: "post-submit list unavailable" }, 503),
);
enqueueFetch(`/v1/runs/${submittedRun.run_id}`, () => jsonResponse(submittedRun));
enqueueFetch(
  `/v1/runs/${submittedRun.run_id}/events?limit=200`,
  () => jsonResponse([eventFor(submittedRun)]),
);
enqueueFetch(`/v1/runs/${submittedRun.run_id}/approval`, () => jsonResponse(null));
await elements.get("#run-form").dispatch("submit");
assert.match(
  elements.get("#status-message").textContent,
  /Run submitted and queued\. Current state could not be fully loaded/,
);
assert.doesNotMatch(elements.get("#status-message").textContent, /Run submission failed/);
assert.equal(elements.get("#status-message").classList.contains("success"), false);
assert.equal(elements.get("#run-form").attributes.get("aria-busy"), "false");
assert.equal(elements.get("#submit-button").disabled, false);

elements.get("#workflow-reason").focus();
for (const listener of globalListeners.get("pagehide") || []) {
  listener();
}
assert.equal(elements.get("#connection-label").textContent, "Locked");
assert.equal(elements.get("#token-input").value, "");
assert.equal(elements.get("#token-input").focused, false);
assert.equal(elements.get("#workflow-reason").focused, true);
assert.equal(fetchHandlers.length, 0, "all expected fetch handlers must be consumed");
assert.ok(fetchCalls.length > 0);
