import {
  formatJson, validateMeasuredBenchmarkProduct, validateWebMeasuredProductProjection,
} from "./protocol.js";

const BASE = "/v1/measured-reviews";
const DIGEST = /^[a-f0-9]{64}$/;
const ID = /^review_[a-f0-9]{32}$/;
const STATES = ["open", "awaiting-review", "changes-requested", "accepted"];

export function validateReviewEvidence(value) {
  if (!value || value.apiVersion !== "pajin.dev/measured-review-evidence/v1"
    || !["web", "network", "ai"].includes(value.domain) || !DIGEST.test(value.evidenceDigest)
    || value.evidenceScope !== "verified-controlled-benchmark-summary"
    || value.rawContentIncluded !== false || !Number.isFinite(Date.parse(value.verifiedAt))) {
    throw new Error("The evidence response does not match the review contract.");
  }
  if (value.domain === "web") validateWebMeasuredProductProjection(value.projection);
  else validateMeasuredBenchmarkProduct(value.projection, value.domain);
  return value;
}

export function validateMeasuredReview(value) {
  if (!value || value.apiVersion !== "pajin.dev/measured-human-review/v1"
    || !ID.test(value.reviewId) || !Number.isInteger(value.revision)
    || value.revision < 1 || value.revision > 200 || !DIGEST.test(value.recordDigest)
    || typeof value.title !== "string" || !STATES.includes(value.state)
    || value.historicalVerificationOnly !== true
    || ["executionAuthorized", "genericFindingConfirmed", "sarifAuthorized", "externalDeliveryAuthorized"]
      .some((key) => value[key] !== false)
    || !Array.isArray(value.history) || value.history.length !== value.revision
    || value.history.some((item, index) => item.revision !== index + 1 || !DIGEST.test(item.recordDigest))) {
    throw new Error("The review response does not match the human review contract.");
  }
  validateReviewEvidence(value.evidence);
  if (value.retest !== null) {
    validateReviewEvidence(value.retest.evidence);
    if (value.retest.executionAfterRemediationVerified !== false) {
      throw new Error("Retest timing cannot be claimed by this review contract.");
    }
  }
  if (value.state === "accepted" && (!value.assessment || !value.reviewer
    || value.decision?.decision !== "accept" || value.reviewer === value.assessmentAuthor
    || value.reviewer === value.retestAuthor)) {
    throw new Error("Acceptance does not identify a distinct human reviewer.");
  }
  return value;
}

export function createMeasuredReviews({ document, request, requestReport, access, authEpoch, announce }) {
  const element = (name) => document.querySelector(`#measured-review-${name}`);
  const panel = element("panel");
  const status = element("status");
  const detail = element("detail");
  const list = element("list");
  const source = element("source");
  const forms = ["open", "assessment", "decision", "retest"].map((name) => element(`${name}-form`));
  const state = { sequence: 0, stepSequence: 0, busy: false, evidence: null, review: null, after: null, keys: new Map() };
  const fields = (form) => [...form.querySelectorAll("input, select, textarea, button")];
  const node = (tag, text, className = "") => {
    const result = document.createElement(tag);
    result.textContent = text;
    if (className) result.className = className;
    return result;
  };
  function updateAccess() {
    const role = access();
    const reading = role.connected && !state.busy;
    const writing = reading && role.operator;
    element("domain").disabled = !reading;
    element("load-source").disabled = !reading;
    element("refresh").disabled = !reading;
    element("more").disabled = !reading || state.after === null;
    element("more").hidden = state.after === null;
    fields(element("lookup-form")).forEach((field) => { field.disabled = !reading; });
    list.querySelectorAll("button").forEach((button) => { button.disabled = !reading; });
    fields(forms[0]).forEach((field) => { field.disabled = !writing || !state.evidence; });
    fields(forms[1]).forEach((field) => { field.disabled = !writing || !state.review; });
    const pending = state.review?.state === "awaiting-review";
    const selfReview = state.review && [state.review.assessmentAuthor, state.review.retestAuthor].includes(role.subject);
    fields(forms[2]).forEach((field) => { field.disabled = !reading || !role.approver || !pending || selfReview; });
    const fresh = state.evidence && state.review && state.evidence.domain === state.review.evidence.domain
      && state.evidence.evidenceDigest !== state.review.evidence.evidenceDigest
      && state.evidence.evidenceDigest !== state.review.retest?.evidence.evidenceDigest;
    fields(forms[3]).forEach((field) => {
      field.disabled = !writing || state.review?.state !== "accepted" || !fresh;
    });
    element("download").disabled = !reading || !state.review;
    element("history-load").disabled = !reading || !state.review;
    element("decision-help").textContent = selfReview
      ? "Another authenticated Approver must review your contribution."
      : "An Approver reviews the complete current assessment and any attached retest.";
    panel.setAttribute("aria-busy", String(state.busy));
  }
  function addStep(action = "", verification = "") {
    const steps = element("steps");
    if (steps.children.length >= 20) return;
    const number = ++state.stepSequence;
    const group = document.createElement("fieldset");
    group.append(node("legend", `Remediation step ${number}`));
    for (const [name, label, value] of [["action", "Action", action], ["verification", "Expected verification", verification]]) {
      const id = `review-step-${number}-${name}`;
      const title = node("label", label);
      title.htmlFor = id;
      const input = document.createElement("textarea");
      input.id = id;
      input.dataset.stepField = name;
      input.rows = 2;
      input.maxLength = 2000;
      input.required = true;
      input.value = value;
      group.append(title, input);
    }
    const remove = node("button", "Remove this step", "button button-quiet");
    remove.type = "button";
    remove.addEventListener("click", () => {
      if (steps.children.length <= 1) {
        status.textContent = "Keep at least one remediation step.";
        return;
      }
      group.remove();
      element("add-step").focus();
    });
    group.append(remove);
    steps.append(group);
    updateAccess();
  }
  function clear() {
    state.sequence += 1;
    state.busy = false;
    state.evidence = state.review = null;
    state.after = null;
    state.keys.clear();
    forms.forEach((form) => form.reset());
    element("lookup-form").reset();
    element("domain").value = "web";
    element("steps").replaceChildren();
    addStep();
    [source, list, detail, element("history")].forEach((item) => item.replaceChildren());
    element("workspace").hidden = true;
    source.hidden = true;
    status.textContent = "Connect, then load evidence or refresh the saved reviews.";
    updateAccess();
  }
  async function run(message, action) {
    if (!access().connected || state.busy) return;
    const sequence = ++state.sequence;
    const epoch = authEpoch();
    const current = () => sequence === state.sequence && epoch === authEpoch() && access().connected;
    state.busy = true;
    status.textContent = message;
    updateAccess();
    try {
      await action(current);
    } catch (error) {
      if (current()) {
        status.textContent = `${error instanceof Error ? error.message : "The request failed."} Retry the action, or reload the current review if it changed.`;
        announce("Human review action could not be completed.", "error");
      }
    } finally {
      if (current()) { state.busy = false; updateAccess(); }
    }
  }
  function evidenceView(value, historical) {
    const box = document.createElement("div");
    box.append(node("h4", `${value.domain.toUpperCase()} benchmark evidence`),
      node("p", `${historical ? "Stored verification" : "Verified now"}: ${value.verifiedAt}`),
      node("p", "This is a verified summary of a controlled benchmark. Raw requests, responses and private Ground Truth are not included."),
      node("p", `Evidence digest: ${value.evidenceDigest}`, "review-digest"));
    const projection = value.projection;
    if (value.domain !== "web") {
      const cases = document.createElement("ul");
      projection.cases.forEach((item) => cases.append(node("li", `${item.case.caseId}: ${item.comparisonState}`)));
      box.append(cases, node("p", `${projection.floor.requiredMetricCount} required checks; ${projection.floor.notApplicableMetricCount} not applicable.`));
    } else box.append(node("p", `Source Run: ${projection.sourceRunId}`));
    const disclosure = document.createElement("details");
    disclosure.append(node("summary", "Inspect measured summary and metrics"), node("pre", formatJson(projection)));
    box.append(disclosure);
    return box;
  }
  function showReview(raw) {
    const view = validateMeasuredReview(raw);
    state.review = view;
    forms.slice(1).forEach((form) => form.reset());
    element("lookup-id").value = view.reviewId;
    element("history").replaceChildren();
    const title = node("h3", view.title);
    title.tabIndex = -1;
    detail.replaceChildren(title,
      node("p", `${view.state === "accepted" ? "ACCEPTED" : "DRAFT"} · ${view.state} · revision ${view.revision}`, "review-state"),
      node("p", view.reviewId, "review-digest"),
      node("p", "This human report does not confirm a general vulnerability or authorize execution. Downloading it does not reverify stored evidence."),
      evidenceView(view.evidence, true));
    const assessment = view.assessment;
    element("steps").replaceChildren();
    state.stepSequence = 0;
    if (assessment) {
      detail.append(node("h4", "Human assessment"),
        node("p", `${view.assessmentAuthor} · ${assessment.severity} (human-assigned)`));
      for (const [label, key] of [["Impact", "impact"], ["Severity rationale", "severityRationale"], ["Known limitations", "limitations"], ["Retest plan", "retestPlan"]]) {
        detail.append(node("h5", label), node("p", assessment[key], "review-human-text"));
      }
      const steps = document.createElement("ol");
      assessment.remediation.forEach((step) => {
        const item = document.createElement("li");
        item.append(node("p", step.action, "review-human-text"), node("p", `Expected verification: ${step.verification}`, "review-human-text"));
        steps.append(item);
        addStep(step.action, step.verification);
      });
      detail.append(node("h5", "Remediation"), steps);
      for (const key of ["impact", "severity", "severityRationale", "limitations", "retestPlan"]) {
        forms[1].elements.namedItem(key).value = assessment[key];
      }
    } else addStep();
    if (view.retest) {
      detail.append(node("h4", "Attached retest"),
        node("p", `${view.retestAuthor} · ${view.retest.conclusion}`),
        node("p", `Change reference: ${view.retest.changeReference}`, "review-human-text"),
        node("p", view.retest.rationale, "review-human-text"),
        node("p", "Execution after remediation is not independently verified. The result does not automatically establish that a production issue was fixed."),
        evidenceView(view.retest.evidence, true));
    }
    if (view.decision) detail.append(node("h4", "Human review decision"),
      node("p", `${view.reviewer} · ${view.decision.decision} · revision ${view.revision}`),
      node("p", view.decision.reason, "review-human-text"));
    element("workspace").hidden = false;
    title.focus();
    updateAccess();
  }
  async function save(kind, path, payload, current) {
    const signature = JSON.stringify([path, payload]);
    let pending = state.keys.get(kind);
    if (!pending || pending.signature !== signature) {
      pending = { signature, key: `review-${globalThis.crypto.randomUUID()}` };
      state.keys.set(kind, pending);
    }
    const raw = await request(path, { method: "POST", body: JSON.stringify({ ...payload, requestKey: pending.key }) });
    if (!current()) return;
    const result = validateMeasuredReview(raw);
    // A duplicate returns its original revision; reopen the latest state before editing it.
    const latest = await request(`${BASE}/${result.reviewId}`);
    if (!current()) return;
    showReview(latest);
    status.textContent = "Saved. The current review and its retained history are available below.";
    announce("Human review saved.", "success");
  }
  function clearSelection() {
    state.review = null;
    forms.slice(1).forEach((form) => form.reset());
    detail.replaceChildren();
    element("history").replaceChildren();
    element("workspace").hidden = true;
    updateAccess();
  }
  async function loadList(after, current) {
    const raw = await request(BASE + (after ? `?after=${encodeURIComponent(after)}` : ""));
    if (!current()) return;
    if (!Array.isArray(raw?.items) || raw.items.length > 10
      || (raw.nextAfter !== null && !ID.test(raw.nextAfter))
      || raw.items.some((item) => !ID.test(item.reviewId) || typeof item.title !== "string" || !STATES.includes(item.state))) {
      throw new Error("Saved review list is not valid.");
    }
    const rows = raw.items.map((item) => {
      const row = document.createElement("li");
      const button = node("button", `${item.title} · ${item.state} · revision ${item.revision}`, "button button-quiet");
      button.type = "button";
      button.addEventListener("click", () => run("Loading saved review…", async (valid) => {
        clearSelection();
        const review = await request(`${BASE}/${item.reviewId}`);
        if (valid()) { showReview(review); status.textContent = "Saved review loaded."; }
      }));
      row.append(button);
      return row;
    });
    list.replaceChildren(...rows);
    state.after = raw.nextAfter;
    status.textContent = rows.length ? "Saved reviews loaded. Select a review to continue." : "No saved reviews. Load evidence to start one.";
  }
  element("load-source").addEventListener("click", () => run("Verifying the configured benchmark evidence…", async (current) => {
    state.evidence = null;
    source.replaceChildren();
    source.hidden = true;
    const domain = element("domain").value;
    const raw = await request(`/v1/measured-review-evidence/${domain}`);
    if (!current()) return;
    const evidence = validateReviewEvidence(raw);
    if (evidence.domain !== domain) throw new Error("Evidence domain differs from the selection.");
    state.evidence = evidence;
    source.append(evidenceView(evidence, false));
    source.hidden = false;
    status.textContent = "Evidence verified. An Operator can open a review or attach it to an accepted review as a retest.";
  }));
  element("domain").addEventListener("change", () => {
    state.evidence = null;
    source.replaceChildren(); source.hidden = true; updateAccess();
  });
  element("refresh").addEventListener("click", () => run("Loading saved reviews…", (current) => loadList(null, current)));
  element("more").addEventListener("click", () => run("Loading the next saved reviews…", (current) => loadList(state.after, current)));
  element("lookup-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const id = element("lookup-id").value.trim();
    if (!ID.test(id)) return;
    run("Loading saved review…", async (current) => {
      clearSelection();
      const raw = await request(`${BASE}/${id}`);
      if (current()) { showReview(raw); status.textContent = "Saved review loaded."; }
    });
  });
  forms[0].addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.evidence || !access().operator) return;
    const payload = { title: element("title").value, domain: state.evidence.domain, evidenceDigest: state.evidence.evidenceDigest };
    run("Opening review…", (current) => save("open", BASE, payload, current));
  });
  forms[1].addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.review || !access().operator) return;
    const values = Object.fromEntries(new FormData(forms[1]));
    const remediation = [...element("steps").children].map((group) => Object.fromEntries(
      [...group.querySelectorAll("textarea")].map((input) => [input.dataset.stepField, input.value]),
    ));
    const payload = { expectedRevision: state.review.revision, assessment: {
      ...values, remediation, evidenceDigest: state.review.evidence.evidenceDigest,
    } };
    run("Saving assessment…", (current) => save("assessment", `${BASE}/${state.review.reviewId}/assessment`, payload, current));
  });
  forms[2].addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.review || !access().approver) return;
    const payload = { ...Object.fromEntries(new FormData(forms[2])), expectedRevision: state.review.revision };
    run("Recording human review decision…", (current) => save("decision", `${BASE}/${state.review.reviewId}/decision`, payload, current));
  });
  forms[3].addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.review || !state.evidence || !access().operator) return;
    const payload = { ...Object.fromEntries(new FormData(forms[3])), expectedRevision: state.review.revision, evidenceDigest: state.evidence.evidenceDigest };
    run("Verifying and attaching the separate retest…", (current) => save("retest", `${BASE}/${state.review.reviewId}/retest`, payload, current));
  });
  element("add-step").addEventListener("click", () => {
    addStep();
    element("steps").lastElementChild.querySelector("textarea").focus();
  });
  element("history-load").addEventListener("click", () => run("Loading retained revision history…", async (current) => {
    const raw = await request(`${BASE}/${state.review.reviewId}/history`);
    if (!current()) return;
    if (!Array.isArray(raw) || raw.length > 200 || raw.some((row, index) => row.reviewId !== state.review.reviewId || row.revision !== index + 1)) {
      throw new Error("Retained history does not match this review.");
    }
    element("history").replaceChildren(node("pre", formatJson(raw)));
    status.textContent = "Retained commands include earlier, superseded assessments and decisions.";
  }));
  element("download").addEventListener("click", () => run("Preparing the current review report…", async (current) => {
    const id = state.review.reviewId;
    const markdown = await requestReport(`${BASE}/${id}/report.md`);
    if (!current()) return;
    const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url; link.download = `${id}.md`;
    document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    status.textContent = "Report downloaded with its exact revision and evidence limits.";
  }));
  clear();
  return { clear, updateAccess };
}
