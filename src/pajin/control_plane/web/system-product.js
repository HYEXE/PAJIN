const CAMPAIGN = /^[a-z0-9][a-z0-9-]{2,79}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const RUN = /^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$/;

export function validateSystemProduct(view, campaign) {
  const validRun = (value) => {
    if (value === null) return;
    if (!value || !RUN.test(value.run?.run_id) || !DIGEST.test(value.run?.root_digest)
      || typeof value.workerExecuted !== "boolean" || typeof value.complete !== "boolean"
      || !["absent", "present", "unknown", "not-created"].includes(value.cleanup)) {
      throw new Error("System Run does not match the read contract.");
    }
    if (value.distribution !== null) {
      const distribution = value.distribution;
      if (!DIGEST.test(distribution?.fileSha256) || !Number.isInteger(distribution.fileBytes)
        || distribution.fileBytes < 1 || distribution.fileBytes > 8192
        || ["ID", "VERSION_ID", "PRETTY_NAME"].some((key) => {
          const text = distribution.metadata?.[key];
          return typeof text !== "string" || !text.length || text.length > 1024 || /[\x00-\x1f]/.test(text);
        })) throw new Error("System distribution does not match the read contract.");
    }
    if (value.complete && (!value.workerExecuted || value.distribution === null || value.cleanup !== "absent")) {
      throw new Error("System completion has no verified result and cleanup.");
    }
  };
  if (!view || view.version !== "pajin.sys-003.operator-read/v1" || view.campaignId !== campaign
    || !CAMPAIGN.test(view.campaignId) || !["empty", "verified", "incomplete"].includes(view.state)
    || view.evidenceVerified !== (view.state !== "empty") || view.readOnly !== true
    || view.findingAuthority !== false || view.generalSystemSupport !== false || view.executionAuthorized !== false
    || ![true, false, null].includes(view.distributionMatch)) {
    throw new Error("System response does not match the selected Campaign or read contract.");
  }
  validRun(view.source); validRun(view.replay);
  if ((view.source === null) !== (view.state === "empty")
    || (view.source === null && view.replay !== null)
    || (view.replay === null && view.distributionMatch !== null)
    || (view.replay && view.source.run.run_id === view.replay.run.run_id)
    || (view.state === "verified" && (!view.source.complete
      || (view.replay && (!view.replay.complete || view.distributionMatch !== true))))) {
    throw new Error("System result state contradicts its retained evidence.");
  }
  return view;
}

export function createSystemProductPanel({ document, request, isOperator, authEpoch, announce }) {
  const element = (name) => document.querySelector(`#system-product-${name}`);
  const panel = element("panel"), form = element("form"), campaign = element("campaign");
  const button = element("load"), status = element("status"), result = element("result");
  let sequence = 0, loading = false;
  const node = (tag, text) => {
    const value = document.createElement(tag);
    value.textContent = text;
    return value;
  };
  function clear() {
    sequence += 1; loading = false;
    panel.setAttribute("aria-busy", "false");
    button.disabled = !isOperator(); campaign.disabled = !isOperator();
    result.replaceChildren(); result.hidden = true;
    status.textContent = isOperator()
      ? "Enter the configured Campaign to read its retained System result."
      : "Connect with an Operator credential to view this result.";
  }
  campaign.addEventListener("input", clear);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!isOperator() || loading || !CAMPAIGN.test(campaign.value.trim())) return;
    const selected = campaign.value.trim(), epoch = authEpoch(), requestSequence = ++sequence;
    const current = () => sequence === requestSequence && epoch === authEpoch() && isOperator();
    loading = true; button.disabled = true; panel.setAttribute("aria-busy", "true");
    result.replaceChildren(); result.hidden = true;
    status.textContent = "Verifying the pinned source and separately approved replay…";
    try {
      const raw = await request(`/v1/campaigns/${encodeURIComponent(selected)}/products/system-os-release`);
      if (!current()) return;
      const view = validateSystemProduct(raw, selected);
      if (view.state === "empty") {
        status.textContent = "No retained System result is configured for this Campaign.";
        return;
      }
      for (const [label, value] of [["Source", view.source], ["Replay", view.replay]]) {
        if (value === null) continue;
        const article = document.createElement("article");
        article.append(node("h3", label), node("p", `Run: ${value.run.run_id}`));
        if (value.distribution) {
          const metadata = value.distribution.metadata;
          article.append(node("p", metadata.PRETTY_NAME), node("p", `${metadata.ID} · ${metadata.VERSION_ID}`));
        } else article.append(node("p", "No authenticated OS result was obtained."));
        article.append(node("p", `Worker ${value.workerExecuted ? "executed" : "did not execute"} · cleanup ${value.cleanup} · ${value.complete ? "complete" : "incomplete"}`));
        const details = document.createElement("details");
        details.append(node("summary", `Show ${label.toLowerCase()} evidence digests`), node("p", `Run root: ${value.run.root_digest}`));
        if (value.distribution) details.append(node("p", `File SHA-256: ${value.distribution.fileSha256} · ${value.distribution.fileBytes} bytes`));
        article.append(details); result.append(article);
      }
      result.append(node("p", view.replay === null ? "No replay is configured."
        : view.distributionMatch === true ? "Separately approved source and replay observed the same distribution file."
          : "A complete source/replay comparison is unavailable."));
      result.hidden = false;
      status.textContent = view.state === "verified"
        ? "Retained evidence verified. This describes the completed isolated Linux read."
        : "Evidence integrity verified, but the recorded execution or cleanup is incomplete.";
      announce("System result loaded.", view.state === "verified" ? "success" : "neutral");
    } catch (error) {
      if (!current()) return;
      result.replaceChildren(); result.hidden = true;
      status.textContent = `Result unavailable: ${error instanceof Error ? error.message : "read failed"}`;
      announce("System result unavailable.", "error");
    } finally {
      if (current()) { loading = false; panel.setAttribute("aria-busy", "false"); button.disabled = false; }
    }
  });
  clear();
  return { clear, updateAccess: () => { if (!isOperator()) clear(); else {
    button.disabled = loading; campaign.disabled = false;
    if (!loading && result.hidden) status.textContent = "Enter the configured Campaign to read its retained System result.";
  } } };
}
