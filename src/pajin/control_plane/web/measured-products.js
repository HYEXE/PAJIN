import { formatJson, validateMeasuredBenchmarkProduct } from "./protocol.js";

const PRODUCTS = [
  ["network", "Network", "/v1/products/network-measured-service-identification"],
  ["ai", "AI", "/v1/products/ai-measured-system-prompt-disclosure"],
];

export function createMeasuredProductPanels({ document, request, isOperator, authEpoch, announce }) {
  const panels = PRODUCTS.map(([domain, title, endpoint]) => {
    const panel = document.querySelector(`#${domain}-measured-panel`);
    const button = document.querySelector(`#${domain}-measured-load`);
    const status = document.querySelector(`#${domain}-measured-status`);
    const result = document.querySelector(`#${domain}-measured-result`);
    const state = { sequence: 0, loading: false };
    const empty = () => {
      result.replaceChildren();
      result.hidden = true;
    };
    const clear = () => {
      state.sequence += 1;
      state.loading = false;
      panel.setAttribute("aria-busy", "false");
      button.disabled = !isOperator();
      status.textContent = isOperator()
        ? "Load the retained benchmark result to verify its evidence."
        : "Connect with an Operator credential to view this result.";
      empty();
    };
    button.addEventListener("click", async () => {
      if (!isOperator() || state.loading) return;
      const sequence = ++state.sequence;
      const epoch = authEpoch();
      const current = () => state.sequence === sequence && authEpoch() === epoch && isOperator();
      state.loading = true;
      button.disabled = true;
      panel.setAttribute("aria-busy", "true");
      status.textContent = "Verifying retained source, Replay, and cleanup evidence…";
      empty();
      try {
        const view = validateMeasuredBenchmarkProduct(await request(endpoint), domain);
        if (!current()) return;
        const summary = document.createElement("p");
        summary.textContent = `${view.cases.length} controlled case(s) · ${view.floor.requiredMetricCount} required checks passed · ${view.floor.notApplicableMetricCount} not applicable`;
        const cases = document.createElement("ul");
        view.cases.forEach((item) => {
          const row = document.createElement("li");
          const label = item.case.caseId.replace(/^(network|ai)-fixture:/, "").replaceAll("-", " ");
          row.textContent = `${label} — ${item.comparisonState.includes("negative") ? "negative control" : "expected result observed"}`;
          cases.append(row);
        });
        const metrics = document.createElement("dl");
        metrics.className = "measured-metrics";
        view.floor.observations.forEach((observation) => {
          const name = document.createElement("dt");
          name.textContent = observation.metric.metricId.split(".").at(-1).replaceAll("-", " ");
          const value = document.createElement("dd");
          value.textContent = observation.applicability === "not-applicable"
            ? "Not applicable"
            : `${formatJson(observation.numerator)} / ${formatJson(observation.denominator)} ${observation.unit}`;
          metrics.append(name, value);
        });
        const detail = document.createElement("details");
        const disclosure = document.createElement("summary");
        disclosure.textContent = `Show ${view.floor.observations.length} metrics`;
        detail.append(disclosure, metrics);
        result.append(summary, cases, detail);
        result.hidden = false;
        status.textContent = "Evidence verified for the controlled benchmark. This does not establish performance against real targets.";
        announce(`${title} benchmark evidence verified.`, "success");
      } catch (error) {
        if (!current()) return;
        empty();
        status.textContent = `Result unavailable: ${error instanceof Error ? error.message : "verification failed"}`;
        announce(`${title} benchmark result unavailable.`, "error");
      } finally {
        if (current()) {
          state.loading = false;
          panel.setAttribute("aria-busy", "false");
          button.disabled = false;
        }
      }
    });
    return {
      clear,
      updateAccess: () => {
        if (!isOperator()) {
          clear();
        } else {
          button.disabled = state.loading;
          if (!state.loading && result.hidden) {
            status.textContent = "Load the retained benchmark result to verify its evidence.";
          }
        }
      },
    };
  });
  return {
    clear: () => panels.forEach((panel) => panel.clear()),
    updateAccess: () => panels.forEach((panel) => panel.updateAccess()),
  };
}
