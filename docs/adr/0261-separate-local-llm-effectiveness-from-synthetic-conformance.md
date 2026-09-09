# ADR-0261: Separate Local LLM Effectiveness from Synthetic Conformance

- Status: Accepted
- Date: 2026-09-07

## Context

AI-002 proves a bounded execution and evidence contract using deterministic targets. Its public
M03 marker detector does not by itself measure private-information exposure on actual language
models. Reusing that result as detection accuracy would conflate transport correctness, target
behavior, and the detector's judgment. The original Finding benchmark also lacks negative cases
and does not represent multiple target models as independent comparison axes.

## Decision

Implement EFFECT-001 as a separate, versioned local effectiveness evaluation. Freeze the existing
marker detector, a private-canary oracle, development/held-out split, source identities, two pinned
model artifacts, two policies, two sampling settings, and three seeds before any held-out request.
The complete comparison contains 24 fresh model runs and 384 isolated case requests. The oracle
does not consume the detector's decision or infer private exposure from a public marker.

Keep the registered Provider call, attenuated Capability, shared conservative model budget,
ToolGateway, secret lease, Docker Worker, egress proxy, and bound Provider outcome in the path.
Only the CLI operator's fixed disposable local endpoint is supported. Runtime observations and
cleanup are retained with raw Provider sources in sealed RunStore artifacts. A fresh reader
checks pinned roots and source bindings and recomputes confusion matrices, support, repetition
variation, timing, and scoped local cost. Missing and failed attempts cannot count as negatives
or yield a complete comparison. Do not issue Finding, Replay, SARIF, or further execution authority.

## Consequences

Synthetic AI-002 compatibility and its claim ceiling remain unchanged. EFFECT-001 measures a small
diagnostic corpus on declared model configurations; its project-held-out split does not establish
pretraining decontamination or population-level accuracy. Model token usage remains provider-
reported. Zero local marginal token price excludes unmeasured hardware, electricity, and storage.

Evidence integrity depends on the operator's pinned local roots and host observations. This is
not an independent measurement signature or protection against whole-host rollback. A consumed
local plan cannot silently resume or rerun after failure. A hard process/host failure can leave
an unsealed partial Run and owned resources; neither is a successful report. Subsequent recovery
work must preserve this distinction and target only the recorded ownership identities.

The implementation is additive. Existing CLI inputs, AI-002 readers, model Provider defaults,
and the legacy benchmark schema retain their current behavior.
