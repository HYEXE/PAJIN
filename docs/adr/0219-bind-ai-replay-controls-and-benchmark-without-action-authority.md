# ADR-0219: Bind AI Replay, Controls, and Benchmark without Action Authority

## Status

Accepted

## Context

AI-001C admits one neutral Observation from an already authorized and sealed REDTEAM Capability
Graph Run. Its consumed ActionPermit and Graph event are historical evidence, not authority to
execute another model request. PAJIN already has a separate KISA path that compiles fresh-session
Replay under bounded Capability authority, executes independent Baseline, Negative Control, and
Counterfactual requests, seals their receipts, and evaluates the complete evidence against the
AI-assessment Profile floor.

REDTEAM-002 also already registers the exact M03, M06, and A04 profile denominator, CAP-003 mapping,
CAP-006 Replay support, Ground Truth vocabulary, negative-control requirement, Replay requirement,
and aggregation contract. Reimplementing any of these mechanisms for the AI Domain would create
parallel authority, validation, and measurement models.

## Decision

Add one content-addressed AI-001D projection that reopens the exact AI-001C source/admission and
binds it to a separately sealed VAL-004A KISA assessment, the exact REDTEAM-002 Profile and
Capability contract, and the DOMAIN-006 AI `fresh-session-independent-replay` plan.

Require exact semantic equality of target, method, Tool, scenario, threat class, turns, and checks
between the admitted AI request and the KISA source. Require the admitted source, KISA source, two
Replay repetitions, and three Controls to use disjoint sessions and request identities. Require the
KISA Replay contract to be registered by CAP-006 for the exact REDTEAM Capability.

Do not convert this binding into a concrete Ground Truth case or benchmark measurement. The
independent KISA evidence may satisfy its own registered Profile floor, but it does not confirm the
AI Graph Observation or create a Finding. Keep all action and authority markers false.

## Consequences

- AI-001D demonstrates fresh-session Replay and independent Control evidence for the same bounded
  M03, M06, or A04 semantics without dispatching from Graph knowledge.
- Existing KISA Replay, Control, Profile-floor, REDTEAM benchmark, and DOMAIN registry identities
  remain authoritative and unchanged.
- The source AI session is explicitly included in the independence check rather than assuming that
  KISA's internal source isolation covers a different execution path.
- MCP remains outside this projection because REDTEAM-002 and CAP-006 register no MCP Replay or
  negative-control path.
- A future measurement adapter must still provide sealed raw observations and a concrete Ground
  Truth case before REDTEAM-002 can publish metrics.

## Rejected alternatives

### Reuse the AI-001C ActionPermit for Replay

Rejected because the Permit is one-use and consumed. Replay needs its own bounded authority and
cannot be authorized by Graph admission.

### Trust matching scenario or Tool labels

Rejected because Profile, Domain, MCP, Tool, and threat-class metadata are not authority. The
projection reconstructs code-owned contracts and exact-matches sealed semantic and session
coordinates.

### Treat VAL-004A floor satisfaction as AI Observation confirmation

Rejected because the KISA assessment belongs to a distinct Candidate and Claim lineage. Semantic
equivalence is useful validation evidence but cannot transfer confirmation or Finding authority.

### Emit a numeric AI benchmark result

Rejected because AI-001D does not admit concrete Ground Truth cases, policy-denial sources, or raw
measurement accounting. REDTEAM-002 remains the only aggregate measurement boundary.

## Compatibility and rollback

The new model and builder are additive. Existing AI, KISA, VAL, REDTEAM, DOMAIN, Graph, Permit,
Worker, Replay, Control, benchmark, and Finding wires remain unchanged. Rollback stops producing
the projection without rewriting sealed Runs, Graph events, or content-addressed records.

## Related documents

- [AI-001D contract](../benchmark/AI-001D-fresh-session-replay-controls-benchmark.md)
- [AI-001C contract](../graph/AI-001C-cross-surface-observation-evidence-admission.md)
- [VAL-004A contract](../orchestration/VAL-004A-kisa-profile-validation-evidence.md)
- [REDTEAM-002 contract](../benchmark/REDTEAM-002-initial-profile-benchmark.md)
- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0032](0032-fresh-capability-validation-controls.md)
- [ADR-0150](0150-evaluate-kisa-profile-floors-from-sealed-evidence.md)
- [ADR-0209](0209-measure-redteam-profiles-without-finding-authority.md)
- [ADR-0211](0211-register-domain-metrics-without-measurement-authority.md)
- [ADR-0218](0218-admit-ai-observations-without-tool-authority.md)
