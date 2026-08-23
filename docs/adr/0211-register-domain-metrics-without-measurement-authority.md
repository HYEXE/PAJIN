# ADR-0211: Register Domain Metrics without Measurement Authority

## Status

Accepted

## Context

BENCH-001 has a stable twelve-metric Finding-oriented wire. REDTEAM-002 is a separate additive
contract for the exact REDTEAM-001 Profiles and already distinguishes measured zero from an
unavailable semantic denominator. Extending PAJIN to nine Security Domains requires shared
comparison terms, but not every domain has exploit Findings or the same cost and cleanup model.

In particular, a read-only forensic parser should be evaluated by artifact coverage, parsing
accuracy, provenance preservation, corrupted-input behavior, and deterministic or independent
re-analysis. Forcing it into exploit Finding recall would misstate the product. Conversely, a
Domain label or registered metric must not activate a Target Factory, select a Worker, satisfy a
Replay floor, or establish detection quality.

## Decision

Add a content-addressed DOMAIN-006 registry containing:

- thirteen common metric definitions with exact unit and aggregation semantics;
- thirteen exact domain-specific metric definitions bound to DOMAIN-001 classifications;
- one plan per Security Domain with an exact Replay or re-analysis strategy; and
- explicit `required` or `not-applicable` applicability with a code-owned N/A reason.

The registry binds the current BENCH-001 and REDTEAM-002 API versions and metric orders but does not
change either wire. It has no numeric observation fields. Zero is never used to represent a missing
denominator.

The Forensics plan uses task success instead of exploit detection recall, false-positive rate, or
precision and adds four analysis-specific metrics. Request units and monetary cost are required
only where their initial domain plan has a semantic denominator. Cleanup is N/A for every read-only
first slice; later active slices require a versioned plan.

The registered strategy is a future validation requirement, not evidence that Replay or
deterministic re-analysis occurred. Metric, plan, and registry objects explicitly deny measurement,
detection-quality, runtime-support, validation-floor, Finding, Target Factory, activation, Permit,
and execution authority.

## Consequences

- Domain vertical slices can share comparison vocabulary without creating a parallel benchmark
  engine or changing existing benchmark artifacts.
- Domain-specific accuracy and provenance metrics remain explicit and reviewable.
- Consumers must separately admit Ground Truth and raw measurement evidence before publishing a
  result.
- Profile validation floors remain Profile-owned and cannot be inferred from Domain plans.
- Domain metadata still cannot select a Capability, Tool, Worker, Scope, Permit, or Target Factory.

## Rejected alternatives

### Extend BENCH-001 in place

Rejected because its fixed order and artifact readers are compatibility boundaries.

### Treat REDTEAM-002 as the universal domain benchmark

Rejected because it is intentionally bound to REDTEAM-001A through REDTEAM-001D and their exact
Ground Truth and Replay paths.

### Use zero for unavailable metrics

Rejected because zero is a measured outcome, while lack of a semantic denominator is not a
measurement.

### Infer metric applicability from Domain or Tool metadata at runtime

Rejected because mutable metadata is neither Ground Truth nor validation or execution authority.

### Register a strategy as proof of Replay

Rejected because a requirement cannot substitute for independently admitted Replay or re-analysis
Evidence.

## Compatibility and rollback

The registry and references are additive. Removing DOMAIN-006 consumers leaves BENCH-001,
REDTEAM-002, Target Factory, Replay, validation, Finding, Capability, Graph, and Permit readers
unchanged. A future metric, applicability, or active-slice change requires a new versioned registry
or plan rather than silent mutation.

## Related documents

- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [BENCH-001](../benchmark/BENCH-001-benchmark-contract.md)
- [REDTEAM-002](../benchmark/REDTEAM-002-initial-profile-benchmark.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0209](0209-measure-redteam-profiles-without-finding-authority.md)
