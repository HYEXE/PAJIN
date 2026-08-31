# UX-009A: Sealed Measured Web Product Flow Projection

## Purpose

Project one exact, contextually reverified WEB-002D controlled-validation authority into a
content-addressed, read-only Operator product shape. The projection exposes only the measured-case
boundary, content-free Evidence references, public validation-floor metrics, the bounded
`benchmark-ground-truth-match` Finding, and an explicit unavailable report state.

UX-009A is not a new Web runtime. It performs no Target, provider, Docker, Worker, network,
credential, Graph, report, or external-system action, and it does not infer a Campaign Scope or
Campaign Profile.

## API, artifact, and event

- API: `pajin.dev/web-measured-product-flow-projection/v1alpha1`
- Kind: `WebMeasuredProductFlowProjection`
- Artifact: `web-measured-product-flow-projection.json`
- Event: `product.web-measured-flow.projected`

`WebMeasuredProductFlowProjector.project()` accepts one exact
`WebControlledValidationAuthorityOutcome` plus a complete
`WebMeasuredProductSourceReopenContext`. Before creating the product Run, it invokes the exact
`load_web_controlled_validation_authority()` path with the measured case, private Ground Truth
profile, source reopen context, floor and Finding mapping, route trust anchor and claim ledger,
Target journal, provider, adapter, and denial route authority.

The projector writes one canonical JSON artifact to a distinct sealed Run with exactly these
events:

1. `campaign.started`;
2. `product.web-measured-flow.projected`; and
3. `campaign.completed`.

It immediately reopens that Run before returning. `load_web_measured_product_flow()` repeats the
exact WEB-002D contextual load before reading the product artifact, verifies Run integrity and the
event payloads, parses strict JSON, rebuilds the complete projection from the reverified source,
and requires canonical bytes and object equality.

## Product sections

### Scope

`WebMeasuredProductScopeProjection` carries only the exact measured-case and source-measurement
references. It fixes:

- `scopeState=measured-case-bounded-campaign-scope-unavailable`;
- `campaignScopeAvailable=false`;
- `scopeExpanded=false`; and
- `profileInferred=false`.

The WEB-002D measured case is not promoted into a complete Campaign Scope, and no product Profile
is inferred from a Domain label or Finding.

### Evidence

`WebMeasuredProductEvidenceProjection` carries the floor-evaluation and Finding references, the
digest-bound denial-Control Observation reference, and the exact public requirement counts:

- six source Evidence requirements;
- ten controlled-validation Evidence requirements;
- `denialControlSatisfied=true`; and
- `targetCleanupVerified=true`.

The state is `content-free-authority-references-verified`. Raw Evidence, SARIF, the controlled
query, response body, transcript, route details, private expected reference, private Ground Truth,
and filesystem coordinates are absent.

### Floor

`WebMeasuredProductFloorProjection` contains the exact floor-policy, projection-policy, and
evaluation references plus all fourteen public `WebBenchmarkMetricObservation` values. Exactly
eleven metrics are required and three are not applicable. It fixes
`floorState=satisfied-independent-controlled-validation`, preserves the satisfied denial and
cleanup markers, and records `benchmarkValidationFloorSatisfied=true`.

These are the public rational values already recomputed by WEB-002D. UX-009A does not rerun the
probe, private matcher, Target, Worker, or provider.

### Finding

`WebMeasuredProductFindingProjection` retains the exact WEB-002D Finding, evaluation,
projection-policy, and source-measurement references. Its maximum claim is:

- `claimCeiling=benchmark-ground-truth-match`;
- `findingState=confirmed-benchmark-ground-truth-match-only-impact-and-severity-not-evaluated`;
- `impactAssurance=not-evaluated-information-only`;
- `severityAssurance=not-evaluated-information-only`;
- `benchmarkGroundTruthMatchConfirmed=true`; and
- `productFindingConfirmed=true`.

`genericProductionVulnerabilityConfirmed` and `negativeSecurityConclusionAuthorized` remain
false. The Finding is valid only for the exact bounded benchmark case and is neither a production
vulnerability conclusion nor a negative security conclusion.

### Report

`WebMeasuredProductReportProjection` fixes
`reportState=unavailable-bounded-finding-not-report-authority`. Report availability, creation,
delivery, and external delivery are all false. UX-009A does not serialize a report body or create a
reporting instruction.

## Authority boundary

Every projection records that the source authority was contextually verified, the projection is
read-only, and Evidence content is redacted. It also fixes all of the following absent:

- a WEB-002C Graph Hypothesis as a causal predecessor;
- Campaign Scope availability or expansion and Profile inference;
- private Ground Truth, expected reference, raw SARIF, controlled query, response body,
  transcript, raw Evidence, route details, or filesystem coordinates;
- Graph content or mutation;
- report creation, delivery, or external delivery;
- Capability activation, Permit issuance, route reuse, or additional execution;
- Target, provider, Docker, Worker, network, credential, or external-system side effects; and
- HTTP or UI entrypoints.

WEB-002C remains an independent neutral knowledge-admission branch. UX-009A derives only from the
exact WEB-002D authority and does not require or consume a Graph predecessor.

## Fail-closed cases

Publication or loading rejects:

- an incomplete or substituted WEB-002D reopen context;
- a missing, malformed, unsealed, mutated, or non-canonical product Run;
- product/source Run identity reuse;
- a changed artifact path, event sequence, event payload, source Run, authority ID, or digest;
- disagreement among measured-case, source, floor, Finding, denial, cleanup, or projection-policy
  references;
- a metric count, applicability count, identity set, Evidence count, claim ceiling, impact, or
  severity mismatch;
- a forged flow ID or digest;
- duplicate-key or oversized JSON;
- boolean coercion on security-relevant markers; and
- any Scope, Profile, Graph, report, disclosure, route-reuse, execution, side-effect, HTTP, or UI
  authority escalation.

The exact source loader runs before product publication and before product reload. A valid outer
artifact cannot compensate for a stale, substituted, or unverifiable WEB-002D predecessor.

## Compatibility, rollback, and current limits

UX-009A is additive and direct-call only. It does not change WEB-002A/B/C/D, REDTEAM, DOMAIN,
Canonical Graph, Capability, Permit, Gateway, Worker, reporting, or Control Plane wire formats.
Rollback stops new publication and loading of this additive API while retaining the accepted ADR,
this contract, every predecessor Run, and every already sealed product Run as historical records.

There is no deployment-owned product registry, resolver, HTTP endpoint, or Web Console in this
slice. Callers still possess the complete reopen context. UX-009B must introduce the separate
deployment-pinned reader boundary before any Control Plane or UI work.

## Related documents

- [ADR-0257](../adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)
- [WEB-002C contract](../graph/WEB-002C-sealed-zap-source-knowledge-admission.md)
- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
