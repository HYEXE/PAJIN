# UX-008: Initial Red Team Product Flow Projection

## Purpose

Project the exact sealed REDTEAM-002 benchmark inputs into an initial read-only product flow with
separate Scope, Evidence, Finding, and report sections. The projection must make unavailable
authority visible instead of presenting a successful detection, Oracle result, Replay, or metric
as a confirmed Finding.

## API and artifact

- API: `pajin.dev/redteam-product-flow-projection/v1alpha1`
- Kind: `RedteamProductFlowProjection`
- Artifact: `redteam-product-flow-projection.json`
- Event: `product.redteam-flow.projected`

`RedteamProductFlowProjector` accepts the exact REDTEAM-002 Profile Set, aggregate outcome, and all
source Observation outcomes. Before writing anything, it calls the REDTEAM-002 verified loader,
which reopens the aggregate Run and every source Run. It then publishes one content-addressed
projection in a distinct sealed Run. `load_redteam_product_flow()` reopens the projection and all
predecessors and rebuilds the complete view before returning it.

## Product sections

### Scope

Each `RedteamProductScopeProjection` contains the exact REDTEAM product Profile identity, Profile
contract digest, ordered CAP-002 references, and source Observation count. It deliberately records:

- `scopeState=profile-bounded-campaign-scope-not-projected`;
- `campaignScopeAvailable=false`;
- `scopeAuthorized=false`; and
- `scopeExpanded=false`.

REDTEAM-002 does not carry a complete Campaign Scope or a registered mapping from REDTEAM product
Profiles such as `redteam-web-v1` to PROF-001 Campaign Profiles such as
`pajin.profile.bug-hunt`. UX-008 therefore does not manufacture either value.

### Evidence

Each `RedteamProductEvidenceProjection` is a content-free reference to one reverified sealed source
Observation. It retains the Observation and CAP-002 identities, source kind, Run root, artifact
path and digest, case counts, and Evidence completeness counts. It fixes
`sealedSourceVerified=true`, `evidenceContentIncluded=false`, and `observationIsFinding=false`.

The projection does not expose request bodies, prompts, responses, Worker transcripts, target
content, credentials, or raw Evidence bytes.

### Finding

Each Profile receives one explicit `RedteamProductFindingProjection` with:

- `findingState=not-confirmed-no-profile-validation-authority`;
- `validationFloorState=not-evaluated-redteam-profile-is-not-campaign-profile`;
- `confirmedFindingCount=0`;
- `campaignProfileMappingRegistered=false`;
- `validationFloorSatisfied=false`; and
- `findingConfirmed=false`.

This is not a negative security conclusion. It means REDTEAM-001/002 did not produce the separate
Campaign Profile binding, Replay and Control evidence assessment, Validation Decision, or Finding
authority required to confirm a Finding.

### Report

The exact `RedteamInitialBenchmarkReport` remains nested under a
`measurement-only-not-a-finding-report` state. Its detection, false-positive, Replay, cost,
Evidence, and policy-denial metrics remain available as measurement. Finding report availability,
external delivery authority, and confirmed Finding count remain false or zero.

## Authority boundary

Every projection records that the benchmark and sources were verified, the projection is
read-only, and Evidence content is redacted. It fixes all of the following to false:

- Campaign Profile mapping inference;
- Scope authority and Scope expansion;
- Validation authority;
- Finding authority;
- report delivery authority; and
- execution authority.

The wire contains no Capability activation, approval, Permit, Tool request, Gateway dispatch,
Worker job, Graph mutation, or external delivery instruction.

## Fail-closed cases

Publication or loading rejects:

- a missing, malformed, unsealed, or mutated aggregate or source Run;
- a source set, Profile Set, metric report, Observation digest, or source count mismatch;
- duplicate source Run identities or reuse of a predecessor Run for the projection;
- a measured time-to-first-valid-Finding value in the current REDTEAM-002 contract;
- a changed projection artifact or event payload;
- a forged content digest or identifier;
- boolean coercion on security-relevant markers; and
- any Scope, Validation, Finding, report-delivery, or execution authority escalation.

## Compatibility, rollback, and current limits

The projection is additive and direct-call only. REDTEAM-001A/B/C/D, REDTEAM-002, PROF-001,
VAL-002/003/004, generic Finding/reporting, Canonical Graph, Control Plane, and execution wires are
unchanged. Rollback removes the module, tests, contract, and ADR without rewriting predecessor or
projection Runs.

This initial slice does not provide a Control Plane HTTP endpoint or rendered Web Console panel. It
does not expose a complete Campaign Scope, evaluate a VAL-003 floor, create a Finding report,
authorize external delivery, or support arbitrary external Targets. Those capabilities require
separate registered inputs and authority decisions.

## Related documents

- [ADR-0210](../adr/0210-project-redteam-product-flow-without-finding-authority.md)
- [REDTEAM-002 contract](../benchmark/REDTEAM-002-initial-profile-benchmark.md)
- [VAL-003 contract](VAL-003-profile-assurance-floor.md)
- [PROF-001 contract](PROF-001-campaign-profile-authority.md)
