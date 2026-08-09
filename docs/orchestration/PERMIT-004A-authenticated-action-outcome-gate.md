# PERMIT-004A: Authenticated General Attack Action Outcome Gate

- Status: Implemented
- Runtime API: `pajin.supervision.GeneralAttackActionOutcomeGate`
- Record API: `pajin.dev/general-attack-action-outcome-assessment/v1alpha1`
- Decision: [ADR-0131](../adr/0131-authenticate-sealed-action-results-before-oracle.md)

## Scope

PERMIT-004A is the first, no-write vertical slice of the PERMIT-004 side-effect, data-flow, and
cleanup boundary. It authenticates an already consumed PERMIT-003 action result before invoking
the current CAP-002 Result Normalizer, Success Oracle, or Cleanup Handler. A live
`GatewayOutcome`, raw `ToolResult`, raw `WorkerResult`, or consumed `ActionPermit` is not result
authority by itself.

The gate is additive and direct-call only. It does not dispatch a Gateway or Worker, prepare a
second `WorkerJob`, issue another ordinary ActionPermit, create a cleanup Permit, add a store, or
wire a default Supervisor workflow. SUP-007A now composes it after the existing Grant-bound Gateway
lifecycle and sealed Run evidence for an explicit T0/T1 no-write direct call.

## Required authority intersection

`GeneralAttackActionOutcomeGate.assess()` accepts the non-authoritative observation returned by
PERMIT-003 but does not accept a caller-selected Run path. Its constructor requires a deployment
`GeneralAttackActionOutcomeInputAuthority` that resolves the authoritative Run path, exact
pre-claim `CapabilityGraphRunAuditAnchor`, and actual Gateway `CapabilityGrant`. It performs this
order:

This provider is a deployment TCB. The gate removes caller path selection and detects content or
lineage divergence inside the resolved Run; it does not independently prove that a compromised or
misconfigured provider selected the deployment's canonical managed path. SUP-007A owns that mapping
for its direct-call path by deriving the Run from a deployment-managed root and the exact Envelope.

1. require a first dispatch with an exact `GatewayOutcome`; an exact retry with
   `dispatched=false` or a missing result is not assessable;
2. exact-rebuild the complete PERMIT-001/002 source through
   `verify_general_attack_compiled_intent()`;
3. resolve the current signed CAP-005 activation, re-run CAP-002 preparation, and exact-match the
   PERMIT-003 prepared request, release, activation set, Capability, request digest, and normalized
   parameter digest;
4. canonicalize the GRAPH proposal and consumed Permit, require the current GRAPH store to contain
   that exact Permit, and intersect every shared Campaign, Run, Envelope, Decision, Snapshot,
   Capability, Target, request, reservation, proposal, and dispatch field;
5. resolve and canonicalize the deployment-owned Run, anchor, and Grant; require exactly one
   anchor plus a seal covering it before the claim and intersect its Campaign digest, Run, Envelope, release set,
   activation set, and compiler identity with current authority;
6. load `evidence/{requestId}.json` itself with `load_verified_run_artifacts()`, using the Permit
   Run ID as the expected Run and a bounded artifact request;
7. reuse `reconcile_capability_dispatch()` and require exactly one sealed `claimed -> completed`
   lifecycle. `consumed-without-claim`, `claimed-outcome-unknown`, failed, cancelled, and expired
   lifecycles do not reach Oracle or cleanup code;
8. require the terminal event to bind the current activation, release, exact trusted Grant digest,
   exact Gateway outcome digest, Worker execution ID, policy/execution/result flags, and one exact
   evidence path;
9. parse the sealed evidence as strict duplicate-free UTF-8 JSON and exact-reconstruct its
   `ToolRequest`, `PolicyDecision`, pre-evidence `ToolResult`, safe Worker job metadata,
   `WorkerResult`, optional secret leases, artifact SHA-256, provenance, and seal coordinate;
   then require one matching sealed `worker.dispatched` audit, exact job metadata equality, and
   exact lease ID, binding, fingerprint, TTL, audience, Run scope, use, and revocation state;
10. call the current activated CAP-002 Result Normalizer and require it to reproduce the sealed
   pre-evidence `ToolResult` exactly. The final Gateway result may add only the one exact sealed
   evidence path;
11. bind the current Executor Adapter identity without calling `prepare()`, so outcome assessment
    cannot manufacture a second, non-authoritative Worker job;
12. classify transport observation from the Definition, dispatch-audit-bound Worker job metadata,
    and host-owned
    network-log trust flag; then invoke the current Success Oracle and Cleanup Handler; and
13. re-resolve the signed activation and authority set after those calls before emitting one
    content-addressed assessment.

## Side-effect and cleanup boundary

The current seven CAP-005 Capabilities declare only `none` or `read-only` side effects and
`cleanupRequired=false`. PERMIT-004A supports exactly that inventory. The assessment binds the
Definition side-effect ceiling but deliberately records `sideEffectAbsenceAttested=false`; static
metadata is not proof that an external Target was unchanged.

The current Cleanup Handler is still invoked through its registered identity and must return
`None`. A non-empty plan for a cleanup-not-required action fails closed. The assessment fixes
`cleanupPlanCreated`, `cleanupPermitIssued`, and `cleanupExecutionAuthorized` to false.

`reversible-write`, `irreversible-write`, and every `cleanupRequired=true` Definition are rejected.
They require a later typed cleanup request, separately domain-separated bounded one-shot cleanup
Permit, and aggregate Campaign budget accounting in the existing GRAPH durability domain. The
already consumed action Permit cannot be reinterpreted as cleanup authority.

## Data-flow boundary

PERMIT-004A records only a bounded transport observation. It does not claim semantic information
flow, exfiltration absence, or target-side effect attestation.

- A `network=none` Worker job must have no network log and cannot claim a trusted host log.
- An `egress-proxy` job requires `networkAccess=true` in the exact current Definition and
  `networkLogTrusted=true` from the host-owned Docker proxy boundary.
- The record binds whether a log was observed and its SHA-256, but fixes
  `informationFlowAttested=false` and `scopeExpansionAuthorized=false`.

This prevents an untrusted Worker transcript or static `networkAccess` flag from becoming a
semantic data-flow authority.

## Outcome record

`GeneralAttackActionOutcomeAssessment` binds the source intent and general proposal, GRAPH
proposal, consumed Permit and dispatch, exact deployment Run anchor, anchor event hash, and
pre-claim anchor seal root, verified
Run root, reconciliation and terminal event, trusted Grant digest, Gateway outcome digest, Worker
execution, exact activated Capability and release, the four outcome role bindings, expected
evidence types, sealed artifact coordinate, Success Oracle decision, side-effect ceiling, transport
observation, and cleanup-not-required result.

The record model alone is an output projection and its self-digest is not predecessor authority.
Consumers must call `GeneralAttackActionOutcomeGate.verify_assessment()` with the complete current
sources and trusted input authority; it exact-rebuilds the gate output and rejects any
self-consistent substitution. A verified record is not a Finding, replay authorization, ordinary
execution Permit, or cleanup Permit. It fixes finding authority, redispatch, Executor job binding,
write admission, cleanup plan creation, cleanup Permit issuance, and cleanup execution to false.

## Negative boundaries

The gate fails closed for:

- missing results, exact retries, missing or substituted stored Permits, and cross-action proposal,
  request, Campaign, Run, Snapshot, activation, release, or dispatch lineage;
- caller-selected Runs, resolved Runs with missing or divergent result evidence, missing,
  duplicated, late, or authority-divergent Run anchors, and substituted trusted Grants;
- incomplete, duplicated, non-completed, unsealed, or Permit-divergent dispatch audit;
- a forged live outcome, outcome digest, Worker execution identity, result identity, policy flag,
  Tool success flag, evidence path, or Grant digest;
- absent, mutated, oversized, malformed, duplicate-key, coercive, unsealed, cross-request, or
  cross-execution evidence and incomplete artifact provenance;
- missing, duplicated, or evidence-divergent `worker.dispatched` audit and substituted image,
  command, network, egress, limit, stdin, secret-request, or secret-lease metadata;
- a current Result Normalizer that differs from the sealed pre-evidence result, an Oracle or role
  identity that drifts, or activation drift during evaluation;
- network-disabled execution that claims egress, or network-enabled execution without both
  Definition permission and host-trusted proxy observation;
- write side effects, cleanup-required Definitions, or a Cleanup Handler that returns a plan
  without separate cleanup authority.

Predecessor, Run, dispatch, result, evidence, and role-identity authentication failures occur before
Success Oracle and Cleanup Handler invocation. `verify_assessment()` intentionally re-evaluates the
already authenticated current Oracle and Cleanup Handler before comparing the candidate projection;
therefore a projection-only substitution is rejected after those pure planning/evaluation calls.
Incomplete dispatch state remains manual-review-only under CAP-005 reconciliation and is never
converted into success, cleanup completion, or redispatch permission.

## Compatibility, migration, and rollback

The module, exports, input-authority interface, assessment wire, contract, and tests are additive.
Existing PERMIT-001/002/003,
CAP-001 through CAP-005, GRAPH-006, Gateway, Worker, Run, artifact, database, CLI, and workflow
formats are unchanged. No schema or data migration is required.

Rollback removes this gate and its consumers. Existing sealed Gateway audit and consumed Permits
remain immutable historical authority. Rollback must not make an incomplete or already consumed
action dispatchable again.

## Remaining boundary

PERMIT-004B1 supplies the separate typed cleanup request, pre-action cleanup budget hold, and
bounded one-shot CleanupPermit in the existing GRAPH authority. This no-write gate deliberately
remains unchanged. PERMIT-004B2 reuses its sealed result-authentication core for a
`reversible-write + cleanupRequired=true` path, exact-rebuilds the current Handler plan, proves an
exact pre-action hold, dispatches a distinct cleanup Capability, and authenticates restored state.
SUP-007A composes the existing PERMIT-003 callback, Grant, RunStore, Gateway, Worker, and this
post-dispatch gate without adding another execution authority. Its deployment ID, managed Run root,
Permit inputs, execution inputs, Gateway dependencies, and current activation remain explicit
deployment TCBs. SUP-007B exposes the zero-cost, non-networked, approval-free subset through the
Control Plane. SUP-008 adds the distinct approved profile and binds the durable APPROVAL-001A
receipt into the same outcome assessment while leaving T3+ and write closed.

## Related documents

- [PERMIT-003 contract](PERMIT-003-exact-single-use-action-permit.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [PERMIT-004B1 contract](PERMIT-004B1-pre-reserved-one-shot-cleanup-permit.md)
- [SUP-007A contract](SUP-007A-opt-in-general-attack-execution.md)
- [SUP-007B contract](SUP-007B-control-plane-general-attack-profile.md)
- [SUP-008 contract](SUP-008-approved-general-attack-control-plane-profile.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
