# DOMAIN-005: Cross-domain Graph Admission

- Status: Implemented, bounded knowledge-admission path
- Contract versions:
  - `pajin.dev/cross-domain-graph-producer-contract/v1alpha1`
  - `pajin.dev/cross-domain-graph-admission-candidate/v1alpha1`
  - `pajin.dev/cross-domain-graph-admission/v1alpha1`
- Decision: [ADR-0205](../adr/0205-admit-cross-domain-knowledge-without-scope-expansion.md)

## Scope

DOMAIN-005 adds the first code-registered cross-domain knowledge producer. One already admitted,
sealed `ai.behavior-observation` may propose either a `web.http-operation` Surface through
`discovers` or a `web.security-property` Hypothesis through `enables`. Both proposals re-enter the
existing `GraphAdmissionAuthority`, append-only Event Log, Projection, and Snapshot path.

This is one exact AI-to-Web bootstrap, not a general nine-domain runtime. It does not implement an
AI or Web locator, extract an endpoint from arbitrary model output, activate a Capability, execute
a Tool, select a Worker, or test the admitted knowledge. Other domain pairs remain planned until a
separate code-owned producer and vertical-slice evidence are added.

## Code-owned producer contract

`CrossDomainGraphProducerContract` binds all of the following by exact ID, version, and digest:

- the DOMAIN-002 AI source type-set and `ai.behavior-observation` source semantic;
- the DOMAIN-002 Web target type-set, Surface, locator, and Hypothesis semantics;
- the producer `pajin.graph.cross-domain.ai-to-web-knowledge@1.0.0`; and
- only `SurfaceProposal` and `HypothesisProposal` output kinds.

The contract cannot be relabeled to another Domain, widened to another Proposal kind, resolved by
alias, or used as execution authority. `cross_domain_graph_producer_registration()` returns the
exact existing Graph producer registration required by the single writer.

## Source and Snapshot verification

`CrossDomainGraphAdmissionGate` accepts a full immutable Graph Snapshot and one exact source
`GraphAdmissionEvent`. Before compiling a candidate it:

1. canonically revalidates the Snapshot and source event;
2. rebuilds the Snapshot projection from the same Event Log prefix;
3. requires the Snapshot to be the current head during candidate preparation;
4. requires the exact source event to exist in that prefix;
5. requires one admitted `ObservationProposal` with the registered AI Observation type; and
6. preserves its Campaign, request, Capability or ActionPermit, source-root, and Evidence lineage.

Admission then calls `GraphAdmissionAuthority.submit_if_current`. A concurrent head change becomes
the existing audited `stale-snapshot` rejection. Exact retry returns the prior semantic attempt and
does not append another event or execute an Action.

The source Capability Grant or ActionPermit copied into the derived Graph event is provenance for
the Observation and Evidence only. It is not authority for the target Surface or Hypothesis.

## Knowledge-only projection

Every candidate fixes `targetKnowledgeState=registered-not-authorized` and
`sourceAuthorityProvenanceBound=true`. The following markers are literal false:

- Campaign mutation and Scope expansion;
- Capability activation and budget or egress changes;
- credential use and Worker selection;
- approval satisfaction and Permit issuance;
- source authority transfer; and
- execution authorization.

The admitted `GraphSurface` and `GraphHypothesis` remain the unchanged Graph v1alpha1 nodes. They do
not gain Domain, Scope, Capability, Permit, Worker, credential, or execution fields. Domain meaning
is bound in the additive candidate/projection contract, so existing Graph identities and readers
remain compatible.

A later action against the Surface still requires a new Proposal from a current Snapshot, Campaign
Scope intersection, exact registered and activated Capability release, Policy and approval where
required, a new single-use ActionPermit, Gateway re-entry, and the exact deployment-owned Worker.

## Fail-closed cases

Positive and adversarial tests cover:

- AI Observation to Web Surface `discovers` and Web Hypothesis `enables` in one Canonical Graph;
- exact producer, DOMAIN-001 classification, DOMAIN-002 type-set, Snapshot, Campaign, source event,
  lineage, relation, and target semantic binding;
- stale Snapshot rejection and exact-retry idempotency;
- unregistered or substituted producer identity and Domain relabeling;
- foreign-Campaign, missing, or wrongly classified source Observation;
- target authority-marker escalation and boolean coercion; and
- source ActionPermit preservation as provenance while transfer and execution stay false.

## Implemented versus planned

Implemented:

- one exact AI-to-Web producer contract;
- Snapshot-prefix and source Observation re-verification;
- Web Surface and Hypothesis candidate compilation;
- admission through the existing single writer; and
- content-addressed knowledge-only admission proof and adversarial tests.

Contract or scaffold only:

- the registered locator and semantic IDs classify the target material but do not locate or test a
  real Web endpoint;
- the direct gate is not yet exposed through a Control Plane API or Campaign orchestrator; and
- the admission projection is not an execution-authority input.

Planned:

- additional explicitly reviewed domain-pair producers;
- producer-specific sealed extraction and normalization adapters;
- DOMAIN-006 validation, replay, and benchmark measurements; and
- Web and AI vertical slices that can independently validate the admitted knowledge.

## Compatibility and rollback

DOMAIN-005 is additive. It changes no Graph v1alpha1 node, edge, Proposal, Event Log, Projection,
Snapshot, Campaign, Scope, Capability, Permit, Gateway, Worker, Evidence, Replay, Finding, REDTEAM,
or PENTEST identity. Existing Graph stores require no migration.

Rollback stops registering and calling the producer and removes this optional adapter, exports,
tests, and contract. Already admitted canonical knowledge and its evidence lineage remain valid.
