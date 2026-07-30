# ORCH-002: Deterministic Two-to-Three-Wave Baseline

- Status: Implemented
- Contract version: `pajin.dev/deterministic-multi-wave/v1alpha1`
- Decision: [ADR-0066](../adr/0066-deterministic-two-three-wave-orchestration.md)

## Scope

ORCH-002 extends the existing A5 bounded replanning path from a fixed two-wave slice to a
deterministic baseline of at most two or three Hypothesis waves. An admitted Observation can select
one code-registered transition whose exact next Compiler state produces the next Plan. ORCH-002
does not add a Supervisor, alter the existing one-time Campaign Planner, or grant new Scope,
Capability, Tool, method, risk, budget, or egress authority.

## Threat model and trust boundary

The boundary assumes a caller may attempt to:

- replay a previously valid Compiler state to create a repeated wave;
- configure an `A -> B -> A` transition cycle;
- substitute a different Compiler or rule set after a decision;
- reuse a valid Hypothesis Wave from another Surface Snapshot or Campaign authority;
- mutate Campaign Scope while retaining an authority digest;
- omit or alter an ORCH-001 Plan or Task binding; or
- exceed the configured wave, replan, shared budget, or rate limits.

The trusted inputs are the exact Campaign manifest, the initial sealed Hypothesis Wave, the
revision-1 ORCH-001 Surface Snapshot, code-registered Observation rules and transitions, configured
follow-up Compiler states, and a runtime-owned `BoundedReplanningPolicy`.

## Authority contract

`DeterministicMultiWaveAuthority` binds:

- the complete Campaign manifest, including Scope, authorization, rules of engagement, and budgets;
- the exact ORCH-001 `SurfaceSnapshotAuthority`;
- a policy of `maxWaves=2, maxReplans=1` or `maxWaves=3, maxReplans=2`;
- every eligible Compiler's deterministic preview, including Compiler/rule identity, Hypothesis
  Set ID, Wave Plan ID, and the complete ORCH-001 Plan with its digest;
- the complete sorted Observation-rule set; and
- the complete sorted transition set.

The authority has a domain-separated `authorityDigest` and content-addressed `authorityId`.
Transitions must target one configured Compiler state with exact rule equality. Every follow-up
rule and transition source rule must have one Observation authority. Preview compilation performs
no capability issuance or Tool dispatch and must consume the original Campaign and Surface
Snapshot.

Each `ReplanDecision` binds the authority ID and digest, current Observation Graph Snapshot,
candidate Plan-state digest, transition, novelty result, completed wave count, and replan count.
The Plan-state digest includes the exact Surface Snapshot ID, revision, and digest as well as the
Compiler and rule set.

## Execution

1. Replanning reloads and integrity-verifies the initial sealed Hypothesis Wave, including
   `surface-bound-plan.json`, its terminal state, compiled/completed audit fields, and the in-memory
   outcome.
2. It creates and seals `deterministic-multi-wave-authority.json`.
3. Each completed wave promotes exact Tool results into an append-only Observation Graph.
4. Only Observations admitted from the current wave may select the next transition.
5. Before each decision, the complete Multi-wave authority is reconstructed and compared exactly.
6. A selected transition identifies one pre-bound full ORCH-001 Plan and dispatches the exact
   configured Compiler with the original Campaign and Recon authority.
7. The returned wave is accepted only when its Compiler/rules, fresh Run ID, and complete ORCH-001
   Surface Snapshot, Hypothesis Set, Wave Plan, and Plan digest equal the decision authority.
8. The Observation Graph records the ordered ORCH-001 Plan digest for every completed wave.

The first `next_wave` outcome remains available for A5 callers. ORCH-002 adds the complete
`follow_up_waves` tuple and the Multi-wave authority to the outcome.

## Stop and negative boundaries

The runner stops without another dispatch when:

- no registered transition matches the current wave;
- the candidate state equals the current state (`repeated-state`);
- the candidate state equals an earlier non-current state (`cycle-detected`);
- novelty is below the policy threshold; or
- the exact two- or three-wave limit has been reached.

It fails closed for ambiguous transitions, Compiler/rule drift, Campaign or Surface Snapshot
replacement, retained-digest Scope expansion, missing ORCH-001 artifacts or audit fields,
cross-Run outcome substitution, malformed policy limits, and shared budget/rate-limit exhaustion.

## Audit artifacts and events

The sealed replanning Run preserves:

- the legacy Campaign, policy, Observation-rule, transition, graph, and decision artifacts;
- additive `deterministic-multi-wave-authority.json`;
- ordered `surfaceBoundPlanDigests` in each new graph snapshot;
- authority ID/digest and state digest in every new decision;
- `discovery.multi-wave.authority-bound`;
- one `discovery.replan.wave-dispatched` per accepted transition; and
- final authority, Snapshot, Plan-digest, wave, replan, and follow-up Run lineage.

## Compatibility, migration, and rollback

The existing `pajin.dev/discovery-replanning/v1alpha1` classes and `next_wave` outcome remain
available. The default constructor path remains two waves with one `next_wave` runner. Legacy
Observation Graphs without `surfaceBoundPlanDigests` and legacy Decisions without Multi-wave
authority fields retain their v1 identity calculation and remain readable.

Three-wave execution is opt-in through `next_waves` and a `maxWaves=3, maxReplans=2` policy.
Rollback disables the three-wave configuration and returns to the default two-wave path. Sealed
ORCH-002 Runs remain immutable and must not be reinterpreted as legacy unbound execution.

## Verification and benchmark impact

Positive tests require an admitted Observation to change the Tool Plan in both follow-up waves,
with three distinct sealed wave Runs and one ordered ORCH-001 Plan digest per graph revision.
Negative tests cover repeated intermediate state, `A -> B -> A` cycle detection before third-wave
dispatch, retained-digest Scope expansion, forged sealed outcomes, ambiguous transition, and
cumulative budget limits.

ORCH-002 provides the deterministic 2-3 wave candidate required by the architecture benchmark. It
does not claim benchmark superiority or complete the Thin Walking Skeleton; measured yield, cost,
latency, variance, and chain completion remain BENCH and WALK work.
