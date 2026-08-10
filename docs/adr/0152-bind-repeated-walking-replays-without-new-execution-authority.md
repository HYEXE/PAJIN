# ADR-0152: Bind Repeated WALK Replays without New Execution Authority

- Status: Accepted
- Date: 2026-08-10

## Context

VAL-004C must satisfy the VAL-002 `repeated-controlled-validity-replay` requirement for a VAL-001
WALK validity Claim. VAL-004B already verifies the exact source execution, one WALK-005B2 Replay and
three stateless Controls, but it correctly refuses to count a Control execution as a Replay.

WALK-005B1 is a deterministic, non-executable Plan for the exact source Claim, Tool, target, method
and normalized arguments. WALK-005B2 owns the actual execution boundary: every completed Replay has
its own pre-dispatch approval receipt, request, Grant, Permit, dispatch, Worker result, execution Run,
evidence and sealed publication. The Plan does not contain a reusable approval or a dispatch token.

Creating a second planner, dispatcher or Replay store for VAL-004C would duplicate authority that
WALK-005B1/B2 already owns. Treating the two independently sealed WALK-005B2 authorities as repeated
evidence without cross-checking them would still permit replay or Control lineage reuse.

## Decision

1. Reuse one exact WALK-005B1 Plan for both repetitions. The Plan fixes request semantics but grants
   no execution authority; each WALK-005B2 repetition must still carry its own exact approval and
   execution authority.
2. Add an explicit VAL-004C module rather than changing the VAL-001 or VAL-004B wires.
3. Verify the existing VAL-001 authority against the primary sealed WALK-005B2 outcome and compile a
   second VAL-001 authority from the same exact Chain and an additional sealed WALK-005B2 outcome.
4. Require the two VAL-001 authorities to retain the same Campaign, Chain, validity Claim, source
   execution and complete WALK-005B1 Plan. The first Replay remains the exact VAL-004B Control anchor.
5. Record exactly two Replay repetitions. Do not accept a Control, Retest, unsealed execution or
   structurally similar artifact as a repetition.
6. Require source and both Replay executions to be pairwise distinct across Run/root, execution,
   request, Grant, Permit, dispatch, approval, Worker and Run-qualified evidence coordinates.
7. Require both Replay publication Runs, roots, artifact references and authority digests to be
   distinct.
8. Retain `sessionPolicy=stateless` and the exact one-field `text` arguments across the source and
   both Replays. A session argument or changed request semantics fails closed.
9. Evaluate the repeated depth only with the exact VAL-004B Baseline, Negative Control and
   Counterfactual authority anchored to the primary Replay.
10. Require all six source, Replay and Control execution lineages to be pairwise distinct. This
    prevents an additional Replay from substituting any Control execution coordinate.
11. Exact-match the two repetitions, ordered Control set, observed contrast and stateless policy
    against the registered VAL-002 repeated-controlled requirement before satisfying a Profile floor.
12. Keep Profile selection, Campaign mutation, additional execution, additional Replay,
    confirmation and Finding authority false.

## Consequences

- VAL-001 WALK evidence can satisfy the `ai-assessment` repeated-controlled floor when two exact
  WALK-005B2 Replays and the existing three-Control authority are supplied.
- VAL-004C introduces no planner, dispatcher, approval, Grant, Permit, Worker or mutable store.
- Reusing either Replay, swapping sealed predecessors, changing the source Plan, borrowing a Control
  execution, mutating session semantics or escalating an authority marker fails closed.
- The first Replay has an explicit semantic role as the Control anchor; predecessor order is not an
  interchangeable set.
- Existing VAL-001, VAL-004B, WALK-005B1 and WALK-005B2 artifacts retain their wire meanings.

## Rejected alternatives

### Add a separate N-run Replay planner and executor

Rejected because WALK-005B1 already fixes the exact request semantics and WALK-005B2 already owns
every per-execution authority. A second execution path would duplicate the trust boundary.

### Count Control executions as repetitions

Rejected because Controls intentionally change either the observation condition or request. They
are causal contrasts, not exact Claim reproductions.

### Widen the existing VAL-004B assessment wire

Rejected because adding repeated evidence to the existing content-addressed model would change the
digest and compatibility of previously serialized VAL-004B assessments.

### Accept two structurally valid VAL-001 objects without sealed predecessor verification

Rejected because object shape and digest validation do not reopen the WALK-005B2 publication Runs or
prove that the supplied outcomes are the exact predecessors.

## Compatibility and rollback

The change is additive. Rollback removes the VAL-004C module, tests, contract and this ADR without
rewriting any VAL-001, VAL-004B, WALK Plan, Replay, Control, Campaign, Profile or Finding artifact.

## Related documents

- [VAL-004C contract](../orchestration/VAL-004C-mode-neutral-repeated-walking-profile-evidence.md)
- [VAL-004B contract](../orchestration/VAL-004B-mode-neutral-walking-profile-evidence.md)
- [VAL-002 contract](../orchestration/VAL-002-validation-depth-policy.md)
- [ADR-0151](0151-bind-stateless-walking-controls-to-val001.md)
- [ADR-0147](0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md)
