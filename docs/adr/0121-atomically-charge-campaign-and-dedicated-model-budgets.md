# ADR-0121: Atomically Charge Campaign and Dedicated Model Budgets

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-004A proves that a future Shadow Supervisor request fits both its Campaign and dedicated
ceiling, but it deliberately reserves nothing. The current Provider port accepts one
`BudgetController`. Adding a separate Supervisor controller and reserving the two sequentially
would expose a partial mutation when the second controller rejects. A lock owned only by a
composite wrapper would also fail to serialize an existing caller that directly uses the shared
Campaign controller.

## Decision

1. Revalidate and detach each supplied `Budgets` authority, add one reentrant usage lock to every
   `BudgetController`, and protect all usage checks, mutations, active reservations, restoration,
   duration reads, and snapshots with it.
2. Add `DualModelUsageBudget`, which requires distinct Campaign and dedicated controllers and
   always acquires their locks in stable object-identity order.
3. Reserve the same call, Tool-call, prompt-token, completion-token, and cost upper bound on both
   controllers while both locks are held. Roll back every created internal reservation if
   dedicated admission or later composite publication fails.
4. Expose only one opaque composite reservation. Before commit or release, require that composite
   and both hidden reservations to remain exact and active.
5. Extend `PolicyBoundProviderPort` with an optional dual budget that must include the exact
   supplied Campaign controller. Preserve all existing call signatures and return values.
6. Use the minimum remaining duration across both ledgers. Commit both bounds whenever dispatch
   occurred or is uncertain; release both only when non-execution is proven.
7. Reject boolean-number coercion at Campaign budget ingestion, runtime model usage, and
   persistent usage restoration. Tool Loop checkpoints reject boolean budget values before model
   coercion and do not cast raw checkpoint scalars before restoration.
8. Keep the implementation process-local. Do not imply a distributed budget ledger, stable
   Provider request identity, durable dispatch claim, or Supervisor invocation receipt.

## Consequences

- A direct Campaign caller and a dual caller cannot both consume the same final process-local
  capacity.
- Dedicated denial cannot leave a phantom Campaign charge, and proven non-execution releases both
  sides together.
- Existing Campaign-only Provider callers retain their behavior.
- The runtime lock is deliberately reentrant because reservation helpers compose existing checked
  methods while holding both controller locks.
- Cross-process budget coordination and actual Shadow invocation remain separate work.

## Compatibility and rollback

The public classes and Provider constructor parameter are additive. Valid existing integer and
finite-number inputs retain their meaning; ambiguous boolean-as-number inputs now fail closed.
Rollback removes the dual controller and optional Provider path. The internal usage locks and
strict scalar checks may remain as independent hardening.

## Related documents

- [SUP-004B1 contract](../orchestration/SUP-004B1-atomic-dual-model-budget.md)
- [SUP-004A contract](../orchestration/SUP-004A-checkpoint-invocation-plan.md)
- [ADR-0120: Plan and Seal Supervisor Checkpoints Before Provider Invocation](0120-plan-supervisor-checkpoints-before-invocation.md)
- [ADR-0009: Policy-bound Provider Runtime](0009-provider-backed-agent-runtime.md)
