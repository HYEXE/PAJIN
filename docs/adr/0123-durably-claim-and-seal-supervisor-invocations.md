# ADR-0123: Durably Claim and Seal Supervisor Invocations

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-004A seals the exact Shadow Supervisor request plan. SUP-004B1 atomically charges a shared
Campaign and dedicated model budget, and SUP-004B2 supplies a stable Gateway request ID plus a
secret-free successful outcome. The Gateway request reservation is nevertheless confined to one
Run. A process can fail after a Provider dispatch and before returning the outcome, so constructing
a new Run on retry could duplicate the call. A returned B2 outcome also does not prove the Gateway
evidence bytes, Run membership, seals, or admission of the exact model draft to SUP-003.

## Decision

1. Add one host-local SQLite journal whose immutable intent binds the exact current SUP-004A
   publication, request binding, checkpoint, dedicated budget policy, preplanned Provider Run ID,
   stable request ID, receipt path, and dual budget scope.
2. Use a closed lifecycle of `intent-recorded`, `dispatch-started-outcome-unknown`, and
   `terminal-success`. Commit the started state before Run creation or Provider dispatch and never
   grant automatic redispatch from any state.
3. Treat every failure after the started transition as outcome-unknown. Recover only by verifying a
   complete receipt in the exact preplanned Run and advancing the existing journal entry; do not
   call the Provider again.
4. Protect the journal with strict schema metadata, immutable rows, append-only hash-chained events,
   compare-and-swap state transitions, exact reconstruction, safe local paths, `BEGIN IMMEDIATE`,
   and full synchronous durability.
5. Rebuild and verify the current SUP-004A schedule and request before claiming or consuming. Before
   the initial dispatch, additionally require exact concrete Policy, ledger, registry, budget,
   Provider Tool, registration, grant, Campaign budget, dedicated policy, and
   `DualModelUsageBudget` controller identities.
6. Invoke only through the existing SUP-004B2 `chat_bound()` path with the journal-derived request
   ID and `campaign-and-dedicated` charge.
7. Seal the Provider Run twice. The first seal freezes only the request reservation, Gateway
   evidence, and Provider/Gateway event prefix. Append one content-addressed receipt with the full
   B2 outcome and strict untrusted draft plus one receipt event, then create the final seal.
8. Store the final Run root and receipt SHA-256 in the external journal terminal transition to avoid
   embedding a self-referential final root in the receipt.
9. Expose no independently admitted raw draft. The public consumer must verify the terminal journal,
   both seals, artifacts, events, reconstructed Gateway/B2 sources, current schedule, exact dual
   scope, receipt, and draft, then pass the draft directly to the existing SUP-003 compiler and
   verifier.
10. Reconstruct the code-owned Provider Worker job and require exact job metadata, egress, stdin
    digest, Secret Lease issue/revoke events, execution lifecycle, and Tool result re-derived from
    the sealed Worker stdout.
11. Serialize Campaign set-backed wire fields as sorted arrays so nested Supervisor authority
    digests do not depend on Python hash seed.
12. Keep redispatch, Task creation, Plan mutation, Scope expansion, Capability, Permit, execution,
    and activation authority false.

## Consequences

- Exact retries of an unstarted or terminal checkpoint are idempotent within one canonical journal.
- A crash after dispatch cannot silently create a second Provider call; incomplete evidence remains
  conservatively unknown and requires manual review.
- A crash after the final seal but before the terminal journal update can be recovered without
  Provider redispatch after the complete sealed Run is re-verified.
- The accepted SUP-003 proposal is traceable to the current schedule, exact Provider/Gateway
  lifecycle, immutable evidence bytes, charged bound, and sealed untrusted draft.
- Availability is lower after ambiguous dispatch failure because safety forbids automatic retry.
- The journal is not distributed consensus. Alternate database paths, cross-host coordination, and
  copied or replaced trust roots are outside this guarantee.
- Sealed charged usage does not reconstruct process-local budget ledgers after restart, and sealed
  Gateway evidence remains sensitive.

## Compatibility and rollback

The journal and invocation runtime are additive. Existing SUP-001 through SUP-004B2 wires and
Provider APIs remain unchanged. No existing data migration is required. Rollback removes the
additive invocation path but retains journal databases and sealed Runs for audit; started intents
must not be treated as fresh invocation authority after downgrade.

## Related documents

- [SUP-004B3 contract](../orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md)
- [SUP-004B2 contract](../orchestration/SUP-004B2-stable-provider-bound-outcome.md)
- [SUP-004B1 contract](../orchestration/SUP-004B1-atomic-dual-model-budget.md)
- [SUP-004A contract](../orchestration/SUP-004A-checkpoint-invocation-plan.md)
- [ADR-0122: Stable Provider Outcomes](0122-bind-stable-provider-requests-to-secret-free-outcomes.md)
- [ADR-0121: Atomic Dual Budgets](0121-atomically-charge-campaign-and-dedicated-model-budgets.md)
- [ADR-0120: Plan Supervisor Checkpoints](0120-plan-supervisor-checkpoints-before-invocation.md)
- [ADR-0119: Compile Untrusted Supervisor Drafts](0119-compile-untrusted-supervisor-drafts.md)
