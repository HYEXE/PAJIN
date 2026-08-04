# ADR-0120: Plan and Seal Supervisor Checkpoints Before Provider Invocation

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-001 binds a non-invocable Supervisor model configuration, SUP-002 creates the actual
target-taint-preserving Snapshot projection, and SUP-003 compiles an externally supplied draft.
None defines the exact Provider request, checkpoint trigger, dedicated budget, or request/response
receipt.

Calling the existing Provider port immediately would leave material gaps. It internally creates a
random ToolRequest ID and returns only `ProviderChatResult`; callers cannot bind the exact Gateway
request, conservative reservation, and evidence receipt without unsafe event inference. A second
independent `BudgetController` would also let Supervisor cost sit outside the Campaign-wide
accounting. Raw Gateway evidence currently contains the complete request, so an early integration
would persist target-tainted model input in a transport artifact.

## Decision

1. Split SUP-004 into a non-invocable planning slice and a later actual-call slice.
2. In SUP-004A, rebuild and externally verify the complete current SUP-002 input before deriving a
   checkpoint, but fail closed when its canonical JSON exceeds the current 65,536-character
   `ProviderMessage` limit.
3. Reuse existing Canonical Graph Snapshot reasons rather than adding checkpoint vocabulary.
4. Build the exact two-message structured-output `ProviderChatRequest` in memory. Bind only ordered
   content digests and byte counts, complete request/schema digests, and predecessor identities in
   the authority artifact.
5. Add a dedicated Supervisor call/token/time/cost policy that must be attenuated by Campaign
   budgets. Check conservative affordability without reserving or consuming usage.
6. Share the pure conservative Provider usage-bound calculation with `PolicyBoundProviderPort` so
   planning and transport cannot drift.
7. Make one process-local scheduler instance exact-idempotent and single-flight. Reject a different
   request for the same Campaign/Graph checkpoint as equivocation.
8. Publish each new schedule in a separate create-only sealed Run and require consumer-side exact
   registered path, one-seal/one-artifact/one-event shape, caller-expected dedicated budget policy,
   Run/root/artifact/event, and current-source verification.
9. Keep model invocation, Task/Plan mutation, Scope, Capability, Permit, execution, Stop
   application, and activation authority false.
10. Reject boolean-number coercion in Provider request/result/usage fields before they can enter a
    future receipt.
11. Defer actual dispatch to SUP-004B, which must expose one bound Provider call outcome and
    atomically enforce both Campaign and dedicated Supervisor budgets.

## Consequences

- The actual request wire and scheduling decision are auditable before any model sees target data.
- Exact retries create no second schedule Run inside one scheduler authority instance.
- Source Runs remain immutable; the Supervisor audit references them from a separate sealed Run.
- A schedule cannot be mistaken for consumption or execution because every authority marker and
  reservation state remains false/not-reserved.
- Process restart can produce an exact duplicate schedule in another Run. Cross-process durable
  claiming and post-dispatch uncertainty remain explicit SUP-004B work.
- No model-backed Shadow output exists yet. This is intentional rather than an implied Provider
  receipt.
- A valid SUP-002 projection can exceed the current single-message Provider wire. Such input is
  explicitly rejected until a later version introduces a chunked or content-addressed input
  envelope bound to the actual request and receipt.

## Compatibility and rollback

The new contracts and exports are additive. Existing Provider requests with valid JSON scalar
types remain valid. SUP-001, SUP-002, SUP-003, WALK-006, Campaign execution, and Provider transport
do not invoke the scheduler. Rollback removes the additive schedule implementation without data
migration.

## Related documents

- [SUP-004A contract](../orchestration/SUP-004A-checkpoint-invocation-plan.md)
- [SUP-003 contract](../orchestration/SUP-003-typed-non-executable-supervisor-proposal.md)
- [ADR-0119: Compile Untrusted Supervisor Drafts](0119-compile-untrusted-supervisor-drafts.md)
- [ADR-0009: Policy-bound Provider Runtime](0009-provider-backed-agent-runtime.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
