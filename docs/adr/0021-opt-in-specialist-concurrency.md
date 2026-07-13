# ADR 0021: Opt-in Specialist concurrency

- Status: Accepted
- Date: 2026-07-14

## Context

The local multi-agent runner created one Specialist per planned step but executed every ready task
sequentially. ADR 0020 now fixes every Specialist's maximum calls before dispatch, so sibling tasks
cannot amplify or steal the root budget. Running independent offline or read-only tasks concurrently
can reduce Campaign duration, especially for the Web and Crypto CTF Suite.

Parallelizing every registered Tool would weaken stop conditions and could overlap state-changing
operations that were designed for sequential use. Unbounded fan-out could also start too many local
Docker Workers. Completion-order results would make validation and reports less reproducible.

## Decision

`ToolSpec` adds `parallel_safe`, defaulting to `false`. A Tool author must explicitly opt in only
when concurrent invocations are independent and its side effects, target behavior, secret use, and
evidence paths are safe under overlap. Risk tier alone never implies parallel safety.

After plan validation and call allocation, the Supervisor builds execution waves in stable plan
order:

1. Consecutive `parallel_safe` tasks form one concurrent wave.
2. Every non-opted-in task forms a single-task wave and acts as a barrier.
3. A local semaphore permits four active Specialists by default and rejects runtime limits outside
   1 through 16.
4. Each task writes to a private result buffer; the Supervisor merges those buffers in plan order
   after the wave completes.

The call-allocation sum remains within the observed root remainder, while the Capability lineage and
Budget Controller remain the final dispatch checks. RunStore event and artifact mutations are
synchronous, await-free critical sections on one local event loop; evidence filenames remain bound
to unique request IDs. The Supervisor records `specialist.wave.started` and
`specialist.wave.completed` events with wave membership, safety contract, concurrency, and status.

A normal Tool failure is isolated to its task and does not cancel a sibling. Kill Switch activation,
deadline exhaustion, or a Rules of Engagement stop condition is observed by every active
`_within_budget` operation and cancels its Worker. Queued tasks recheck control state after acquiring
the semaphore and do not dispatch after cancellation.

The fixed CTF Web backup GET and bounded no-network Crypto XOR Tool opt in. Existing Tools remain
sequential until their contracts and tests explicitly demonstrate parallel safety.

## Consequences

- Independent opted-in Specialists reduce wall-clock execution time without receiving more calls,
  targets, Tools, or risk authority.
- Non-opted-in and state-changing Tools retain conservative plan-order execution.
- Validator and Reporter receive plan-ordered results even when Workers finish out of order.
- One stop signal can cancel multiple active local Workers, but already dispatched safe operations
  may have begun before the signal is observed.
- The scheduler is cooperative and process-local. Distributed Workers, crash recovery, and multiple
  Supervisors still require durable atomic reservations and cancellation delivery.
