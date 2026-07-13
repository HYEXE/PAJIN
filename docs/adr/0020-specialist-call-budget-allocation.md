# ADR 0020: Specialist call-budget allocation

- Status: Accepted
- Date: 2026-07-13

## Context

The root Capability decrements every ancestor when a child Tool call executes, so sibling Grants
cannot exceed the Campaign total. The previous local orchestrator nevertheless delegated up to two
attempts independently to every low-risk Specialist without reserving those calls across siblings.
In a multi-step plan with two total calls, the first T0/T1 task could consume both calls on a retry;
the second Specialist would then be spawned but fail before dispatch because the root was empty.

Model-backed Validator and Reporter roles also use the root Tool-call budget through the Provider
Gateway. Specialist allocation must not make their already declared maximum attempts impossible.

## Decision

After the Planner returns a validated plan and before any Specialist is spawned, the Supervisor
allocates root calls in this order:

1. Reserve the declared maximum attempts for a model-backed Validator and Reporter, if present.
2. Require one first attempt for every planned Specialist.
3. Assign each remaining slot in stable plan order as at most one retry to a T0 or T1 Specialist.
4. Leave calls unallocated when all eligible Specialists already have their maximum of two.

If the remaining root capacity cannot fund every Specialist's first attempt after the control-role
reservation, the Campaign is cancelled before partial Specialist fan-out. Each Specialist Grant's
`maxCalls` and Task's `maxAttempts` receive the same allocation. The Supervisor records
`specialist.call-budget.allocated` with the root remainder, control-role reservation, per-request
allocation, and unallocated count.

This is a deterministic local allocation, not a mutable reservation inside `CapabilityLedger`.
The lineage counter remains the final atomic authorization check at dispatch. Because the sum of
the orchestrator's child maxima cannot exceed the observed root remainder, successful or failed
children cannot consume a sibling's required first attempt.

## Consequences

- Multi-step plans fail before partial fan-out when their minimum execution cannot fit the budget.
- A transient failure cannot starve a later Specialist of its first authorized attempt.
- T0/T1 retry behavior remains available when the Campaign explicitly has surplus calls.
- Provider-backed downstream roles retain enough root capacity for their declared maximum attempts.
- Stable plan order decides who receives scarce optional retries; no priority or parallel scheduler
  is introduced.

ADR 0021 permits bounded local concurrency only for explicitly opted-in Tools because this
single-Supervisor allocation fixes every child maximum before dispatch. Distributed execution still
requires durable, atomic reservations.
