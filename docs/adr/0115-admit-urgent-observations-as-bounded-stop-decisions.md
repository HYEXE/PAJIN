# ADR-0115: Admit Urgent Observations as Bounded Stop Decisions

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs a fast path for urgent collaboration results without letting untrusted Agent or target
text become commands or letting urgency bypass normal Capability, Permit, Budget, and replanning
authority. Canonical Graph already owns admitted Observations and their Action/Evidence edges;
HANDOFF-002 already binds destination terminal state and sealed result Artifact metadata.

## Decision

Add a process-local single-writer authority that accepts only a safe Graph Observation reference,
resolves it from the exact HANDOFF-002 current Snapshot, and selects one fixed
`stop-and-escalate` disposition. Require code-owned urgent types, operator or trusted-core origin,
confidence `1.0`, exact Action production and result-Evidence support edges, and equality between
the Observation value digest and sealed result Artifact hash.

Fix the boundary to one Observation, one decision, and one local budget unit per handoff. Store no
predecessor and no content. Mark the decision `admitted-not-applied` and every continuation,
replanning, Scope, Capability, Permit, and execution authority false.

## Consequences

- target- or Agent-derived prompt text cannot directly select or populate the fast decision;
- Graph, Artifact, Snapshot, Handoff, and execution authorities are reused rather than duplicated;
- stale, foreign, repeated, cyclic, cross-Campaign, and equivocal inputs fail closed;
- lifecycle and urgent classification remain distinct from Finding confirmation; and
- a downstream enforcement point is still required to stop execution and notify a human.

## Rejected alternatives

Accepting free-form urgent messages was rejected because it creates a command/prompt relay.
Running the normal replanner with an urgent flag was rejected because urgency could alter Plan or
execution authority. Automatically revoking Permits or scheduling escalation was rejected because
this slice has neither durable coordination nor those authorities. A revision-only Snapshot check
was rejected because unrelated Graph stores can produce plausible foreign revisions.
