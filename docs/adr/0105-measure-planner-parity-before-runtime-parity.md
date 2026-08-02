# ADR-0105: Measure Planner Parity Before Runtime Parity

## Status

Accepted

## Context

ENG-002A identifies the exact current Planner, Validator, runner, scheduler, and projector classes
but explicitly does not prove behavior. A complete dual runtime comparison also requires Tool,
Policy, Worker, receipt, Outcome, and Mode-specific post-processing coordinates. Introducing all of
those inputs in one change would make a Planner mismatch difficult to isolate and could accidentally
turn a parity harness into another execution authority.

Planner outputs contain fresh step and request identities. Those identities must differ between
independent invocations, while every semantic request field must remain equal.

## Decision

PAJIN will measure deterministic Planner parity as a separate ENG-002B1 checkpoint. The legacy
direct and Profile adapter paths receive the same complete Campaign and typed constructor inputs.
Only fresh step and request identities are replaced with ordered fixture ordinals; the remaining
typed `AgentPlan` is compared exactly and content-addressed.

This checkpoint proves only Scope and ToolRequest Planner behavior. Capability and Outcome remain
unmeasured. It cannot construct the Common runner, invoke a Worker, compile a `MissionEnvelope`, or
authorize Common execution.

## Consequences

- Planner and constructor drift fails before more expensive dual runtime measurement.
- Fresh identity requirements are preserved without creating false parity failures.
- KISA thresholds are explicit parity inputs rather than hidden constructor defaults.
- Capability, receipt, Validator, candidate, triage, report, and writeup parity remain required.
- The measurement record is content-addressed but is not externally signed or attested.

## Compatibility and rollback

The new API is additive and opt-in. Legacy Planner construction and every CLI/API default remain
unchanged. Rollback removes ENG-002B1 without changing ENG-002A or Mode behavior.

## Related documents

- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0104: Register Implementation Identity Before Runtime Parity](0104-register-implementation-identity-before-runtime-parity.md)
- [ENG-002A contract](../orchestration/ENG-002A-common-engine-implementation-adapter.md)
- [ENG-002B1 contract](../orchestration/ENG-002B1-common-engine-planner-fixture-parity.md)
