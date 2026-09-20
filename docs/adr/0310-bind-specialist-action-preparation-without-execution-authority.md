# ADR-0310: Bind Specialist Action Preparation without Execution Authority

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C2 inert specialist action preparation
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-003C1 proves that one receiver-acknowledged specialist assignment is still current and
reserves it behind a process-local, one-use handle. It does not yet bind that assignment to the
deployment-owned Campaign, exact Web Target, closed specialist profile, or production executor.
Conversely, constructing a Capability, approval, Permit, Gateway request, or Worker job while those
inputs are still unresolved would either overstate authority or permit caller-controlled routing.

Preparation must also avoid entering `dispatch-started-outcome-unknown`. That transition is a crash
fence for a real governed action and must not be consumed merely because later approval or Permit
issuance fails.

## Decision

Add an inert AGENTIC-003C2 preparation boundary.

`AgenticCoordinationStore.specialist_preparation_entry()` accepts only the original live,
store-local `VerifiedSpecialistExecutionReservation`. It independently reloads the current Graph,
the complete durable history and head, the exact reserved row, and the currently admitted
assignment. It rechecks the command, admission, Candidate, and specialist-definition digests but
does not consume the reservation or change durable state. The returned entry is an audit-only
value; it cannot begin dispatch.

`prepare_agentic_specialist_action()` then resolves, without I/O:

1. the deployment-fixed Juice Shop Target through the closed governed adapter profile registry;
2. the one exact specialization and threat-class profile through the production specialist
   profile catalog;
3. the corresponding code-owned production executor descriptor; and
4. a strictly reloaded Campaign whose identity, single Target, Scope, budgets, and risk ceiling
   agree with the coordination binding and code-owned route.

The result is a deterministic, content-addressed `AgenticSpecialistPreparation` binding the store,
reservation, durable and Graph heads, assignment, Target, adapter, profile, executor, Campaign,
Scope, and budget identities. Its nested `AgenticSpecialistCapabilityRequirement` describes only a
future one-call, non-delegable, T2-or-lower Capability with fresh approval. It is not a Capability
definition, Grant, `ToolRequest`, `PreparedCapabilityAction`, approval, or Permit.

All Scope, Capability, approval, Permit, Gateway, Worker, execution, Evidence, Finding, and Graph
authority and completion markers remain literal false. Preparation performs no model, browser,
network, Target, Gateway, Worker, reporting, or delivery I/O.

The later executable bridge is AGENTIC-003C3. A fresh signed approval and ActionPermit must be
consumed first. Only inside the one winning `GraphApprovedActionPermitDispatcher` callback may the
bridge reverify current state, call `begin_specialist_dispatch()`, consume the returned store-local
started handle, durably consume an exact one-call child Grant, install a specialist-specific
dispatch binding, and enter the Gateway and specialist Worker. The existing aggregate Web
Capability, Tool, and Worker are not rebranded as specialist authority.

## Consequences

### Positive

- Caller-supplied origins, profiles, executors, policies, transports, payloads, and Tool requests
  cannot influence specialist preparation.
- A stale, foreign, consumed, serialized, or audit-only reservation cannot prepare or begin work.
- All execution-relevant identities needed by the future approval boundary are content-addressed
  before any authority is minted.
- Approval or Permit failure cannot strand a reservation in outcome-unknown state.

### Tradeoffs and residual risks

- The current implementation supports only the exact deployment-owned local Juice Shop route.
- A serialized preparation is descriptive evidence, not bearer authority. The original process-
  local reservation remains the only input accepted by the future dispatch transition.
- Graph and coordination storage are separate transactions. AGENTIC-003C3 must reverify both at the
  action boundary and treat any post-CAS uncertainty as non-redispatchable.
- No specialist Capability, Grant, approval, Permit, Gateway, Worker, sealed Evidence, independent
  Replay, Finding promotion, Graph admission, report, SARIF, or PoC authority exists yet.

## Compatibility, migration, and rollback

The preparation API is additive and has no production consumer. It does not change the version-3
coordination schema or existing Campaign, Capability, Permit, Gateway, Worker, Finding, or Graph
wire formats. Rollback removes the preparation module, store read seam, and tests. A later
executable bridge requires its own versioned migration and rollback contract before activation.

## Rejected alternatives

### Accept a serialized execution row or preparation as authority

Rejected because by-value data cannot prove store locality, liveness, or one-use ownership.

### Infer the origin or profile from a model proposal Target ID

Rejected because a proposal is advisory and cannot create routing or Scope authority.

### Accept caller-supplied profiles, executors, policies, transports, or payloads

Rejected because self-consistent substituted inputs could widen the selected closure or egress
boundary.

### Reuse the aggregate Web Capability, Tool, or Worker unchanged

Rejected because its multi-diagnostic and validation authority exceeds one selected specialist
task and does not bind the durable assignment or specialist executor.

### Begin dispatch before approval and Permit consumption

Rejected because pre-authority failures would permanently create an outcome-unknown execution
without any Target I/O.

## Related documents

- [ADR-0308: Bind Specialist Profiles to Closed Executor Definitions](0308-bind-specialist-profiles-to-closed-executor-definitions.md)
- [ADR-0309: Reserve Receiver-Acknowledged Specialist Assignments before Dispatch](0309-reserve-receiver-acknowledged-specialist-assignments-before-dispatch.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
