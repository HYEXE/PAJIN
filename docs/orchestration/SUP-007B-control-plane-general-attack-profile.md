# SUP-007B: Control Plane General Attack Profile

## Purpose

Expose the SUP-007A direct-call composition through one existing Control Plane Campaign Job kind
without adding a new daemon, Permit, deployment wire, store, Grant, or execution result authority.

## Product surface

`CampaignJobExecutor` recognizes the explicit `general-attack-v1` profile only when the Worker was
started with an existing SHA-256-pinned `CapabilityGraphWorkerDeployment`. The Job supplies the
exact Discovery Hypothesis Set, Surface-bound Plan, source Task digest, Capability Definition
reference, code-backed Capability reference, Graph Decision, and current Grant. It does not supply
a Campaign, MissionEnvelope, activation, Run path, Tool registry, Policy engine, or Worker.

The executor rebuilds the General Attack Proposal and compiled intent from the Job sources and the
deployment's current Campaign and CAP-001/CAP-002 registries. It then adapts the deployment's exact
Envelope, Job Decision and Grant, zero cost, and durable used-call count into both SUP-007A input
authorities. The existing `GeneralAttackActionExecutionGate` owns the remaining Permit, managed Run,
Gateway, Worker, and outcome intersection.

## First activation ceiling

The first Control Plane profile accepts only an activated Definition that is:

- T0 or T1;
- `none` or `read-only` and cleanup-not-required;
- `networkAccess=false`;
- `approvalRequired=false`; and
- executed under a Campaign whose maximum monetary budget is exactly zero.

The executor supplies `costMicrousd=0`. It does not infer a price from untrusted Job data or silently
under-account a networked or priced action. T2, T3+, approval-required T0/T1, write,
cleanup-required, networked, and non-zero-cost Campaigns fail closed before Permit consumption and
Worker invocation.

## Existing deployment authority

The profile reuses the existing deployment file and its digest pin without advancing the deployment
wire. The deployment continues to own:

1. the exact Campaign and MissionEnvelope;
2. signed Capability release and activation sets;
3. the bounded absolute Graph database and managed Run root;
4. the closed existing-mode Tool registry;
5. compiler identity, Permit TTL, and Worker process selection; and
6. the canonical Graph Permit store.

The leased Job payload is not authority by itself. The executor validates strict source models,
rebuilds derived wires, exact-matches the Decision against the compiled intent and current Graph,
attenuates the Grant through SUP-007A and the Gateway, and derives used calls from durable consumed
Permits for the deployed Run.

## Result and retry semantics

A first successful execution returns a Control Plane `CompletedExecution` projection containing the
existing deployment profile, Graph Run, Permit identity, authenticated outcome assessment identity,
Oracle decision, and dispatch status. It does not return a bearer Grant or a reusable Permit.

SUP-007A deliberately cannot reconstruct an authenticated `GatewayOutcome` from an exact retry.
Therefore a repeated Job fails permanently as already consumed, never invokes the Worker again, and
preserves the existing sealed audit. Cancellation and callback failures remain terminal and the Run
is sealed before the exception crosses the executor boundary.

## Negative boundaries

Tests cover the real T0 CTF path plus:

- T2 rejection before Worker invocation;
- approval-required, networked, or non-zero-cost profile rejection;
- stale or substituted Decision, Grant, source, activation, or deployment authority;
- exact retry without a second Worker call;
- malformed profile payload and missing startup deployment; and
- cancellation or terminal-audit failure without redispatch.

## Remaining boundary

The next Phase 7 checkpoint may add a distinct T2 profile only if the deployment pins a complete
APPROVAL-001A provider, issuer verifier, ApprovalEnvelope, and receipt path for the exact General
Attack source. T3+ and write remain default denied. Generic pricing, networked execution, verified
Decision actor provenance, and cross-host coordination remain separate deployment contracts.

## Related documents

- [SUP-007A contract](SUP-007A-opt-in-general-attack-execution.md)
- [APPROVAL-001A contract](APPROVAL-001A-single-action-approval.md)
- [ADR-0140](../adr/0140-expose-general-attack-through-control-plane.md)
