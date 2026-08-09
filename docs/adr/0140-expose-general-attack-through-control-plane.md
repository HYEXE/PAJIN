# ADR-0140: Expose General Attack Through the Control Plane

- Status: Accepted
- Date: 2026-08-09

## Context

SUP-007A composes the existing General Attack authority chain but is a Python direct call. PAJIN
already has two potential product surfaces: the broad local CLI and the leased Control Plane
Campaign Job. The Control Plane Worker can load a digest-pinned `CapabilityGraphWorkerDeployment`
that already owns the Campaign, MissionEnvelope, signed activation, Graph store, managed Run root,
closed Tool registry, compiler identity, and Worker backend.

A separate CLI manifest would duplicate most of that deployment authority. Extending the deployment
wire with a new action record is unnecessary for a first T0/T1 slice because General Attack sources
can be exact-rebuilt and intersected with the existing deployment at execution time. Admitting T2,
network access, or caller-priced actions would require authorities that the current composition does
not possess.

## Decision

1. Add an explicit `general-attack-v1` input profile to the existing Control Plane Campaign Job.
2. Require the existing startup-pinned Capability Graph deployment. Do not add another deployment
   file, daemon, store, Permit, Grant, or result wire.
3. Accept only source Hypothesis Set, Plan, Task digest, Definition reference, code-backed Capability
   reference, Graph Decision, and Grant in the strict Job payload.
4. Rebuild the General Attack Proposal and intent inside the trusted executor from the deployment
   Campaign and current CAP registries.
5. Resolve the Envelope from the deployment, derive used calls from durable Permits, and adapt those
   exact values into both SUP-007A input authorities.
6. Restrict the first profile to approval-free, non-networked, zero-cost T0/T1 no-write actions.
7. Return only existing Permit and authenticated outcome identities in `CompletedExecution`.
8. Treat exact retry, cancellation, callback failure, and missing terminal evidence as terminal
   no-redispatch outcomes.

## Consequences

- General Attack obtains one concrete daemon-backed product surface without changing existing
  default Campaign execution.
- A Job cannot choose the Campaign, Envelope, activation, Run root, Gateway registry, Worker, or
  Graph store.
- Job admission, Graph Decision actor authentication, and Grant provenance remain explicit Control
  Plane/deployment TCBs; exact source reconstruction does not make their providers cryptographic.
- T2 remains closed until a distinct profile composes APPROVAL-001A end to end.
- Networked and priced General Attack actions remain closed until a trusted pricing and egress
  deployment contract exists.

## Rejected alternatives

### Add a standalone CLI execution manifest

Rejected because it would repeat deployment identity, activation, state roots, Tool registry, and
Worker selection already pinned by the Control Plane deployment.

### Add General Attack sources to the deployment wire

Rejected for the first slice because strict Job sources are exact-rebuilt and attenuated against the
existing deployment. A wire version increase would add migration cost without increasing authority.

### Reuse `capability-graph-v1` without a distinct profile

Rejected because that payload starts from an already-derived `ActionProposal` and `ToolRequest` and
cannot prove the full PERMIT-001/002 General Attack source lineage.

### Enable T2 or caller-provided pricing

Rejected because T2 needs the existing approval provider/verifier/issuer chain and caller-provided
cost is not a trusted pricing authority.

## Compatibility and rollback

The profile is additive. Existing deployment v1alpha1/v1alpha2, Campaign Job profiles, Graph schema,
Gateway, Run, and result wires are unchanged. Rollback removes the profile and caller while retaining
all consumed Permits and sealed Run audit as immutable evidence.

## Related documents

- [SUP-007B contract](../orchestration/SUP-007B-control-plane-general-attack-profile.md)
- [SUP-007A contract](../orchestration/SUP-007A-opt-in-general-attack-execution.md)
- [ADR-0139](0139-compose-general-attack-through-managed-gateway.md)
