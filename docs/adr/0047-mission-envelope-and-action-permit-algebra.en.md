> Languages: [English](0047-mission-envelope-and-action-permit-algebra.en.md) | [한국어](0047-mission-envelope-and-action-permit-algebra.ko.md)

# ADR-0047: MissionEnvelope and ActionPermit Algebra

- Status: Accepted
- Date: 2026-07-26

## Context

The existing `CampaignManifest`, `CapabilityGrant`, `ToolRequest`, and `ReplayCapabilityGrant`
provide strong authority boundaries. Architecture v2 lets an Agent or Supervisor choose among
registered Capabilities, so it needs one contract separating proposals from execution authority
and proving monotonic attenuation through every composition.

## Decision

1. A `MissionEnvelope` is an immutable, digest-bound authority object compiled from an approved
   Campaign. It includes at least campaign/profile/compiler identity, authorization window,
   targets/scope, allowed Capability constraints, maximum risk, budget, rate, autonomy, and source
   Campaign digest.
2. An `ActionProposal` is intent, not execution authority. It includes proposer, exact snapshot
   ID/digest, Capability ID/version, target, normalized input, expected risk/cost, and rationale
   lineage.
3. Only a deterministic Compiler plus the existing Policy Gate can issue an `ActionPermit`. An LLM,
   Specialist, Supervisor, or Profile cannot issue one.
4. An `ActionPermit` is non-delegable, single-use authority bound to the exact proposal,
   MissionEnvelope, registered Capability, target, normalized-parameter digest, budget reservation,
   expiry, request, and snapshot.
5. The authority algebra always satisfies:

   ```text
   authority(ActionPermit)
     subset-of authority(registered Capability)
     intersection authority(MissionEnvelope)
     subset-of authority(approved Campaign)
   ```

6. Child-envelope or subtask authority uses set intersection for scope/tools/targets, minimum risk,
   and upper bounds from remaining budget/rate/time. Union, permissive interpretation of missing
   values, new credentials, and new egress are forbidden.
7. Permit consumption succeeds once through atomic compare-and-set storage. An exact retry may
   retrieve the prior result but cannot execute again.
8. If graph revision changes after proposal, the compiler or dispatcher re-verifies the exact
   snapshot binding. A stale decision is recompiled or rejected, never executed automatically.
9. Issuance, denial, consumption, expiry, and cancellation preserve canonical digests and reasons
   in audit events.

## Relationship to existing contracts

- `CapabilityGrant` remains the attenuated authority held by an Agent inside a MissionEnvelope.
- Existing `ToolRequest` later becomes an execution payload compiled from an `ActionProposal`; its
  wire format does not change immediately.
- `ReplayCapabilityGrant` and single-use replay tickets remain narrower existing Permit cases.
- Until this algebra is implemented, the existing Policy/Tool Gateway remains the sole execution
  boundary.

## Rejection conditions

Unknown or inactive Capability, version/digest mismatch, out-of-Scope target, risk/budget/rate
excess, expired authorization, stale snapshot, foreign campaign/run lineage, reused Permit, and
Permit/ToolRequest digest mismatch all fail closed.

## Consequences

Agents can explore a wider registered authority space while actual execution authority becomes
more explicit and narrower. Atomic consumption and snapshot re-verification add storage cost.
Later slices choose concrete wire schemas and Capability Registry storage without relaxing this
algebra.

## Related documents

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.en.md)
- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.en.md)
- [ADR-0048: Minimum Graph and Admission Consistency](0048-minimum-graph-and-admission-consistency.en.md)
