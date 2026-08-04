# ADR-0117: Bind the Shadow Supervisor Model Before Invocation

- Status: Accepted
- Date: 2026-08-04

## Context

WALK-006 records a deterministic code-owned Shadow decision but deliberately does not bind or call
a model. PAJIN already has policy-bound Provider sessions, Campaign Profile compilation, a Common
Engine contract, and safe Walking and Collaboration Snapshot wires. Letting Phase 6 begin with a
new model runner would bypass those predecessor identities and conflate configuration with
invocation authority.

A model name alone is mutable and insufficient. Prompt text is untrusted content, not authority.
The input and output interfaces must also be pinned before any model is allowed to observe a
Snapshot or emit a proposal.

## Decision

1. Add a separate content-addressed `SupervisorModelBinding` before any Supervisor model call.
2. Bind the exact Campaign Profile compilation, Common Engine contract, Supervisor role, and
   WALK-006 registered policy.
3. Project one secret-free Provider/model identity from the complete runtime registration, model
   ID, and an explicit immutable revision. Reject mutable aliases.
4. Bind a frozen structured-output configuration with no prompt content, streaming, or function
   Tool calls.
5. Pin code-owned schema digests for WALK-006 input, Phase 5 Collaboration Snapshot input, and one
   minimal untrusted Shadow proposal draft.
6. Require consumer-side exact verification against the expected Campaign, registration, model
   revision, and configuration. Content addressing alone does not make a foreign binding current.
7. Keep model invocation, Capability, Permit, execution, and activation eligibility false.
8. Leave actual Snapshot projection and taint to SUP-002, and typed Task/Replan/Stop/Escalation
   proposal compilation to SUP-003.

## Consequences

- Provider/model/configuration and schema drift changes binding identity and fails exact runtime
  verification.
- Existing Provider registration remains the source of endpoint and model configuration; SUP-001
  adds no Provider registry or Secret store.
- The output interface cannot represent a direct Agent command or execution request.
- The binding proves configuration identity, not provider attestation, model weight identity,
  deterministic inference, output quality, or activation safety.

## Compatibility and rollback

The new supervision package and schemas are additive and are not used by existing execution paths.
No legacy wire, reader, CLI, API, WALK-006 record, or deterministic baseline changes. Rollback
removes the additive binding and leaves all current behavior intact.

## Related documents

- [SUP-001 contract](../orchestration/SUP-001-supervisor-model-binding.md)
- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0077: Walking Shadow Supervisor Decision Record](0077-walking-shadow-supervisor-record.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
