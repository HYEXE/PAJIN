# SUP-001: Supervisor Model Binding

- Status: Implemented
- Authority contract: `pajin.dev/supervisor-model-binding/v1alpha1`
- Output interface: `pajin.dev/supervisor-shadow-proposal-draft/v1alpha1`
- Decision: [ADR-0117](../adr/0117-bind-shadow-supervisor-model-before-invocation.md)

## Scope

SUP-001 records which exact Provider registration, model revision, bounded configuration, Campaign
Profile, Common Engine contract, WALK-006 policy, input Snapshot schemas, and output draft schema a
future Shadow Supervisor may use. The binding is content-addressed but non-invocable.

It does not call a model, construct messages or prompts, accept a Snapshot instance, schedule a
checkpoint, create a product proposal, mutate the deterministic baseline, or grant a Capability,
Permit, Tool request, execution authority, or activation eligibility. SUP-002 owns actual
Snapshot-only input and Target taint; SUP-003 owns deterministic compilation of model drafts into
typed product proposals.

## Bound identities

`SupervisorModelBinding` includes:

- the exact legacy Campaign Profile compilation and Campaign digest;
- the selected Profile digest and registered Common Engine contract digest;
- `AgentRole.SUPERVISOR` and the exact WALK-006 registered Shadow policy;
- a secret-free Provider/model projection containing Provider ID, normalized endpoint, model ID,
  immutable model revision, and a digest of the complete runtime `ProviderRegistration`;
- a frozen structured-JSON configuration digest with no prompt content or function Tools;
- the code-owned JSON Schema digests for `WalkingShadowInputSnapshot`,
  `CollaborationSnapshot`, and `SupervisorShadowProposalDraft`; and
- literal shadow-only, non-invocable, non-executable authority markers.

The Provider registration digest sorts the set-valued function Tool allowlist before hashing. The
wire does not expose `secret_ref`; changing the registration, including its secret reference name,
changes the digest and requires a new exact binding.

## Output schema boundary

`SupervisorShadowProposalDraft` is untrusted model output, not an Action or command. It contains
only the bound Snapshot ID/digest, one of `task`, `replan`, `stop`, or `escalate`, and bounded
rationale. It has no message, prompt, command, argument, ToolRequest, Capability, or Permit field,
and fixes all authority markers to false.

Consumers must call `verify_supervisor_model_binding()` with the expected Campaign, Provider
registration, immutable model revision, and configuration. A standalone, internally consistent
binding for another runtime is not interchangeable with the expected binding.

## Negative boundaries

Validation or verification fails closed for:

- forged binding, component, Profile, policy, or schema digests;
- mutable model revision aliases such as `latest`, `default`, or `auto`;
- independently valid cross-Campaign, cross-Provider, cross-model-revision, or configuration
  substitution;
- input schema reorder or schema digest substitution;
- prompt, command, Tool, Capability, or Permit fields in the output draft; and
- any attempt to enable model invocation, Capability, Permit, execution, or activation.

## Compatibility and rollback

The package, contracts, and exports are additive. Existing Provider sessions, execution
Supervisor, WALK-006 records, Collaboration Snapshot readers, Campaign Profile compilation, and
wire formats are unchanged. Rollback removes the SUP-001 package and documentation; no stored
runtime state or data migration is required.
