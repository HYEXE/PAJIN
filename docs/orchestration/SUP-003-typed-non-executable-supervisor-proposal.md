# SUP-003: Typed Non-Executable Supervisor Proposal

- Status: Implemented
- Authority contract: `pajin.dev/supervisor-typed-proposal/v1alpha1`
- Decision: [ADR-0119](../adr/0119-compile-untrusted-supervisor-drafts.md)

## Scope

SUP-003 deterministically compiles one exact SUP-001 `SupervisorShadowProposalDraft` and one
externally reverified SUP-002 `SupervisorSnapshotInput` into a typed `task`, `replan`, `stop`, or
`escalate` advisory proposal. The compiler never interprets model rationale or Snapshot text as
authority.

This slice does not invoke a model, attest that a Provider produced the draft, construct a prompt,
schedule or mutate a Task or Plan, expand Scope, revoke a Permit, stop execution, notify a human,
or grant Capability, Permit, execution, or activation eligibility. SUP-004 owns checkpoint
scheduling and a dedicated budget. Any future model call also requires an additive invocation
binding for its actual request wire.

## Compilation authority

`SupervisorProposalCompilationPolicy` is code-owned and content-addressed. It binds:

- the actual `SupervisorSnapshotInput` projection schema, rather than treating the raw
  `CollaborationSnapshot` schema as the projection wrapper;
- the exact SUP-001 `SupervisorShadowProposalDraft` schema digest;
- the complete `SupervisorTypedProposal` output schema digest;
- the registered WALK-006 policy identity without inferring its `still-vulnerable` lifecycle from
  Collaboration Fact text;
- the fixed `current-collaboration-shadow` compiler state and exact ordered four-kind allowlist;
  and
- literal false authority markers for model invocation, Scope expansion, Capability, Permit,
  execution, and activation.

The current Collaboration projection has no trusted typed lifecycle state that can safely narrow
the four roadmap kinds. All four are therefore structural advisory records in this policy state.
Unknown kinds, allowlist reordering, duplication, widening, or policy-state substitution fail
closed. A future state-specific allowlist requires a separate typed state projection; Fact text or
model rationale cannot supply it.

## Source binding and output

The compiler calls `verify_supervisor_snapshot_input()` with the expected Campaign, Provider
registration, immutable model revision, configuration, current Collaboration Snapshot, Graph
store, and Artifact sources. A standalone self-consistent or stale input is insufficient.

The draft `snapshotId` and `snapshotDigest` must equal the exact source Collaboration Snapshot in
the SUP-002 input. `SupervisorTypedProposal` additionally binds:

- Campaign, SUP-001 binding, SUP-002 input, and source Snapshot identities and digests;
- a domain-separated taint digest over complete text/reference provenance without raw text;
- the complete canonical draft digest, proposal kind, rationale SHA-256, and UTF-8 byte count;
- the compiler policy, WALK-006 policy, and actual input/draft/output schema digests; and
- one code-owned discriminated typed payload.

The rationale itself is not embedded. Different rationale for the same kind produces the same
typed payload but a different source-draft and final proposal identity.

Typed payloads have only code-owned literals:

- `task` requests human Supervisor review but has no Capability and cannot be scheduled;
- `replan` requests deterministic review without Plan mutation or Scope expansion;
- `stop` recommends stopping autonomy but does not revoke a Permit or interrupt execution; and
- `escalate` requests human review but sends no notification and grants no approval.

Every payload and envelope fixes instruction, TaskGraph mutation, scheduling, Capability, Permit,
execution, baseline mutation, provider-response verification, model-output attestation, and
activation authority to false as applicable.

## Negative boundaries

Compilation or external verification fails closed for:

- stale or foreign Campaign, Provider, model revision, configuration, binding, Graph head, input,
  or source Snapshot substitution;
- Snapshot ID/digest confusion between the source Snapshot and the SUP-002 projection envelope;
- forged input, binding, taint, draft, policy, schema, rationale, payload, or proposal digest;
- unknown, widened, duplicated, reordered, or payload-mismatched proposal kinds;
- prompt, command, message, ToolRequest, argument, Scope, or other extra draft fields;
- copying prompt-shaped Fact, Artifact, or rationale content into the output wire;
- `model_construct()` or `model_copy()` validation bypass objects at the compiler boundary;
- integer/string coercion of boolean authority fields or boolean coercion of integer byte counts;
  and
- any attempt to apply a Task, Replan, Stop, escalation, Capability, Permit, execution, or
  activation effect.

The adjacent WALK-006 Stop and authority booleans now also reject numeric `0`/`1` coercion before
SUP-003 can inherit an ambiguous predecessor wire.

## Audit, compatibility, and rollback

The content-addressed typed envelope is the audit record for this pure compiler. No Run, event,
Provider receipt, scheduler record, or external notification is claimed. SUP-004 may persist a
separately bound checkpoint decision but cannot treat this envelope alone as invocation or
execution authority.

The module and exports are additive. Existing SUP-001, SUP-002, Collaboration, WALK-006, TaskGraph,
Plan, Capability, Permit, and execution wire shapes are unchanged. WALK-006 valid boolean wires are
unchanged; only previously coerced invalid numeric forms are rejected. Rollback removes SUP-003
without data migration, while the boolean hardening may remain independently.
