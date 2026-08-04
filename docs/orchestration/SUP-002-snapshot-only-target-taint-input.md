# SUP-002: Snapshot-Only Target-Taint Input

- Status: Implemented
- Authority contract: `pajin.dev/supervisor-snapshot-input/v1alpha1`
- Decision: [ADR-0118](../adr/0118-preserve-target-taint-in-supervisor-snapshot-input.md)

## Scope

SUP-002 projects one exact current Phase 5 `CollaborationSnapshot` into a bounded model-visible
input while preserving the provenance and target taint of every admitted Campaign Fact and shared
Artifact reference. It first re-verifies the exact SUP-001 runtime binding and existing MEM-003
Snapshot authorities.

The slice does not invoke a model, construct messages or a prompt, read Artifact bytes, emit a
SUP-001 draft, compile a SUP-003 proposal, or grant Capability, Permit, execution, or activation.
The WALK-006 input schema remains registered by SUP-001 but is not materialized by this first
SUP-002 Collaboration projection.

## Projection

The compiler resolves the current Graph Snapshot behind MEM-003 and requires the Graph head to
remain unchanged. Every admitted Fact reference resolves to its exact `GraphCampaignFact`.

- Fact statements become `SupervisorModelVisibleText` records with source node ID, source value
  digest, text digest, `GraphContentOrigin`, and exact taint.
- `agent-derived` and `target-derived` text is `target-tainted-untrusted`; this prevents an Agent
  summary from laundering target content.
- `operator` and `trusted-core` text is `trusted-metadata`.
- Fact references carry the same origin and taint as their text record.
- Shared Artifact references never expose bytes and are always `target-tainted-untrusted` because
  `GraphEvidence` has no separate trustworthy content-origin field.

Membership is complete and sorted. Omitting a Fact text, Fact reference, or Artifact reference
invalidates the envelope. Standalone records cross-bind Fact reference digest/origin/taint and
Artifact reference digest to their source Snapshot; the external verifier additionally rebuilds
the exact Graph-backed text and value digest.

## Negative boundaries

The implementation rejects stale or cross-Campaign Snapshots, foreign SUP-001 runtime bindings,
schema substitution, text/reference omission, taint downgrade, digest or provenance forgery, raw
prompt relay, boolean coercion, and any attempt to enable model invocation, Capability, Permit, or
execution. Prompt-shaped Fact text remains visibly marked untrusted data and is never represented
as a message, role, instruction, command, ToolRequest, or argument.

## Compatibility and rollback

The new projection and exports are additive. MEM-003, Graph, WALK-006, SUP-001, Provider session,
and execution wire formats are unchanged. Rollback removes SUP-002 without data migration; no
model call or durable runtime state has been created.
