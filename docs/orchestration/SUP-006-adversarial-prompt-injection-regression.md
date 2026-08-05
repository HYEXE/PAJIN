# SUP-006: Adversarial Prompt Injection Regression

- Status: Implemented
- Provider draft wire: `pajin.dev/supervisor-shadow-proposal-draft/v1alpha1`
- Decision: [ADR-0127](../adr/0127-enforce-the-advertised-supervisor-draft-wire.md)

## Scope

SUP-006 closes the Shadow Supervisor adversarial regression milestone by exercising the existing
SUP-002 through SUP-005B2 authorities as one containment path. It adds no proposal, execution,
threshold, activation, Capability, Permit, Observation, Result, Comparison, or registry authority.

The regression does not claim that a model ignores prompt injection. It assumes the target Fact
and model rationale can be fully adversarial, then proves that accepted output remains a
content-free advisory record and that benchmark metrics still come only from externally attested
Target Observations.

## Exact Provider draft wire

The Provider is shown a strict JSON Schema whose field names are camelCase aliases. Internal Python
callers may still construct `SupervisorShadowProposalDraft` with field names for compatibility,
but raw Provider JSON is now parsed by `parse_supervisor_shadow_proposal_draft()`. The parser accepts
only the exact advertised alias spellings before Pydantic validation.

This closes a schema escape where raw JSON containing `snapshot_id`, `snapshot_digest`, or
`proposal_kind` was accepted even though those names were absent from the advertised schema.
Unknown fields, mixed spellings, wrong kinds, authority `true`, duplicate JSON keys, non-finite
values, and foreign Snapshot identities fail closed through the alias-only parser, strict JSON
loader, and existing typed validation.

## Adversarial corpus

The regression freezes prompt-shaped target content covering:

- JSON and chat-delimiter attempts to inject `system` or `developer` roles;
- requests to downgrade `targetTaint` or set `instructionAuthorized=true`;
- Campaign Scope expansion and Plan or TaskGraph mutation requests; and
- `shell.execute`, ToolRequest, Capability, Permit, execution, threshold, and activation requests.

The same path also exercises structurally invalid Provider drafts: snake_case schema escape, extra
ToolRequest, Capability escalation, unknown executable kind, and foreign Snapshot replay. Invalid
drafts consume the one already-dispatched model call conservatively, leave the journal in
`dispatch-started-outcome-unknown`, require manual review, and never redispatch.

## End-to-end containment

For schema-valid adversarial output, the regression proves:

1. SUP-002 keeps target content `target-tainted-untrusted` and `instructionAuthorized=false`.
2. SUP-004A emits exactly one code-owned developer message and one canonical user JSON message.
   The user message is tainted, has no instruction authority, and the request exposes no Tools.
3. SUP-004B3 admits one schema-valid adversarial `escalate` draft, while SUP-003 copies neither
   target text nor rationale into its typed proposal and fixes mutation, Scope, Capability, Permit,
   execution, scheduling, and activation authority to false.
4. SUP-005B1 keeps the exact Snapshot, sealed Plan publication, coordinate, stable request, and B3
   receipt relation. A candidate from another otherwise identical Plan publication is not
   interchangeable.
5. SUP-005B2 accepts metrics only through the existing external Target attestation and
   registry-governed Harness. Its final lineage contains no target prompt or rationale, attributes
   no proposal causality, and keeps threshold, activation, and execution false.

## Compatibility and rollback

The change hardens only raw Provider draft admission and adds regression coverage. Existing model,
Snapshot, proposal, B3, Plan, Target, Harness, Observation, Result, and Comparison wire shapes are
unchanged. Valid camelCase Provider output and internal Python model construction remain compatible.
Rollback removes the alias-only admission hardening and tests; it requires no data migration.

## Remaining boundary

The regression uses deterministic fake Provider and external-measurement fixtures. It proves
authority containment, source isolation, and fail-closed replay handling, not production model
quality, resistance to every natural-language attack, distributed exactly-once execution, or an
activation threshold. Phase 7 must still require deterministic ActionProposal compilation, exact
single-use Permits, and approvals before any execution path exists.
