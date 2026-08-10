# VAL-001: Mode-neutral Claim Replay

## Purpose

Bind an exact mode-neutral attack-chain authority to an already executed, sealed, and independently
approved validity Claim Replay without authorizing another execution, another Replay, or Finding
confirmation.

## Supported vertical slice

The version-1 contract accepts only:

- `chain-002:file-upload-rag-injection-tool-abuse`; and
- `chain-005:mcp-authorization-failure-privileged-action`.

Both Chains use the WALK-003 MCP authorization hypothesis that also anchors the existing
WALK-005A/B1/B2 Candidate and Replay path. CHAIN-001, CHAIN-003, and CHAIN-004 remain unsupported
because they do not yet have an exact executed Candidate and Replay predecessor.

## Inputs and predecessor verification

The compiler accepts one canonical `CampaignManifest`, one supported Chain authority, its exact
`MCPToolAuthorizationHypothesisOutcome`, and one `WalkingMCPClaimReplayOutcome`.

The selected Chain is rebuilt by its existing verifier, which reopens the sealed WALK-003 source.
The WALK-005B2 loader separately verifies its sealed publication Run, Campaign, artifact, copied
Gateway evidence, publication event, and in-memory outcome equality. VAL-001 records the Replay
publication Run ID and root, fixed artifact path and SHA-256, and the complete
`WalkingMCPClaimReplayAuthority`.

The Chain and Replay must contain an exactly equal `SealedMCPAuthorizationHypothesisDependency`.
Semantic equivalence is insufficient: a different Run, root, artifact, publication, hypothesis, or
Campaign fails closed.

## Claim and fresh-execution binding

VAL-001 accepts only the exact validity `AtomicClaim` selected by WALK-005B1. The WALK-005B2
projection must be `REPRODUCED`, independently execution-attested, and
`confirmationEligible=false`. Its Candidate, Claim, replay Run, request, and execution digest must
match the complete replay authority.

The `replayBindingDigest` covers:

- Chain ID, kind, authority ID, and authority digest;
- WALK-003 Run root, artifact, and hypothesis identity;
- the complete Atomic Claim;
- WALK-005B2 publication Run root and artifact digest;
- Replay authority, Plan, and approval-receipt identities;
- fresh execution Run root, request, Grant, Permit, dispatch, and Worker identities; and
- the exact Replay projection and validation state.

WALK-005B2 continues to own the rules that every execution identity is fresh relative to the
original Candidate execution and that the replay request preserves the Plan semantics.

## Mode neutrality and authority ceiling

`campaignModeConstraint=none`; the contract is identical for `ai-redteam`, `bug-bounty`, and `ctf`.
The exact Campaign digest and nested Campaign manifest remain part of the predecessor lineage.

`ModeNeutralClaimReplayAuthority` records `claimReplayVerified=true`, `freshnessVerified=true`, and
`independentExecutionAttested=true` only after both sealed predecessors pass. It is fixed to
`validity-reproduced-not-confirmed`. `additionalExecutionAuthorized`, `additionalReplayAuthorized`,
`confirmationEligible`, and `findingConfirmed` are false.

The authority is evidence about one completed Replay. It is not a reusable Replay ticket, approval,
Grant, Permit, dispatch instruction, Validation Decision, Finding, or Report.

## Fail-closed boundaries

Compilation and verification reject:

- an unsupported Chain kind or ID;
- malformed, stale, mutated, or cross-Campaign Chain or WALK-005B2 authority;
- Chain and Replay inputs that do not share one exact WALK-003 publication;
- an impact or severity Claim substituted for the exact validity Claim;
- Candidate, Claim, projection, replay Run, request, or execution-digest substitution;
- changed publication root, artifact path, artifact SHA-256, Plan, approval receipt, Grant, Permit,
  dispatch, Worker, evidence, or validation state;
- forged binding or authority digests and boolean-marker coercion or escalation; and
- attempts to derive Replay evidence from Chain topology, Surface metadata, hypothesis text, or
  synthetic Findings.

## Compatibility and rollback

The API version is `pajin.dev/mode-neutral-claim-replay/v1alpha1`. The addition is an immutable
contract, sealed dependency wrapper, Chain-bound authority, compiler, verifier, tests, and public
exports. Existing CHAIN-001~005 and WALK-005B2 wires do not change.

Rollback removes the additions while preserving all sealed predecessor Runs and the rule that
unsupported Chains cannot receive Replay status.

## Current limitations

The first slice supports validity reproduction for CHAIN-002 and CHAIN-005 only. It does not create
impact or severity assurance, negative controls, counterfactual evidence, repeated N-run policy, or
Finding confirmation. The inherited `independentExecutionAttested` marker means the existing
WALK-005B2 fresh execution invariant; local seals alone are not cryptographic proof of a separate
off-host organization or infrastructure.

VAL-002 must decide how Validation depth constrains the evidence required beyond this single fresh
validity Replay.

## Related documents

- [WALK-005B2 contract](WALK-005B2-plan-bound-mcp-claim-replay.md)
- [CHAIN-002 contract](CHAIN-002-file-upload-rag-tool-abuse.md)
- [CHAIN-005 contract](CHAIN-005-mcp-authorization-privileged-action.md)
- [ADR-0147](../adr/0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md)
