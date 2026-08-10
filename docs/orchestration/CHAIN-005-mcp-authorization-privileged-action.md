# CHAIN-005: MCP Authorization Failure to Privileged Action

## Purpose

Represent one sealed MCP authorization-failure hypothesis and its exact registered,
independent-approval-gated Capability as a mode-neutral coverage chain without granting approval,
execution, Replay, or Finding authority.

## Inputs and predecessor authority

The compiler accepts one canonical `CampaignManifest` and one
`MCPToolAuthorizationHypothesisOutcome`. It calls
`load_sealed_mcp_authorization_hypothesis_dependency()`, which verifies the sealed WALK-003 Run
root, artifact path and SHA-256, publication event, Campaign lineage, and in-memory outcome
equality.

The selected WALK-003 authority must use the exact code-owned MCP authorization rule, threat class
`mcp-tool-authorization-failure`, control `independent-user-approval`, and execution state
`registered-not-authorized`. Its exact Campaign target must be declared once. Its
`CapabilityDefinition` must advertise the `mcp-tool` Surface type, include that threat class, and
set `approvalRequired=true`.

## Registered stages and edge

`chain-005:mcp-authorization-failure-privileged-action@1.0.0` fixes this exact order:

1. `mcp-authorization-failure`: the sealed WALK-003 authority, recorded only as an
   `independent-approval-failure-hypothesis`; and
2. `privileged-action`: the exact registered `CapabilityDefinition`, recorded only as a
   `registered-approval-gated-mcp-capability`.

One ordered `enables` edge connects the stages. The first stage has
`authorityKind=MCPToolAuthorizationHypothesisAuthority` and
`executionState=registered-not-authorized`. The second has
`authorityKind=CapabilityDefinition` and `executionState=registered-not-activated`.

Each stage binds the exact source Run ID and root, artifact path and SHA-256, hypothesis ID and
digest, subject kind, subject ID, and subject digest. The privileged-action digest additionally
binds the Target, server and tool Surface IDs and locators, full Capability, registered invocation,
approval control, and closed action state.

## Privileged-action meaning

For CHAIN-005, privileged means only that the exact registered MCP Capability requires independent
user approval. Risk tier and side-effect classification remain part of the full Capability digest
but are not alternate inference rules. Tool names, descriptions, arguments, observed-looking text,
and synthetic Findings cannot create or substitute privileged-action authority.

This definition does not claim operating-system privilege, administrative access, data access,
business impact, or successful action execution.

## Mode neutrality and authority ceiling

The contract has `campaignModeConstraint=none`; its topology is identical for `ai-redteam`,
`bug-bounty`, and `ctf`. It retains the exact Campaign and WALK-003 lineage and does not permit
cross-Campaign or cross-publication replay.

`ModeNeutralMCPPrivilegeAttackChainAuthority` is fixed to `hypothesized-not-validated` and
`hypothesisEvidenceOnly=true`. Authorization failure confirmation, approval, Capability Grant,
privileged action execution, execution authorization, Claim Replay authorization, and Finding
confirmation are false. The compiler and verifier create no approval receipt, Grant, Permit,
ToolRequest, dispatch, Worker result, Replay, Report, or benchmark result.

## Fail-closed boundaries

Compilation and verification reject:

- malformed, unsealed, mutated, stale, or cross-Campaign WALK-003 authority;
- a Campaign target that is missing or not declared exactly once;
- a non-code-owned rule, changed threat class, changed approval control, or open execution state;
- a Capability without independent approval, MCP Surface support, or the exact threat class;
- reordered stages, changed edge topology, forged action or authority digests, and boolean marker
  coercion or escalation;
- verification against another sealed publication even when its semantics are equal; and
- attempts to infer privilege or validation from risk labels, side-effect labels, Tool metadata,
  arguments, or synthetic Findings.

## Audit artifacts and events

No new mutable store or event family is introduced. The authority embeds the existing sealed
WALK-003 dependency, which identifies the source Run root, publication artifact, exact
authorization hypothesis, MCP Surfaces, invocation, and Capability. That predecessor Run remains
the audit authority.

## Compatibility and rollback

The new API version is `pajin.dev/mode-neutral-mcp-privilege-attack-chain/v1alpha1`. The addition is
a compiler, verifier, immutable contract and authority, stage reference type, tests, and public
exports. Existing WALK-003 and CHAIN-001/002/003/004 wire meanings do not change.

Rollback removes those additions while preserving sealed predecessor Runs and the rule that no
other metadata can fill the privileged-action stage.

## Current limitations

WALK-003 is a registered authorization hypothesis, not evidence of an actual failed authorization
check. CHAIN-005 does not observe an approval denial or bypass, does not grant or execute the
Capability, and does not establish impact. VAL-001 must introduce an exact Claim and independent
fresh Replay authority before this chain can advance beyond a coverage hypothesis.

## Related documents

- [WALK-003 contract](WALK-003-mcp-tool-authorization-hypothesis.md)
- [CHAIN-002 contract](CHAIN-002-file-upload-rag-tool-abuse.md)
- [ADR-0146](../adr/0146-bind-mcp-privilege-chain-to-approval-gated-capability.md)
- [ADR-0143](../adr/0143-bind-walking-lineage-to-mode-neutral-chain.md)
