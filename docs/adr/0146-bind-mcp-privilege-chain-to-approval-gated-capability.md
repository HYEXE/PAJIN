# ADR-0146: Bind MCP Privilege Chains to Approval-gated Capabilities

- Status: Accepted
- Date: 2026-08-10

## Context

CHAIN-005 needs to represent MCP Authorization Failure -> Privileged Action across every legacy
Campaign mode. WALK-003 already seals an exact MCP server and tool Surface, registered invocation,
full `CapabilityDefinition`, independent user-approval control, and the closed
`registered-not-authorized` state.

PAJIN does not have a separate universal privileged-action registry. Inferring privilege from a
Tool name, description, risk tier, side-effect label, argument content, or synthetic Finding would
let descriptive or target-controlled data manufacture attack-chain authority. A registered
Capability that requires independent approval is an explicit bounded privilege boundary, but it
does not prove that authorization failed, approval was granted, or the action executed.

## Decision

1. Reuse the exact sealed WALK-003 `MCPToolAuthorizationHypothesisAuthority` as the sole predecessor.
   Do not add another locator, store, or mutable publication.
2. Define CHAIN-005 `privileged-action` narrowly as the exact registered MCP
   `CapabilityDefinition` whose `approvalRequired` value is true and whose enclosing WALK-003
   authority requires `independent-user-approval`.
3. Register two ordered stages: `mcp-authorization-failure` and `privileged-action`, joined by one
   `enables` edge.
4. Bind the action digest to the exact Campaign target, MCP server and tool Surfaces and locators,
   complete Capability, registered invocation, authorization control, and
   `registered-not-activated` state.
5. Reopen the sealed WALK-003 Run and artifact through the existing dependency loader. Verification
   rebuilds the complete CHAIN-005 authority and requires exact equality.
6. Keep the chain mode-neutral and `hypothesized-not-validated`. Authorization failure, approval,
   Capability Grant, privileged execution, execution authorization, Claim Replay authorization,
   and Finding confirmation remain false.
7. Treat risk tier and side-effect classification as retained Capability coordinates, not as
   alternate privilege inference rules.

## Consequences

- CHAIN-005 gains a deterministic coverage hypothesis without creating duplicate execution or
  approval authority.
- Exact Campaign, Run root, artifact SHA-256, WALK-003 hypothesis, Capability, Surface, invocation,
  and approval-control coordinates remain auditable.
- Non-approval Capabilities, stale or equivalent publications, mutated artifacts, reordered stages,
  forged action digests, and authority-marker escalation fail closed.
- The same topology applies to `ai-redteam`, `bug-bounty`, and `ctf`, while retaining the exact
  Campaign identity.
- The word privileged remains deliberately bounded to the registered independent-approval gate;
  it is not a claim about operating-system privilege, business impact, or successful access.

## Rejected alternatives

### Add a universal privileged-action registry

Rejected because the current slice has one exact MCP Capability predecessor. A second registry
would duplicate Capability and approval authority before another consumer requires it.

### Infer privilege from risk tier or side effect

Rejected because those classifications do not themselves establish an approval boundary and can
change independently of the registered invocation contract.

### Infer privilege from Tool metadata or Findings

Rejected because names and descriptions are descriptive input, while Findings belong to a later
validated evidence boundary.

### Treat the WALK-003 hypothesis as a confirmed authorization failure

Rejected because WALK-003 records a testable hypothesis with no failed request, approval decision,
Grant, Permit, dispatch, or observed outcome.

## Compatibility and rollback

The change is additive. Existing WALK-003, Capability, approval, Permit, Replay, Finding, and
CHAIN-001/002/003/004 artifacts keep their meanings. Rollback removes the CHAIN-005 contract,
compiler, verifier, tests, and public exports without rewriting predecessor Runs or allowing
another authority kind to fill either stage.

## Related documents

- [CHAIN-005 contract](../orchestration/CHAIN-005-mcp-authorization-privileged-action.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [CHAIN-002 contract](../orchestration/CHAIN-002-file-upload-rag-tool-abuse.md)
- [ADR-0143](0143-bind-walking-lineage-to-mode-neutral-chain.md)
