# CHAIN-002: Mode-neutral File Upload to RAG Injection to Tool Abuse

## Purpose

Represent the existing WALK-002/003 File Upload -> RAG Injection -> Tool Abuse lineage as one
ordered, mode-neutral coverage contract without relabeling a Hypothesis as execution, validation,
or benchmark evidence.

## Inputs and predecessor authority

The compiler accepts one canonical `CampaignManifest` and one
`MCPToolAuthorizationHypothesisOutcome`. It reopens the WALK-003 Run through
`load_sealed_mcp_authorization_hypothesis_dependency()` and verifies its Campaign, artifact,
publication event, Run root, and exact single Hypothesis. That WALK-003 authority already carries
the sealed WALK-002 Run root, artifact SHA-256, RAG Hypothesis, and Surface Snapshot it consumed.

CHAIN-002 does not create another Surface, Hypothesis, Capability, execution, or validation store.
It binds the existing content-addressed predecessor coordinates into a separate coverage
authority.

## Registered stages and edges

`chain-002:file-upload-rag-injection-tool-abuse@1.0.0` fixes this exact order:

1. `file-upload`: the WALK-002 upload Surface and `not-authorized` RAG Hypothesis authority;
2. `rag-injection`: the co-located WALK-002 corpus-ingest RAG Surface and the same Hypothesis; and
3. `tool-abuse`: the WALK-003 MCP server and Tool Surfaces, registered Capability definition, and
   `registered-not-authorized` Hypothesis authority.

Two ordered `enables` edges connect File Upload to RAG Injection and RAG Injection to Tool Abuse.
`AttackChainStageContract`, `AttackChainEdgeContract`, and `AttackChainStageReference` are additive
step/edge primitives that later mode-neutral chains can reuse without changing CHAIN-001's wire
shape.

Each stage reference binds its ordinal, semantic, predecessor kind and digest, Run root, artifact
SHA-256, exact Campaign target, Surface Snapshot, Surface IDs, and closed execution state. The
RAG and MCP stages may use different targets, but both targets must be declared exactly once by the
same sealed Campaign.

## Mode neutrality and P0-D2B boundary

The contract has `campaignModeConstraint=none`, while the authority retains both the exact WALK
Campaign digest and the canonical source Campaign digest. Compilation therefore uses the same
topology for `ai-redteam`, `bug-bounty`, and `ctf` without permitting cross-Campaign replay.

P0-D2B's runnable local-Docker scenario was used to cross-check the stage meanings and order. The
contract records its profile identity only as `semanticCrossCheck`. It does not accept Docker
provider evidence, matcher output, measured counts, or a benchmark Finding;
`fixtureEvidenceAdmitted=false` remains fixed.

## Authority ceiling

`ModeNeutralWalkingAttackChainAuthority` is fixed to `hypothesized-not-validated` and
`hypothesisEvidenceOnly=true`. Capability Grant, execution authorization, Claim Replay, and Finding
confirmation are all false. The Capability definition nested in WALK-003 remains registration
metadata and is not a Grant, Permit, Tool request, or dispatch authority.

## Fail-closed boundaries

Compilation and verification reject:

- malformed, unsealed, mutated, or cross-Campaign WALK-003 outcomes;
- WALK-002 or WALK-003 rules that differ from their code-owned registrations;
- missing or undeclared RAG and MCP Campaign targets;
- omitted, repeated, or reordered stages and changed edge topology;
- Campaign, target, Surface Snapshot, Surface, Run, artifact, Hypothesis, or digest substitution;
- execution or validation marker escalation; and
- verification against another sealed WALK publication, even if its semantics are otherwise equal.

## Compatibility and rollback

The API version remains `pajin.dev/mode-neutral-attack-chain/v1alpha1`, with new kinds and public
exports added alongside CHAIN-001. Existing CHAIN-001, WALK-002/003, P0-D2B, Capability, Replay,
Finding, and benchmark wires do not change. Rollback removes the CHAIN-002 types, compiler, verifier,
and loader export while retaining all sealed predecessor artifacts.

## Current limitations

CHAIN-002 records a coverage hypothesis only. It does not prove document upload, retrieval, MCP
argument influence, missing approval, Tool execution, internal data access, impact, or severity.
VAL-001 must add a separate mode-neutral Claim Replay authority before validation can advance.

## Related documents

- [WALK-002 contract](WALK-002-rag-injection-hypothesis.md)
- [WALK-003 contract](WALK-003-mcp-tool-authorization-hypothesis.md)
- [P0-D2B runnable fixture](../benchmark/P0-D2B-local-ai-rag-mcp-docker-provider.md)
- [CHAIN-001 contract](CHAIN-001-mode-neutral-auth-bypass-ai-admin.md)
- [ADR-0143](../adr/0143-bind-walking-lineage-to-mode-neutral-chain.md)
