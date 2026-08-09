# CHAIN-001: Mode-neutral Auth Bypass to AI Admin Surface

## Purpose

Define the first mode-neutral attack-chain contract without claiming that authentication was
bypassed, a Finding was validated, or any action was authorized. CHAIN-001 links one explicit
authentication boundary to the same-route AI/RAG index-management boundary inside an exact sealed
Surface Snapshot.

## Inputs and predecessor authority

The compiler accepts:

- one canonical `CampaignManifest`;
- one `ReconWaveOutcome` whose source and projection Runs pass the existing
  `load_recon_surface_authority()` verifier; and
- exact source and target `AttackSurface` IDs from that verified `AttackSurfaceSet`.

It reuses the ORCH-001 `SurfaceSnapshotAuthority`, including the exact Campaign digest, source and
projection Run roots, published artifact SHA-256, and Surface Set identity. The chain digest is not
a signature and does not replace that predecessor verification.

## Registered chain semantics

`chain-001:auth-bypass-to-ai-admin-surface@1.0.0` requires:

1. a source `http-authentication` locator that does not allow anonymous access;
2. a target `http-rag` locator with the explicit `index-management` boundary;
3. both locators to bind the exact same `HTTPRouteSurfaceLocator`;
4. both Surfaces to bind the same Campaign target; and
5. that target to occur exactly once in the sealed Campaign.

The compiler does not infer administration from URL text, operation names, descriptions, generic
schemas, or model output. In v1, only the explicit DISC-003C `x-pajin-rag` index-management
declaration supplies the typed AI administration boundary.

## Mode neutrality

The registered contract has `campaignModeConstraint=none`. Compilation does not branch on
`ai-redteam`, `bug-bounty`, or `ctf`; all three use the same code-owned contract and invariants.
The exact Campaign digest remains in the authority, so mode neutrality cannot be used to relabel a
sealed Campaign or replay a chain across Campaign authority.

## Output and authority ceiling

`ModeNeutralAttackChainAuthority` content-addresses:

- the exact registered contract;
- the ORCH-001 Surface Snapshot;
- bounded source and target Surface references with locator and complete Surface digests; and
- the canonical same-route digest.

Its state is fixed to `hypothesized-not-validated`. `surfaceEvidenceOnly=true`, while Capability,
execution, Claim Replay, and Finding confirmation markers are all false. It creates no
`AttackHypothesis` execution plan, Tool request, Capability Grant, ActionPermit, replay ticket,
validation decision, or confirmed Finding.

## Fail-closed boundaries

Compilation or verification rejects:

- missing, malformed, unsealed, mutated, or cross-Campaign Recon authority;
- missing or ambiguous Surface IDs;
- anonymous authentication alternatives;
- non-authentication source or non-RAG target substitution;
- RAG boundaries other than `index-management`;
- different routes or Campaign targets;
- unregistered or forged chain contracts;
- Campaign, Snapshot, locator, Surface, route, or authority digest substitution; and
- verification against another Recon publication, even when canonical Surface identities happen
  to be equal.

## Compatibility and rollback

The contract is additive. Existing Discovery, ORCH-001, Graph, Campaign Profile, legacy Mode,
Capability, validation, and Replay wires do not change. Rollback removes the CHAIN-001 compiler and
public exports; sealed Surface and Recon artifacts remain readable under their original schemas.

## Current limitations

CHAIN-001 records only a candidate coverage link. It does not prove an authentication bypass, AI
administrative access, exploitability, impact, or severity. UI-only administration, MCP
administration, model-provider consoles, and non-RAG admin surfaces are outside v1. VAL-001 or a
later chain-specific evidence bridge must bind independent execution and Claim Replay before any
validation state can advance.

## Related documents

- [DISC-003 Surface adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ORCH-001 Surface Snapshot binding](ORCH-001-surface-snapshot-plan-task-binding.md)
- [PROF-001 Campaign Profile authority](PROF-001-campaign-profile-authority.md)
- [ADR-0142](../adr/0142-bind-mode-neutral-chain-to-surface-snapshot.md)
