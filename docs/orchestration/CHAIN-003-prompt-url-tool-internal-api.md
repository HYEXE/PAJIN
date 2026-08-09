# CHAIN-003: Prompt Injection to URL Tool Control to Internal API

## Purpose

Represent an advertised MCP prompt, a URL-bearing MCP Tool input, and a Target-declared Internal API
as one ordered, mode-neutral coverage hypothesis without claiming prompt influence, network
reachability, Tool execution, API access, or validation.

## Typed discovery prerequisites

`MCPURLToolSurfaceLocator` is emitted only for a registered MCP discovery result whose top-level
JSON Schema property has exact `type=string` and `format=uri`. It retains the argument name and
strict boolean required flag plus the Tool schema digest. Runtime URL values, descriptions, and raw
schemas are not admitted.

`HTTPInternalAPISurfaceLocator` wraps one exact `HTTPRouteSurfaceLocator` only when the OpenAPI
operation contains `x-pajin-internal-api: true`. A missing marker emits no Internal API Surface;
non-boolean markers are rejected. `HTTPInternalAPIReconPlanner` additionally requires that exact
Surface kind before a Recon wave can complete.

These locators do not classify a Tool or route from its name, description, URL text, DNS result,
address range, or observed reachability.

## Inputs and predecessor authority

The compiler accepts one canonical `CampaignManifest`, one MCP boundary `ReconWaveOutcome`, one
Internal API `ReconWaveOutcome`, and three exact Surface IDs. It calls
`load_recon_surface_authority()` for both outcomes, which re-verifies each sealed source Campaign and
Recon Plan, source Run root, projection Run root, publication event, artifact digest, and in-memory
outcome equality.

Both resulting `SurfaceSnapshotAuthority` objects must carry the same exact Campaign ID and digest.
The MCP prompt and URL Tool must have the same server ID and Campaign target. The Internal API may
use another target, but both target IDs must each be declared exactly once by that Campaign.

## Registered stages and edges

`chain-003:prompt-injection-url-tool-internal-api@1.0.0` fixes this exact order:

1. `prompt-injection`: a non-empty advertised MCP prompt input, recorded only as a
   `prompt-injection-hypothesis`;
2. `url-tool-control`: an exact `MCPURLToolSurfaceLocator`, recorded only as an
   `mcp-url-argument-control-hypothesis`; and
3. `internal-api`: an exact `HTTPInternalAPISurfaceLocator`, recorded as a
   `target-declared-internal-api-surface` rather than reachability.

Two ordered `enables` edges connect Prompt Injection to URL Tool Control and URL Tool Control to the
Internal API. Every stage has `authorityKind=SurfaceSnapshotAuthority` and
`executionState=discovered-not-authorized`.

Each Surface reference binds the exact Surface ID, Campaign target, locator kind and content,
locator digest, Surface digest, and observation count. Each stage additionally binds its Snapshot
ID and digest. Verification rebuilds all of those coordinates from the two sealed Recon outcomes
and requires exact equality.

## Mode neutrality and authority ceiling

The contract has `campaignModeConstraint=none`; its topology is identical for `ai-redteam`,
`bug-bounty`, and `ctf`. Mode neutrality does not remove Campaign authority or permit cross-Campaign
replay.

`ModeNeutralURLAttackChainAuthority` is fixed to `hypothesized-not-validated`,
`surfaceEvidenceOnly=true`, and `crossTargetBinding=same-campaign-hypothesis-only`. Capability Grant,
execution authorization, Claim Replay authorization, and Finding confirmation are false. Neither
the chain compiler nor its verifier creates a Tool request, Permit, dispatch, network observation,
Replay, Report, or benchmark result.

## Fail-closed boundaries

Compilation and verification reject:

- malformed, unsealed, mutated, stale, or cross-Campaign Recon outcomes;
- a generic MCP Tool substituted for an exact URL Tool Surface;
- a generic HTTP route substituted for an explicit Internal API Surface;
- prompt and URL Tool Surfaces from different targets or MCP servers;
- prompts without a declared argument boundary;
- missing Campaign targets or different Campaign digests between Snapshots;
- reordered stages, changed edge topology, forged locator or authority digests, and boolean marker
  coercion or escalation;
- verification against another sealed publication even when its discovered semantics are equal;
  and
- any attempt to treat a runtime URL value, Tool description, raw schema, private address, or route
  name as chain authority.

## Audit artifacts and events

No new mutable chain store or event family is introduced. The authority retains the two existing
`SurfaceSnapshotAuthority` values, which identify the sealed source and projection Runs,
publication artifact paths and SHA-256 digests, and Surface Set IDs. Those predecessor Runs remain
the audit authority.

## Compatibility and rollback

The new API version is `pajin.dev/mode-neutral-url-attack-chain/v1alpha1`. All additions are new
kinds, a dedicated planner, compiler, verifier, and public exports. Existing MCP/HTTP locators,
CHAIN-001/002, Campaign, Capability, Replay, Finding, and benchmark artifacts do not change.
Rollback removes the additions while preserving sealed predecessor Runs and the rule that generic
locators cannot stand in for CHAIN-003 roles.

## Current limitations

CHAIN-003 does not prove that prompt text controls a Tool argument, that a URL Tool is invocable,
that any URL resolves or is reachable, that an Internal API accepts a request, or that data is
exposed. The demo `inspect_url` Tool is advertised for discovery but remains outside the invocation
allowlist. VAL-001 must introduce separate exact Claim and independent Replay authority before the
chain can advance beyond a coverage hypothesis.

## Related documents

- [CHAIN-002 contract](CHAIN-002-file-upload-rag-tool-abuse.md)
- [CHAIN-001 contract](CHAIN-001-mode-neutral-auth-bypass-ai-admin.md)
- [ADR-0144](../adr/0144-bind-url-tool-chain-to-explicit-surface-authority.md)
