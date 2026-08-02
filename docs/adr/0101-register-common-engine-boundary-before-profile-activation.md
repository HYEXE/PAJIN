# ADR-0101: Register the Common Engine Boundary Before Profile Activation

## Status

Accepted

## Context

PAJIN's existing multi-agent commands for `ai-redteam`, `bug-bounty`, and `ctf` route their
Mode-specific planners and validators through `MultiAgentCampaignRunner`. That runner owns shared
Campaign snapshot, budget, rate-limit, Capability, Policy, Worker, validation, and sealed-audit
behavior. Replacing it with another "common" runner would duplicate proven security boundaries.

The target architecture nevertheless requires deterministic `CampaignProfile` compilation and a
non-expanding `MissionEnvelope` before a Common Engine path can become executable. Neither Profile
authority nor legacy/common fixture parity exists yet. Treating the existing shared runner as an
activated Common Engine would therefore overstate the migration state.

## Decision

PAJIN will first publish a code-owned, content-addressed Common Campaign Engine contract over the
existing shared runner boundary. A legacy Campaign may be projected into a content-addressed
execution plan, but that plan is fixed to `profile-required-not-executable` and cannot issue a
Capability, Permit, Tool request, or Worker dispatch.

The contract fixes the three accepted source Modes, the six shared boundary stages, and four
mandatory parity dimensions: Scope, Capability, ToolRequest, and Outcome. The plan binds the
complete Campaign through the same canonical digest used by the existing Capability Graph and
`MissionEnvelope` source-Campaign path, plus the exact source Mode and registered contract.

Common execution remains false until later authorities bind deterministic Profile compilation, a
non-expanding `MissionEnvelope`, and parity evidence. Legacy commands remain the default path.

## Consequences

- ENG-001 records real shared implementation without creating a second runner.
- Campaign, Mode, contract, or parity-boundary substitution fails before any future activation.
- PROF-001 can define Profile semantics against one pinned engine boundary.
- PROF-002 can add deterministic legacy Mode compilation without changing legacy wire formats.
- No current runtime behavior, artifact reader, CLI command, or API route changes.

## Compatibility and rollback

The contracts and exports are additive. The existing `capability_graph_campaign_digest()` helper
retains its name and digest output while delegating to the shared domain helper. Rollback removes
the additive ENG-001 contracts and keeps every existing Mode path unchanged. Serialized ENG-001
plans remain historical non-executable records and never become authority by rollback or upgrade.

## Related documents

- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
- [ENG-001 contract](../orchestration/ENG-001-common-campaign-engine-contract.md)
