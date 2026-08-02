# ADR-0104: Register Implementation Identity Before Runtime Parity

## Status

Accepted

## Context

PROF-002 deterministically maps legacy Campaigns to semantic Profiles but does not identify the
Planner, Validator, or shared workflow implementation that would serve that Profile. ADR-0046
requires parity for Scope, Capability, ToolRequest, and Outcome before a Common path becomes the
default.

Running a new path before the implementation boundary is pinned would make parity results
ambiguous. Conversely, treating equal class names as behavioral parity would ignore constructor
configuration, Tool/Policy/Worker state, generated requests, outcomes, and Mode post-processing.

## Decision

PAJIN will register exact module-qualified class identities for each existing Mode Planner and
Validator, the AI candidate producer, and the shared `MultiAgentCampaignRunner`, scheduler, and
projector. A content-addressed adapter catalog binds these identities to the exact PROF-002
compiler and ENG-001 contract.

Adapter selection revalidates the complete PROF-002 authority and records all four required parity
dimensions. The evidence is structural identity only. Every dimension remains unmeasured and
unproven, fixture parity remains false, and no runtime is constructed.

The catalog may authorize metadata selection, but construction, Tool Registry, Policy, Worker,
output path, `MissionEnvelope`, and Common execution remain unauthorized.

## Consequences

- Cross-Mode implementation substitution fails before future runtime construction.
- The shared scheduler/projector boundary is explicit without duplicating those components.
- Structural schema completeness cannot be mistaken for fixture or behavioral parity.
- ENG-002B has exact identities against which to bind constructor inputs, requests, receipts,
  outcomes, and Mode-specific post-processing.
- Module-qualified identities are code contracts, not binary or supply-chain attestations.

## Compatibility and rollback

All schemas, catalogs, selection functions, and exports are additive and direct-call opt-in.
Existing runtime paths are untouched. Rollback removes the structural selection layer; serialized
records remain non-executable and do not prove parity.

## Related documents

- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0101: Register the Common Engine Boundary Before Profile Activation](0101-register-common-engine-boundary-before-profile-activation.md)
- [ADR-0103: Compile Legacy Modes to Profile Semantics Only](0103-compile-legacy-modes-to-profile-semantics-only.md)
- [ENG-002A contract](../orchestration/ENG-002A-common-engine-implementation-adapter.md)
