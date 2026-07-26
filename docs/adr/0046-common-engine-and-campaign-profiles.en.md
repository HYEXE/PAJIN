> Languages: [English](0046-common-engine-and-campaign-profiles.en.md) | [한국어](0046-common-engine-and-campaign-profiles.ko.md)

# ADR-0046: Common Engine and Campaign Profiles

- Status: Accepted
- Date: 2026-07-26

## Context

PAJIN's `ai-redteam`, `bug-bounty`, and `ctf` paths share safety boundaries but each owns parts of
execution, discovery, and reporting. That makes it difficult to represent a cross-surface chain,
such as an HTTP Observation enabling an AI tool-authorization Hypothesis, in common state. The
existing Mode paths also contain proven policy, evidence, replay contracts, and extensive
regression tests, so a wholesale move or deletion would be unsafe.

## Decision

1. PAJIN's target internal architecture is one policy-governed Common Attack Engine.
2. Operating differences among pentest, bug bounty, AI red team, and CTF are represented by a
   `CampaignProfile`. A Profile declares ROE defaults, reporting semantics, benchmark expectations,
   and a compatibility adapter, but cannot expand Campaign authorization.
3. AI remains a first-class `ai.*` Capability domain. It is neither the whole product framing nor
   a separate authority root.
4. Existing `CampaignMode` values, manifests, CLI commands, API routes, and Artifact readers remain
   supported during migration. Every legacy input compiles deterministically to a version-pinned
   Profile.
5. Profile compilation audit events preserve source Mode, profile ID/version, compiler ID/version,
   input digest, and output digest.
6. A Common Engine path does not become the default until identical fixtures prove parity with the
   legacy Mode path for Scope, Capability, ToolRequest, and expected outcomes.
7. Migration uses a feature-level strangler. Large `modes/` renames or directory moves require
   migrated consumers and proven parity in a separate decision.
8. CTF retains its fixed-lab, flag-validator, and non-submission boundaries. Profile representation
   cannot weaken those boundaries.

## Compatibility, migration, and rollback

- New Profile fields are initially internal projections, not required legacy wire fields.
- An unknown Profile/version, Mode/Profile mismatch, or compiler-digest mismatch fails closed.
- The adapter starts behind an explicit opt-in or feature flag.
- Failed parity or negative tests roll back by disabling the adapter and using the legacy path.
- Existing Artifacts and sealed Runs retain their authoring Mode/schema read semantics.

## Consequences

PAJIN can add a common attack flow and cross-surface Graph, at the temporary cost of adapters and
parallel paths. Proving parity takes precedence over deleting Mode-specific code. This ADR alone
does not change runtime behavior.

## Related documents

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.en.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.en.md)
- [ADR-0048: Minimum Graph and Admission Consistency](0048-minimum-graph-and-admission-consistency.en.md)
