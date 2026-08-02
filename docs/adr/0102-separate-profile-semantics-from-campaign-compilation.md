# ADR-0102: Separate Profile Semantics from Campaign Compilation

## Status

Accepted

## Context

ADR-0046 requires Campaign Profiles for pentest, bug hunt, CTF, and AI assessment semantics while
preserving legacy Mode inputs. ADR-0047 requires every executable authority to remain a subset of
an approved Campaign. ENG-001 now pins the existing shared multi-agent boundary but deliberately
does not compile a Profile or authorize Common Engine execution.

Combining Profile registration, legacy Mode mapping, ROE default application, MissionEnvelope
compilation, and execution parity in one change would make it unclear whether semantic metadata or
the approved Campaign granted authority. It would also couple the first Profile wire format to a
premature compatibility adapter.

## Decision

PAJIN will first register four code-owned, content-addressed Profile identities and their operating,
reporting, and benchmark-expectation semantics. Every Profile binds the exact ENG-001 contract and
fixes ROE handling to `campaign-authority-only`. Its authority constraints require Campaign Scope
intersection and Campaign ceilings for authorization time, risk, and budget, plus a registered
Capability subset.

Profiles contain no Campaign, source Mode, target, credential, Capability grant, Tool request, or
MissionEnvelope. Exact resolution returns semantic authority only and does not select a Profile for
a Campaign. All adapter, Envelope, benchmark measurement, external submission, and execution flags
remain false.

Legacy Mode compilation and its required source/profile/compiler input/output digest audit belong
to PROF-002. Common execution and parity belong to ENG-002.

## Consequences

- Four product operating models have stable ID/version/digest authority without changing legacy
  wire formats.
- CTF fixed-lab, flag-validator, and non-submission semantics remain explicit.
- Reporting and benchmark expectations cannot be mistaken for produced or measured evidence.
- A standalone valid Profile is not registered unless it appears exactly in the code-owned catalog.
- Later compilers can bind existing `MissionEnvelope.profileId/profileVersion/profileDigest` fields
  without changing that wire shape.

## Compatibility and rollback

The Profile and catalog schemas, resolver, and exports are additive and are not wired to runtime
commands. Rollback removes them without changing existing Campaigns, Mode paths, sealed Runs, or
artifact readers. Historical Profile records never become execution authority through rollback.

## Related documents

- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0101: Register the Common Engine Boundary Before Profile Activation](0101-register-common-engine-boundary-before-profile-activation.md)
- [PROF-001 contract](../orchestration/PROF-001-campaign-profile-authority.md)
