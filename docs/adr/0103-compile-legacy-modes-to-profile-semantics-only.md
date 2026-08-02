# ADR-0103: Compile Legacy Modes to Profile Semantics Only

## Status

Accepted

## Context

PROF-001 registers four non-executable Campaign Profile identities. ADR-0046 requires legacy inputs
to compile deterministically to version-pinned Profiles with source Mode, compiler identity, input,
and output digest audit lineage. Applying Profile defaults or compiling a `MissionEnvelope` in the
same compatibility step would blur semantic mapping with execution authority and make parity
rollback difficult.

The current Campaign wire is `pajin.dev/v1alpha1` and has three Mode values. Pentest has a Profile
but no legacy Mode.

## Decision

PAJIN will implement one code-owned compatibility compiler with exactly three mappings:
`ai-redteam` to `ai-assessment`, `bug-bounty` to `bug-hunt`, and `ctf` to `ctf`. The compiler binds
its ID/version/digest, the exact PROF-001 catalog, every mapping digest, and the accepted Campaign
API version.

Compilation preserves and embeds the complete Campaign, records its canonical digest as input,
and emits only a Profile semantic projection as output. The projection binds source Mode, Profile,
compiler, and catalog identity. It applies no ROE defaults, mutates no Campaign field, selects no
pentest Profile, compiles no `MissionEnvelope`, and grants no execution.

The content-addressed compilation authority is suitable as a later audit payload, but this slice
does not claim a persisted event or sealed Run because no legacy runtime path is wired to it yet.

## Consequences

- Every current legacy Mode has one exact Profile identity without changing legacy wire bytes.
- Compiler, catalog, Profile, Campaign, and output substitution fail closed on wire reload.
- Unsupported future Campaign API versions require an explicit compiler version change.
- Pentest remains an explicit Profile choice for a future non-legacy entry point.
- ENG-002 can consume this audit authority only after proving Campaign attenuation and legacy/common
  fixture parity.

## Compatibility and rollback

The compatibility API is additive and direct-call opt-in. Existing commands, APIs, planners,
validators, sealed Runs, and readers remain unchanged. Rollback removes the compiler API and leaves
all legacy paths as before; stored authorities remain non-executable records.

## Related documents

- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.md)
- [ADR-0101: Register the Common Engine Boundary Before Profile Activation](0101-register-common-engine-boundary-before-profile-activation.md)
- [ADR-0102: Separate Profile Semantics from Campaign Compilation](0102-separate-profile-semantics-from-campaign-compilation.md)
- [PROF-002 contract](../orchestration/PROF-002-legacy-mode-profile-compatibility.md)
