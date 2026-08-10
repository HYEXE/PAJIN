# ADR-0153: Build Campaign Drafts without Compilation Authority

## Status

Accepted

## Context

Phase 9 needs a Campaign, Profile, and Scope builder that can power later CLI and Control Plane user
experiences. The repository already has three separate boundaries that must not be collapsed:

- PROF-001 registers non-executable Profile semantics and does not select a Profile for a Campaign;
- `BugBountyScopeService` converts a reviewed program policy into a Campaign only after an exact
  scope-digest approval and active authorization check; and
- `CTFChallengeService` accepts only typed local challenge inputs and rechecks the challenge
  authorization window when it compiles a Campaign.

A builder that emitted `CampaignManifest`, `SubmitRunRequest`, `MissionEnvelope`, Capability, or
Permit objects would either duplicate those compilers or allow a UI selection to cross an existing
authority boundary. A generic editable Scope model would also lose the stronger Bug Bounty policy
and CTF target constraints.

## Decision

PAJIN will introduce the UX-001A `CampaignProfileScopeDraft` as a content-addressed, non-executable
projection of one existing typed compiler input. The first version accepts exactly one
`BugBountyProgramManifest` or one `CTFChallengeManifest` and requires an explicit exact PROF-001
Profile selection:

- Bug Bounty Program to `pajin.profile.bug-hunt@1.0.0`; and
- CTF Challenge to `pajin.profile.ctf@1.0.0`.

The draft embeds a detached copy of the complete typed source, the exact registered Profile and
catalog digest, an exact source digest, a derived Scope and target-input preview, the existing
compiler entrypoint identifier, and the gates that compiler must still enforce. Bug Bounty drafts
separately expose the existing canonical scope-review approval digest. Source digests preserve
ordered input fields while canonically sorting only typed set fields and use a domain-separated
digest for each source kind.

The preview is reconstructed from the embedded source whenever a draft is loaded. It marks
concrete `generic-http` Bug Bounty assets and assets without entry points as review-only instead of
silently omitting that limitation. CTF Web and Crypto target inputs use the same fixed entry point
or content-addressed artifact target as their existing compiler.

All authority flags are fixed false. A draft does not contain a Campaign, approval, execution Job,
`MissionEnvelope`, Capability, Permit, or Worker request. It cannot invoke its compiler and is not
wired to the CLI, Control Plane submission API, or a persistent draft store. Existing compilers
remain the only path that can produce a Campaign and must independently revalidate approvals,
authorization time, supported probe profiles, budgets, and policy constraints.

Pentest and AI Assessment are not accepted because they do not yet have a corresponding typed
builder source contract. CTF Suite composition is also outside this first single-source draft.

## Consequences

- Later product surfaces can render one deterministic Profile and Scope preview without inventing
  a second Campaign schema.
- Source, Profile, catalog, preview, compiler-entrypoint, gate, digest, and false-authority
  substitution fail closed on wire reload.
- Existing Bug Bounty review-only inputs remain blocked by the existing compiler.
- Existing CTF authorization expiry remains effective because the builder does not compile a
  Campaign or evaluate the authorization as an execution decision.
- A later editing or persistence API must produce a newly validated typed source and a new draft;
  it cannot patch the derived preview into authority.

## Compatibility and rollback

The draft schema, builder function, exports, tests, contract, and decision are additive. No
existing Campaign, Mode input, CLI command, Control Plane route, compiler, sealed Run, artifact
reader, or execution default changes. Rollback removes the additive UX-001A API. Serialized drafts
remain non-executable data and cannot be consumed by existing execution paths.

## Related documents

- [ADR-0013: Digest-approved Bug Bounty Scope Parser](0013-bug-bounty-scope-parser.md)
- [ADR-0017: Local-only CTF Web Mode vertical slice](0017-local-ctf-web-mode.md)
- [ADR-0102: Separate Profile Semantics from Campaign Compilation](0102-separate-profile-semantics-from-campaign-compilation.md)
- [ADR-0103: Compile Legacy Modes to Profile Semantics Only](0103-compile-legacy-modes-to-profile-semantics-only.md)
- [UX-001A contract](../orchestration/UX-001A-campaign-profile-scope-builder-draft.md)
