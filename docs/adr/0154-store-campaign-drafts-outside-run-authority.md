# ADR-0154: Store Campaign Drafts outside Run Authority

## Status

Accepted

## Context

UX-001A introduced a content-addressed `CampaignProfileScopeDraft`, but intentionally provided no
persistence or operator entry point. Phase 9 now needs a durable identity that an operator can
create and inspect before a later compiler handoff.

The existing `RunStore` records execution events, evidence, and seals. The Control Plane managed
artifact repository admits artifacts only through a verified sealed Run and its admission
authority. A Campaign Builder draft is neither execution evidence nor an admitted Run artifact.
Putting it in either store would imply lifecycle and authority that the draft does not possess.

The draft embeds the complete typed source, including Bug Bounty policy text, and therefore also
needs bounded, unambiguous, no-follow local file handling. A caller-selected preview or a filename
must not become a substitute for the draft's content identity.

## Decision

UX-001B1 stores each draft as one local strict-JSON artifact at:

`<output-root>/<draftDigest>/campaign-profile-scope-draft.json`

The writer first reconstructs the complete draft and canonicalizes only the typed set-valued Bug
Bounty fields that the source digest already treats as sets. It writes through the existing
symlink-safe atomic text writer, then reads the artifact back through the same public verifier.
The reader enforces a 4 MiB byte limit, bounded JSON depth and node count, duplicate-key and
non-finite-number rejection, no-follow parent and leaf traversal, and exactly one hard link. It
then reconstructs the complete `CampaignProfileScopeDraft`, which re-derives the registered
Profile, source digest, Scope preview, compiler identifier, remaining gates, draft digest, and all
false authority markers.

The CLI exposes `campaign-draft-create` and `campaign-draft-inspect`. Creation accepts only the
two exact UX-001A Profile/source mappings and writes under a caller-selected local output root.
Inspection renders bounded metadata and counts; it does not print the embedded source or invoke a
compiler.

No draft ledger is added. The content-addressed directory is the durable local identity. This
artifact is not inserted into `RunStore`, the managed Control Plane artifact repository, or the
Canonical Graph. It is not a `CampaignManifest`, approval, Capability, Permit, submission request,
or Worker input.

## Consequences

- Repeated writes of the same validated draft converge on one deterministic path and canonical
  wire representation.
- Source, Profile, preview, digest, compiler, gate, and authority substitution fail closed on every
  read rather than trusting the path or prior in-memory validation.
- Symbolic-link, junction, hard-link alias, oversized, ambiguous JSON, and replacement races are
  rejected by the existing safe-file boundary.
- The complete typed source remains available for a later explicit handoff without treating the
  derived preview as compiler input.
- Control Plane read exposure, editing, retention, and compiler invocation remain separate work.

## Compatibility and rollback

The artifact functions, workflow exports, and two CLI commands are additive. Existing Run,
Control Plane, Graph, Campaign, compiler, approval, and execution behavior is unchanged. No data
migration is required. Rollback removes the commands and artifact API; already written files
remain inert strict JSON with no runtime consumer.

## Related documents

- [ADR-0153: Build Campaign Drafts without Compilation Authority](0153-build-campaign-drafts-without-compilation-authority.md)
- [UX-001A contract](../orchestration/UX-001A-campaign-profile-scope-builder-draft.md)
- [UX-001B1 contract](../orchestration/UX-001B1-local-campaign-draft-artifact.md)
