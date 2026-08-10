# ADR-0155: Expose Campaign Drafts as Redacted Operator Views

## Status

Accepted

## Context

UX-001B1 stores a complete typed Campaign Builder source in a content-addressed local artifact. An
operator now needs to retrieve a draft through the authenticated Control Plane before the later
compiler-handoff slice. The caller must not select a filesystem path, and the API must not turn a
draft into a managed Run artifact or imply approval, compilation, or execution authority.

The complete artifact can contain Bug Bounty policy text, target endpoints, authorization
evidence, and other operator-controlled source data. Returning that wire object merely because an
authenticated principal knows its digest would widen the existing Control Plane data-exposure
boundary. Approver and Auditor roles also do not need this pre-compilation source to perform their
current duties.

## Decision

The Control Plane adds one operator-only endpoint:

`GET /v1/campaign-drafts/{draft_digest}`

`draftDigest` must be exactly 64 lowercase hexadecimal characters. The server resolves it only as
`<PAJIN_CP_CAMPAIGN_DRAFT_ROOT>/<draftDigest>/campaign-profile-scope-draft.json`; no request field,
query parameter, or stored object may supply another path. The independently configured root is
optional. A configured root is not a Run store, managed Artifact repository, or new draft ledger.

Every lookup reuses the UX-001B1 public reader, including bounded strict JSON, no-follow path,
single-hardlink, stable-file, complete typed-source, Profile, preview, digest, gate, and false
authority verification. After validation, the reader compares the reconstructed draft digest with
the requested directory digest. Missing, invalid, tampered, and directory-substituted artifacts
share one non-reflective not-found response.

The response is a new redacted `CampaignDraftView`. It contains draft and Profile identity, source
kind, bounded Scope and target counts, remaining gate identifiers, draft state, and explicit false
authority markers. It excludes the embedded source, source and approval digests, policy text,
target identifiers and endpoints, allow/deny values, compiler entrypoint, and artifact path.

Only the Operator role may access the route. Approver, Auditor, and Worker credentials remain
denied. The route invokes no compiler and creates no approval, Campaign, Capability, Permit, Run,
Graph record, or managed Artifact admission.

## Consequences

- An operator can find a verified draft by content identity without supplying an arbitrary path.
- Knowledge of a digest does not expose the complete typed source through the Control Plane.
- A copied valid artifact under another digest directory cannot substitute for that digest.
- Existing authorization separation remains intact; a draft view is not an approval queue item or
  audit evidence.
- Editing, retention, listing, deletion, and compiler handoff remain separate work.

## Compatibility and rollback

The optional setting, reader projection, and GET route are additive. Existing Campaign Builder CLI,
Run, Replay, approval, Worker, managed Artifact, and Graph behavior is unchanged. No database or
artifact migration is required. Rollback removes the route and optional setting; local UX-001B1
artifacts remain available to the CLI and remain non-executable.

## Related documents

- [ADR-0153: Build Campaign Drafts without Compilation Authority](0153-build-campaign-drafts-without-compilation-authority.md)
- [ADR-0154: Store Campaign Drafts outside Run Authority](0154-store-campaign-drafts-outside-run-authority.md)
- [UX-001B1 contract](../orchestration/UX-001B1-local-campaign-draft-artifact.md)
- [UX-001B2 contract](../orchestration/UX-001B2-control-plane-campaign-draft-read.md)
