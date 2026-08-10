# ADR-0156: Handoff Verified Campaign Drafts to Existing Compilers

## Status

Accepted

## Context

UX-001B2 lets an Operator retrieve a redacted projection of one verified UX-001B1 draft. The next
slice must compile that draft without treating the projection, draft digest, or request as a new
approval authority. PAJIN already has separate compilers and authorization inputs for Bug Bounty
Programs and CTF Challenges. Duplicating those rules in the Control Plane would create a second
source of truth for Scope Approval and authorization-window evaluation.

Compilation is also distinct from persistence and execution. A compiled `CampaignManifest` must
not silently become a managed Artifact, Run submission, Capability, Permit, or Worker dispatch.
The caller must not be able to choose an evaluation timestamp to revive stale authority.

## Decision

The Control Plane adds one Operator-only endpoint:

`POST /v1/campaign-drafts/{draft_digest}/compile`

The server resolves and verifies the complete draft through the existing UX-001B2 exact-digest
reader. The request repeats the expected `sourceKind`; it must equal the verified embedded source
kind before any compiler is invoked.

For a Bug Bounty Program, the request must contain exactly one separate, existing
`BugBountyScopeApproval`. The Control Plane passes the verified original
`BugBountyProgramManifest` and that approval to `BugBountyScopeService.compile_campaign`. The
existing compiler remains solely responsible for recomputing the exact Scope digest, verifying
approval freshness and policy-retrieval ordering, and rejecting unsupported review-only assets.

For a CTF Challenge, the request must not contain a Scope Approval. The Control Plane passes the
verified original `CTFChallengeManifest` to `CTFChallengeService.compile_campaign`, which rechecks
its embedded authorization window.

Both compiler calls receive the current timezone-aware server time. The request schema forbids an
evaluation-time field. A mismatched source kind, missing or foreign approval, inactive authority,
invalid compiler result, or invalid server clock fails closed. Expected compiler rejections use a
stable non-reflective conflict response rather than exposing source or approval evidence.

The response contains the complete compiled `CampaignManifest`, its canonical digest, draft and
Profile identity, source kind, and compilation time. Strict markers state that compilation
succeeded while Campaign persistence, Capability, Permit, Run submission, and execution authority
remain false. The service calls neither compiler's `write_campaign` method and does not use the
Run, managed Artifact, Graph, or approval stores.

## Consequences

- One verified typed source reaches exactly its existing source-specific compiler.
- Bug Bounty Scope Approval and CTF authorization rules remain owned by their existing compilers.
- A caller cannot backdate compilation or substitute the redacted view for the original source.
- Successful compilation yields a Campaign value only; downstream execution still requires the
  normal Campaign admission, approval, Capability, Permit, and Run boundaries.
- The endpoint does not create a durable compilation ledger. The response is the only output of
  this slice.
- The existing `BugBountyScopeApproval` is an input contract, not a newly authenticated or signed
  approval mechanism. Strengthening its provenance is a separate authority change.

## Compatibility and rollback

The request, response, compiler adapter, and POST route are additive. Existing Campaign, Run,
approval, Worker, Replay, Graph, and UX-001B1 artifact schemas are unchanged. No database or
artifact migration is required. Rollback removes the POST route and adapter; the read-only route
and local draft artifacts remain valid and non-executable.

## Related documents

- [ADR-0153: Build Campaign Drafts without Compilation Authority](0153-build-campaign-drafts-without-compilation-authority.md)
- [ADR-0154: Store Campaign Drafts outside Run Authority](0154-store-campaign-drafts-outside-run-authority.md)
- [ADR-0155: Expose Campaign Drafts as Redacted Operator Views](0155-expose-campaign-drafts-as-redacted-operator-views.md)
- [UX-001B2 contract](../orchestration/UX-001B2-control-plane-campaign-draft-read.md)
- [UX-001B3 contract](../orchestration/UX-001B3-campaign-draft-compiler-handoff.md)
