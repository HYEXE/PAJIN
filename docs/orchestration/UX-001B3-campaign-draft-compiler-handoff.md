# UX-001B3: Campaign Draft Compiler Handoff

- Status: Implemented
- Response schema: `pajin.control-plane/campaign-draft-compilation/v1alpha1`
- Decision: [ADR-0156](../adr/0156-handoff-verified-campaign-drafts-to-existing-compilers.md)
- Predecessor: [UX-001B2](UX-001B2-control-plane-campaign-draft-read.md)

## Scope

UX-001B3 adds one explicit, authenticated handoff from a verified Campaign Builder draft to the
source's existing compiler:

`POST /v1/campaign-drafts/{draft_digest}/compile`

Only an Operator may call it. The endpoint returns a compiled Campaign value but creates no file,
database row, managed Artifact, Graph record, Capability, Permit, Run, or Worker dispatch.

## Request contract

The path uses the same exact lowercase SHA-256 digest and configured server root as UX-001B2. The
body is strict JSON with no extra fields.

Bug Bounty handoff:

```json
{
  "sourceKind": "bug-bounty-program",
  "scopeApproval": {
    "scope_digest": "<exact-scope-digest>",
    "approved_by": "<approver-identity>",
    "approved_at": "2026-07-14T00:00:00Z",
    "expires_at": "2026-07-20T00:00:00Z",
    "evidence": "<approval-reference>"
  }
}
```

The nested field names intentionally preserve the existing `BugBountyScopeApproval` wire rather
than defining a second approval type.

CTF handoff:

```json
{
  "sourceKind": "ctf-challenge"
}
```

Bug Bounty requires `scopeApproval`; CTF forbids it. `evaluatedAt` and every other caller-selected
evaluation-time field are forbidden. The server takes one timezone-aware current time and passes
it to the existing compiler.

## Verification and compiler ownership

Before compiler invocation, the server:

1. resolves exactly `<configured-root>/<draftDigest>/campaign-profile-scope-draft.json`;
2. reuses the B1 bounded no-follow reader and complete draft verifier;
3. requires the reconstructed digest to equal the requested digest; and
4. requires `sourceKind` to equal the verified embedded source kind.

Bug Bounty then calls `BugBountyScopeService.compile_campaign` with the original embedded typed
Program and separate Scope Approval. That existing compiler recomputes the Scope digest, verifies
the approval window and policy retrieval ordering, and rejects review-only assets.

CTF calls `CTFChallengeService.compile_campaign` with the original embedded typed Challenge. That
existing compiler rechecks the Challenge's embedded authorization at the same server time.

The Control Plane adds no aggregate compiler, fallback compilation rule, approval conversion, or
authorization inference.

## Response contract

`CampaignDraftCompilation` contains:

| Field group | Fields |
| --- | --- |
| Contract | `apiVersion`, `kind` |
| Draft binding | `draftId`, `draftDigest`, `profileId`, `profileVersion`, `sourceKind` |
| Compilation | `compiledAt`, `campaignDigest`, `campaign` |
| State | `campaignManifestCompiled=true` |
| Non-authority | `campaignPersisted=false`, `capabilityGranted=false`, `permitGranted=false`, `runSubmitted=false`, `executionAuthorized=false` |

The response model revalidates the Campaign, its canonical digest, source/Profile/mode binding,
aware compilation time, and strict boolean markers. `/v1/` cache-prevention headers apply.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Authenticated non-Operator role | `403` |
| Malformed digest, missing required authority, or invalid/extra request field | `422` with redacted validation detail |
| Draft root not configured | `409` with stable configuration detail |
| Missing, tampered, linked, unstable, or digest-substituted draft | `404` with one non-reflective detail |
| Source-kind mismatch | `409` before compiler invocation |
| Foreign, stale, or otherwise rejected authority | `409` with one non-reflective compiler-rejection detail |
| Naive/invalid server clock or invalid compiler output | `409` fail closed |

Parser messages, approval evidence, source values, filesystem paths, and tracebacks are not
reflected.

## Negative cases

Tests prove rejection of:

- missing authentication and Approver-, Auditor-, or Worker-only credentials;
- missing Bug Bounty approval and foreign CTF approval;
- caller-selected evaluation time;
- source-kind substitution before either existing compiler is called;
- wrong-digest and expired Bug Bounty approvals;
- expired CTF authorization;
- directory-digest substitution and typed-source mutation;
- naive server time; and
- forged Campaign digest or compilation/non-authority marker.

Successful compilation replaces both existing `write_campaign` methods with failing sentinels and
confirms that the Run list remains empty.

## Compatibility, migration, and rollback

The endpoint and response are additive. There is no database migration, retained compilation
event, Run submission, or artifact migration. Existing B1/B2 artifacts and views are unchanged.
Removing the endpoint and adapter rolls back this slice without changing stored drafts.

Downstream Campaign persistence, execution admission, and signed approval provenance remain later
and separate authority boundaries.
