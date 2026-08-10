# UX-001B2: Control Plane Campaign Draft Read

- Status: Implemented
- Response schema: `pajin.control-plane/campaign-draft-view/v1alpha1`
- Decision: [ADR-0155](../adr/0155-expose-campaign-drafts-as-redacted-operator-views.md)
- Predecessor: [UX-001B1](UX-001B1-local-campaign-draft-artifact.md)

## Scope

UX-001B2 adds one authenticated, read-only Control Plane lookup for a complete UX-001B1 local
artifact. It does not add draft creation, listing, editing, deletion, retention, compiler handoff,
or a new store.

Configure the optional root with `PAJIN_CP_CAMPAIGN_DRAFT_ROOT`. The route is always present:

`GET /v1/campaign-drafts/{draft_digest}`

Only a principal with `operator` role may call it. `approver`, `auditor`, and `worker` roles are not
accepted for this pre-compilation source projection.

## Exact lookup and verification

The path parameter must match `^[a-f0-9]{64}$`. The server constructs exactly one path:

`<configured-root>/<draftDigest>/campaign-profile-scope-draft.json`

The request cannot supply an absolute path, relative path, filename, root, or alternate locator.
The server then calls the UX-001B1 `load_campaign_profile_scope_draft` verifier. That boundary
requires bounded strict JSON, no symbolic-link or junction traversal, one hard link, a stable file,
and complete reconstruction of the embedded typed source, registered Profile, derived preview,
remaining gates, identity digests, and false authority markers.

After reload, the reconstructed `draftDigest` must equal the requested digest. A valid draft copied
under a different digest directory is rejected rather than treating the directory as authority.

## Redacted response

`CampaignDraftView` returns only:

| Field group | Fields |
| --- | --- |
| Contract | `apiVersion`, `kind` |
| Identity | `draftId`, `draftDigest`, `profileId`, `profileVersion`, `sourceKind` |
| Bounded preview | `allowRuleCount`, `denyRuleCount`, `targetInputCount`, `reviewOnlySourceCount` |
| Remaining gates | `requiredGates`, `draftState` |
| Authority state | `scopeAuthorized`, `campaignManifestCompiled`, `capabilityGranted`, `permitGranted`, `executionAuthorized` |

Every authority-state field is the strict boolean `false`. The response excludes the complete
`source`, `scopePreview`, source and approval digests, policy text, allow/deny values, source IDs,
target endpoints, compiler entrypoint, and filesystem path. `/v1/` cache-prevention headers apply.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Authenticated non-Operator role | `403` |
| Malformed digest path parameter | `422` with the Control Plane's redacted validation detail |
| Optional root not configured | `409` with a stable configuration detail |
| Missing, unreadable, invalid, tampered, linked, unstable, or digest-substituted artifact | `404` with one non-reflective detail |

Artifact parser and validation exceptions, source values, paths, and tracebacks are not reflected in
the response.

## Authority boundary

The route is a read projection only. It does not call `BugBountyScopeService.compile_campaign` or
`CTFChallengeService.compile_campaign`. It creates no approval, Campaign, Capability, Permit,
submission, Run, sealed evidence, managed Artifact admission, or Graph record. The draft and view
remain `input-validated-not-compiled` and cannot satisfy a compiler's approval or authorization-time
input.

## Negative cases

Tests prove that the route fails closed for:

- absent authentication and Approver-, Auditor-, or Worker-only credentials;
- uppercase, short, and traversal-shaped digest inputs;
- a valid artifact placed under a different digest directory;
- typed-source or authority-marker mutation retained under the original digest;
- missing or unconfigured roots; and
- numeric `0` substituted for a false authority marker.

Supported draft lookup also replaces both existing compiler methods with failing sentinels and
proves that no compiler is invoked.

## Compatibility, migration, and rollback

The setting, projection, and route are additive. No database schema, Run wire, Campaign schema,
approval model, Worker protocol, Graph model, or UX-001B1 artifact changes. No migration is
required. Removing the route and setting rolls back the Control Plane exposure without changing
stored local artifacts.

Original typed-source plus independent approval handoff to an existing compiler is UX-001B3.
