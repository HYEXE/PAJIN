# UX-001A: Campaign, Profile, and Scope Builder Draft

- Status: Implemented
- Contract version: `pajin.dev/campaign-builder-draft/v1alpha1`
- Decision: [ADR-0153](../adr/0153-build-campaign-drafts-without-compilation-authority.md)

## Scope

UX-001A creates a deterministic, non-executable draft from one existing typed Campaign compiler
input. It supports exactly:

| Source contract | Selected PROF-001 Profile | Existing compiler entrypoint |
| --- | --- | --- |
| `BugBountyProgramManifest` | `pajin.profile.bug-hunt@1.0.0` | `BugBountyScopeService.compile_campaign` |
| `CTFChallengeManifest` | `pajin.profile.ctf@1.0.0` | `CTFChallengeService.compile_campaign` |

The builder validates and detaches the complete source before projecting it. It does not support a
raw URL, arbitrary JSON Scope, free-form Profile name, `CampaignManifest`, Pentest source, AI
Assessment source, or CTF Suite input.

## Draft binding

`CampaignProfileScopeDraft` binds:

- the exact PROF-001 catalog digest and selected registered Profile;
- source kind, complete embedded source, and source digest;
- a source-derived `CampaignBuilderScopePreview`;
- the literal existing compiler entrypoint and required remaining gates;
- state `input-validated-not-compiled`; and
- a domain-separated draft ID and digest.

Bug Bounty source integrity uses a domain-separated digest over the complete Program, preserving
ordered input fields and sorting only typed set fields. The preview separately exposes the
canonical `BugBountyScopeService.review()` approval digest and uses that review's sorted allow,
deny, and entry-point values. It marks an asset review-only when it has no entry point or uses the
currently unsupported concrete `generic-http` probe profile.

CTF source integrity covers the complete typed Challenge. Web previews preserve the fixed local
entry point. Crypto previews use the same content-addressed artifact target constructed by the
existing CTF Tool and compiler path.

Draft loading reconstructs the exact Profile and preview from the embedded source. Changed source,
source digest, Profile, catalog, Scope preview, target support marker, compiler entrypoint, required
gate, draft ID, or draft digest fails validation.

## Authority boundary

The draft and every target preview fix these fields false:

- `scopeAuthorized`;
- `targetExecutionAuthorized`;
- `campaignManifestCompiled`;
- `capabilityGranted`;
- `permitGranted`; and
- `executionAuthorized`.

The draft has no Campaign field and does not carry a Bug Bounty approval, Control Plane submission,
`MissionEnvelope`, Tool request, Capability, Permit, or Worker input. The compiler entrypoint is an
auditable literal identifier, not a dynamic invocation target.

The remaining gates are explicit:

- Bug Bounty requires `scope-digest-approval` and
  `authorization-window-recheck`; and
- CTF requires `authorization-window-recheck`.

Those labels do not satisfy the gates. The existing compiler must receive and validate its original
typed source and required approval or authorization inputs. A review-only Bug Bounty target remains
compiler-rejected, and an expired CTF authorization remains inactive.

## Negative cases

Validation rejects:

- Bug Bounty/CTF cross-Profile selection and Pentest substitution;
- unknown Profile identity or version;
- source mutation under a retained source digest;
- catalog, Profile, source kind, preview, compiler, gate, ID, or digest substitution;
- Scope or target execution markers changed to true or a non-boolean value; and
- Campaign compilation, Capability, Permit, or execution markers changed to true or a non-boolean
  value.

## Compatibility, migration, and rollback

The module and public workflow exports are additive and direct-call only. Existing Campaign and
Mode schemas, CLI commands, Control Plane routes, compiler behavior, approval flows, sealed Runs,
and artifact readers are unchanged. No migration is required. Rollback removes the additive API;
stored JSON drafts remain non-executable and have no existing runtime consumer.
