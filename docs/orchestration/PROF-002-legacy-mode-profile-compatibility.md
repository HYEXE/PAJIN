# PROF-002: Legacy Mode to Campaign Profile Compatibility

- Status: Implemented
- Contract versions:
  - `pajin.dev/legacy-mode-profile-compiler/v1alpha1`
  - `pajin.dev/legacy-campaign-profile-projection/v1alpha1`
  - `pajin.dev/legacy-campaign-profile-compilation/v1alpha1`
- Decision: [ADR-0103](../adr/0103-compile-legacy-modes-to-profile-semantics-only.md)

## Scope

PROF-002 deterministically projects the current legacy `CampaignMode` into one exact PROF-001
Profile while preserving the complete Campaign unchanged. The compiler is callable but is not
wired into a CLI, API route, `MissionEnvelope` compiler, Worker, or Common Engine execution path.

The code-owned mappings are:

| Source `CampaignMode` | Registered Profile |
| --- | --- |
| `ai-redteam` | `pajin.profile.ai-assessment@1.0.0` |
| `bug-bounty` | `pajin.profile.bug-hunt@1.0.0` |
| `ctf` | `pajin.profile.ctf@1.0.0` |

There is no legacy `pentest` Mode. The compatibility compiler therefore cannot auto-select
`pajin.profile.pentest`.

## Compiler authority

`LegacyModeProfileCompiler` binds:

- compiler ID `pajin.profile.compiler.legacy-mode-v1`, version `1.0.0`, and canonical digest;
- the exact PROF-001 catalog ID/digest;
- the canonical three-item mapping set and each mapping digest; and
- the sole accepted current Campaign API version, `pajin.dev/v1alpha1`.

Compiler validation and compilation entry both reject another Campaign API version. Mapping,
catalog, Profile, compiler, or digest drift fails closed. There is no `latest` Profile resolution.

## Input and output authority

`compile_legacy_campaign_profile()` first detaches and revalidates the complete legacy Campaign.
It emits a `LegacyCampaignProfileCompilationAuthority` that binds:

- the complete source Campaign, canonical `inputDigest`, and exact source Mode;
- the complete compiler and compiler digest;
- the complete PROF-001 catalog and catalog digest;
- the exact registered Profile and Profile digest; and
- a semantic projection with canonical `outputDigest`.

`LegacyCampaignProfileProjection` contains only Campaign digest, source Mode, Profile reference,
compiler identity, catalog digest, and fixed compatibility-state flags. It does not contain a
modified Campaign, ROE values, target, credential, Capability, ToolRequest, or `MissionEnvelope`.
The compilation authority is the portable audit payload required by a later runtime integration;
PROF-002 does not invent a sealed Run or claim that an audit event has been persisted.

The compilation authority digest transitively binds the embedded Campaign through `inputDigest`.
Wire loading rehashes the complete embedded Campaign and rebuilds the expected compiler, catalog,
Profile, and projection before accepting the authority.

## Activation gate

The compiler fixes:

- `campaignMutationAllowed=false`;
- `roeDefaultsApplicationAuthorized=false`;
- `pentestAutoSelectionAuthorized=false`;
- `missionEnvelopeCompilationAuthorized=false`; and
- `commonExecutionAuthorized=false`.

The projection also fixes `legacyInputPreserved=true`, while Campaign mutation, ROE application,
Envelope compilation, and Common Engine execution remain false. Resolving a semantic Profile does
not grant execution authority.

## Negative cases

Validation rejects:

- unsupported Campaign API versions at entry and wire reload;
- source Campaign mutation under a retained input digest;
- source Mode or cross-Mode Profile substitution;
- compiler, mapping, catalog, Profile, projection, input, or output digest substitution;
- `pajin.profile.pentest` substitution or automatic selection; and
- any Campaign mutation, ROE, Envelope, or execution authority flag escalation.

## Compatibility, migration, and rollback

Existing Campaign bytes, `CampaignMode` values, CLI commands, API routes, Mode planners/validators,
sealed Runs, and artifact readers are unchanged. The adapter is additive and opt-in by direct API
call only. It compiles semantic identity, not a new Campaign or execution plan.

Rollback removes the additive compiler, projection, compilation authority, and exports. Legacy
paths remain default and previously serialized PROF-002 authorities remain non-executable audit
records.
