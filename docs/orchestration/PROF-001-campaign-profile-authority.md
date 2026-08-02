# PROF-001: Campaign Profile Authority

- Status: Implemented
- Contract versions:
  - `pajin.dev/campaign-profile/v1alpha1`
  - `pajin.dev/campaign-profile-catalog/v1alpha1`
- Decision: [ADR-0102](../adr/0102-separate-profile-semantics-from-campaign-compilation.md)

## Scope

PROF-001 registers four content-addressed operating Profiles against the exact ENG-001 Common
Engine contract. A Profile describes operating and reporting semantics; it is not a Campaign,
compatibility adapter, `MissionEnvelope`, Capability, Permit, benchmark Result, or execution
request.

The code-owned catalog contains exactly these identities, in canonical order:

| Profile ID | Purpose | Reporting semantics | Benchmark expectation |
| --- | --- | --- | --- |
| `pajin.profile.ai-assessment` | `ai-assessment` | `ai-threat-assessment` | `threat-class-coverage` |
| `pajin.profile.bug-hunt` | `bug-hunt` | `program-submission-draft` | `program-scope-finding` |
| `pajin.profile.ctf` | `ctf` | `fixed-lab-result` | `fixed-lab-ground-truth` |
| `pajin.profile.pentest` | `pentest` | `technical-assessment` | `authorized-target-assessment` |

Reporting and benchmark fields are semantic labels only. They do not attest that a report,
benchmark Manifest, measurement, or Result exists.

## Authority constraints

Every Profile has `roeDefaultsPolicy=campaign-authority-only` and the same exact constraints:

- Campaign authorization window;
- Campaign budget ceiling;
- Campaign risk ceiling;
- Campaign Scope intersection; and
- registered Capability subset.

The four Profiles add only restrictive operating controls grounded in their current product
semantics. In particular, CTF retains fixed-lab, flag-validator, and no-external-submission
controls; Bug Hunt remains program-policy and submission-draft oriented; AI Assessment requires
threat-class, Claim-validation, and independent-Replay semantics. Pentest requires explicit Scope,
authorization evidence, and remediation reporting.

No Profile carries target, credential, Scope, risk, budget, Capability, ToolRequest, source Mode,
or Campaign fields. It therefore cannot widen or replace Campaign authority.

## Catalog and resolution

Each `RegisteredCampaignProfile.profileDigest` covers its complete identity, semantics, controls,
fixed false flags, and exact ENG-001 contract ID/digest. `CampaignProfileCatalog.catalogDigest`
covers the complete registered Common Engine contract and the canonical full four-Profile set.

`resolve_registered_campaign_profile(profileId, profileVersion)` performs exact-version lookup and
returns only the registered Profile. It does not select that Profile for a Campaign. Unknown IDs,
`latest`, and unknown versions fail closed. A standalone syntactically valid Profile cannot be
substituted into the code-owned catalog.

## Activation gate

Profile and catalog flags keep all downstream authority absent:

- `legacyCompatibilityAdapterBound=false`;
- `missionEnvelopeCompilerBound=false`;
- `benchmarkMeasurementAuthorized=false`;
- `externalSubmissionAuthorized=false`;
- `profileExecutionAuthorized=false`;
- `legacyModeCompilationAuthorized=false`;
- `missionEnvelopeCompilationAuthorized=false`; and
- `commonExecutionAuthorized=false`.

PROF-002 must bind a legacy input to one exact Profile with compiler identity and audit lineage.
ENG-002 must separately prove parity and compile a non-expanding `MissionEnvelope` before any
Common Engine path can execute.

## Negative cases

Validation rejects:

- unknown Profile ID or version resolution;
- changed Profile purpose, reporting, benchmark, controls, or digest;
- unsorted, duplicate, missing, extra, or reordered catalog membership;
- ENG-001 contract substitution;
- a syntactically valid but unregistered Profile; and
- any adapter, Envelope, benchmark, submission, Profile, or Common Engine authority flag set true.

## Compatibility, migration, and rollback

PROF-001 adds no field to `CampaignManifest` and does not change any `CampaignMode`, CLI command,
API route, planner, validator, artifact, reader, or execution default. Existing `MissionEnvelope`
wire fields can later carry a registered Profile ID/version/digest without schema change.

Rollback removes the additive Profile catalog and exports. Existing legacy paths remain unchanged,
and serialized PROF-001 records remain non-executable semantic records rather than Campaign or
Envelope authority.
