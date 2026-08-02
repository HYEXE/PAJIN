# ENG-001: Common Campaign Execution Engine Contract

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-campaign-engine-contract/v1alpha1`
  - `pajin.dev/common-campaign-execution-plan/v1alpha1`
- Decision: [ADR-0101](../adr/0101-register-common-engine-boundary-before-profile-activation.md)

## Scope

ENG-001 identifies the stable execution boundary already shared by the existing `ai-redteam`,
`bug-bounty`, and `ctf` multi-agent command paths. It does not replace
`MultiAgentCampaignRunner`, compile a `CampaignProfile`, issue a `MissionEnvelope`, or activate a
new execution path.

The code-owned `CommonCampaignEngineContract` identifies the existing
`pajin.workflow.multi_agent.MultiAgentCampaignRunner` boundary and requires these shared stages:

1. Campaign authority snapshot;
2. budget and rate limiting;
3. Capability and Policy enforcement;
4. Worker dispatch;
5. Candidate validation; and
6. sealed Run audit.

These identifiers are a migration contract, not a runtime registry. Their presence grants no
Capability, Permit, Tool request, or dispatch authority.

## Authority binding

`campaign_manifest_digest()` is the shared canonical Campaign fingerprint used by this contract
and by the existing Capability Graph deployment and `MissionEnvelope.sourceCampaignDigest`
construction path. The compatibility helper `capability_graph_campaign_digest()` retains its
public name and exact digest behavior.

`CommonCampaignExecutionPlanAuthority` binds:

- the complete detached legacy Campaign and its canonical digest;
- the exact source `CampaignMode`;
- the complete registered Common Engine contract and its digest; and
- a fixed `profile-required-not-executable` state.

The plan authority digest transitively binds the Campaign through `campaignDigest`. Loading the
wire artifact recomputes that digest from the embedded Campaign before accepting the plan. It also
requires exact equality with the code-owned engine contract, so a syntactically valid substitute
contract cannot become authority.

## Activation gate

All ENG-001 plans have these fixed values:

- `profileCompilationBound=false`;
- `missionEnvelopeBound=false`;
- `parityEvidenceBound=false`; and
- `commonExecutionAuthorized=false`.

Before a Common Engine path can execute, later slices must bind a deterministic Profile
compilation, derive a non-expanding `MissionEnvelope`, and prove legacy/common parity for exactly
`scope`, `capability`, `tool-request`, and `outcome`. ENG-001 supplies no function that consumes its
plan to invoke a Worker.

## Negative cases

Validation fails closed for:

- a Campaign digest or source Mode that differs from the embedded Campaign;
- Campaign mutation under a retained digest;
- a substituted contract or contract digest;
- changed shared-boundary or parity membership/order;
- an unknown or reordered source Mode set; and
- any attempt to set a Profile, envelope, parity, or execution flag to true.

## Compatibility, migration, and rollback

Existing Campaign manifests, `CampaignMode` values, CLI commands, API routes, Mode-specific
planner/validator paths, Run artifacts, and readers are unchanged. The public Capability Graph
digest helper remains available and produces the same bytes. ENG-001 is additive and is not wired
into legacy command execution.

Rollback removes the two additive contracts and their exports while leaving all legacy execution
paths untouched. Previously serialized ENG-001 plans remain non-executable migration records and
must not be interpreted as Profile or `MissionEnvelope` authority.
