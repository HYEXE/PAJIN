# WALK-003: MCP Tool Authorization Hypothesis

- Status: Implemented
- Hypothesis contract: `pajin.dev/walking-mcp-tool-authorization-hypothesis/v1alpha1`
- Recon planner ID: `pajin.walk.mcp-tool-authorization-recon.v1`
- Compiler ID: `pajin.walk.mcp-tool-authorization-hypothesis-compiler.v1`
- Decision: [ADR-0069](../adr/0069-snapshot-bound-mcp-tool-authorization-hypothesis.md)

## Scope

WALK-003 connects the sealed WALK-002 H-17 authority to one exact DISC-003D MCP Tool Surface and
one pre-registered invocation Capability. It establishes only a deterministic authorization-failure
Hypothesis. A discovered interface does not become executable, and a registered Capability does not
become active.

The slice creates no activation set, `CapabilityGrant`, `ActionPermit`, `ToolRequest`, MCP argument,
or Worker dispatch. Its fixed `registered-not-authorized` state means that a later slice must still
obtain all normal Campaign, Capability, approval, Scope, Graph, Permit, and Gateway authority.

## Input authority

`MCPToolAuthorizationReconPlanner` binds an argument-free request to the exact DISC-003D adapter
reference and requires both `mcp-server` and `mcp-tool` Surface kinds. Compilation independently
re-verifies:

- the sealed WALK-002 Campaign and Hypothesis artifact, Run root, artifact SHA-256, publication
  event, Hypothesis IDs and digests;
- the sealed DISC-003D source Campaign and Recon Plan;
- the immutable MCP Surface projection and ORCH-001 `SurfaceSnapshotAuthority`;
- the code-registered authorization rule and exact Capability reference;
- the live `ToolRegistry` entry, frozen `ToolSpec` version and digest, and
  `RegisteredMCPTool` server/tool registration; and
- the Capability's exact MCP input-schema digest, supported Surface type, threat class, and
  independent-user-approval requirement.

The Capability ID must equal the semantic `requiredToolId` already sealed into H-17. This equality
links the stages without treating the earlier string as executable authority.

## Output authority

`MCPToolAuthorizationHypothesisAuthority` is content-addressed over:

- the existing WALK-domain canonical `campaignDigest` plus additive complete Campaign Manifest
  `sourceCampaignDigest` shared exactly by both strengthened Snapshot dependencies;
- the full WALK-002 Hypothesis plus its sealed Run and artifact lineage;
- the complete MCP `SurfaceSnapshotAuthority`;
- MCP target, server and Tool Surface IDs, and complete locators;
- the full immutable `CapabilityDefinition`;
- the local Tool ID/version/digest and remote MCP server/tool binding;
- the complete code-registered rule digest, authorization control, observable, four-call ceiling,
  success condition, and stop condition; and
- fixed execution state `registered-not-authorized`.

The separate WALK-003 Run writes `campaign.json`,
`mcp-tool-authorization-hypotheses.json`, `run.json`, one creation event, terminal Campaign events,
and an integrity seal.

## Negative boundaries

Compilation fails closed before publishing authority when:

- either dependency Run or artifact is missing, modified, substituted, or no longer sealed;
- the Campaign, Recon Plan, adapter reference, required Surface kinds, or Snapshot differs;
- either strengthened Snapshot's complete Campaign Manifest digest differs from its WALK parent;
- the registered server/tool pair is absent, duplicated, or differs from the discovered locator;
- the discovered input-schema digest differs from the Capability parameter schema;
- the Capability reference, ToolSpec version/digest, Surface type, threat class, or H-17 required
  Tool semantic differs;
- independent user approval is not required; or
- any canonical model identity or digest is forged.

Output-schema identity remains bound by the discovered Tool locator but is not interpreted as input
authority. Descriptions, raw schemas, MCP commands, credentials, document content, and arguments are
never copied into the Hypothesis.

## Compatibility and rollback

The planner, models, compiler, Runner, artifact, and exports are additive. `sourceCampaignDigest`
is absent from historical records and therefore preserves their retained digest chain; new records
require exact equality with the strengthened ORCH Snapshot. DISC-003D's argument-free planner,
registered MCP invocation, WALK-002, A4/A5, and ORCH-001/002 remain compatible. Rollback stops
selecting the WALK-003 path but must retain the additive reader or treat strengthened records as
non-executable historical artifacts; no record grants execution authority.

WALK-004 may consume admitted observations and replan only after separately establishing runtime
Capability and Permit authority. It must preserve both Snapshot dependencies and may not reinterpret
this Hypothesis as an approval or dispatch receipt.

## Related documents

- [WALK-002 contract](WALK-002-rag-injection-hypothesis.md)
- [DISC-003 contract](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ORCH-001 contract](ORCH-001-surface-snapshot-plan-task-binding.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
