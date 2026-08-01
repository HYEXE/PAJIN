# WALK-004: Observation Graph and Bounded Replan

- Status: Implemented
- Authority contract: `pajin.dev/walking-observation-replan/v1alpha1`
- Registered rule ID: `pajin.walk.mcp-authorization-observation-replan.v1`
- Decision: [ADR-0071](../adr/0071-evidence-bound-walking-observation-replan.md)

## Scope

WALK-004 admits the sealed state of one WALK-003 MCP authorization Hypothesis as an exact
Observation and selects one bounded follow-up Plan. The selected action is only
`request-independent-approval`; the Plan remains `proposed-not-authorized`.

This slice does not execute the registered MCP Capability. It creates no activation,
`CapabilityGrant`, approval receipt, `ActionPermit`, `ToolRequest`, MCP argument, or Worker
dispatch. A later slice must independently establish every runtime Capability, approval, Graph,
Permit, Gateway, Budget, and Policy authority.

## Input authority

`DeterministicWalkingObservationReplanCompiler` independently re-verifies:

- the complete sealed WALK-003 Campaign, Run root, artifact SHA-256, publication event, and exact
  single Hypothesis;
- the complete nested WALK-002 H-17 dependency and HTTP/RAG Surface Snapshot;
- the WALK-003 MCP Surface Snapshot, immutable Capability Definition, local ToolSpec digest,
  remote MCP identity, and independent-user-approval requirement;
- a content-addressed Observation evidence candidate that exactly names that sealed source state;
- the code-registered admission/Replan rule; and
- the caller's expected previous state against either the sealed baseline or the state path
  reconstructed from a sealed prior WALK-004 authority.

The only admissible evidence kind is `sealed-hypothesis-state`, and its observed state must be
`registered-not-authorized`. Free-form target or model text is not an input to this authority.

## Output authority

`WalkingObservationReplanAuthority` is content-addressed over:

- the full canonical Campaign manifest and digest;
- the complete sealed WALK-003 dependency, including its nested WALK-002 lineage;
- the registered rule and rule digest;
- the exact evidence candidate and admitted Observation;
- both Surface Snapshot identities and digests;
- the exact Capability reference and independent-approval control;
- the baseline, expected previous, and selected Plan state digests;
- the non-executable `request-independent-approval` follow-up Plan; and
- an immutable Graph snapshot with typed `supports`, `enables`, and `depends-on` edges.

The relationship vocabulary also reserves `contradicts`. A contradictory or mismatched candidate
is rejected before admission, so it cannot create a Plan edge in this slice.

The separate WALK-004 Run writes `campaign.json`,
`walking-observation-replan-authority.json`, `run.json`, one exact creation event, terminal Campaign
events, and an integrity seal. `load_walking_observation_replan_authority` reconstructs and checks
the complete artifact and audit payload without mutable in-memory authority.

## State and negative boundaries

The baseline state binds the complete Campaign digest, WALK-003 Run/artifact identity, Hypothesis,
both Surface Snapshots, Capability, approval control, and fixed execution state. The selected
semantic Plan state excludes only the previous-state pointer, while the Plan identity includes it.
This makes a second selection of the same semantic Plan a repeated state instead of an apparently
novel chain. The compiler accepts no caller-authored digest history: any non-baseline history must
come from a prior WALK-004 Run whose artifact, event, source, rule, evidence, and state path are
independently re-verified.

Compilation or artifact validation fails closed when:

- evidence ID/digest or any sealed source field is forged;
- another Run or Hypothesis is substituted;
- the expected previous state is stale;
- the bounded history contains a repeated state or cycle;
- the selected semantic Plan is already present in the history;
- Campaign Scope, either Snapshot, Capability, approval control, rule, or source state expands or
  differs;
- Graph nodes or typed edges differ from the admitted Observation and selected Plan; or
- the sealed artifact, creation event, or any canonical identity is modified.

No dispatch exists in this slice. These checks therefore occur before any future execution
boundary can consume the Plan.

## Compatibility, migration, and rollback

All models, compiler, Runner, artifact, loader, and public exports are additive. A4/A5,
ORCH-001/002, WALK-001/002/003, and their existing artifact readers and wire shapes remain
unchanged. No automatic migration is required.

Adoption is opt-in by constructing the WALK-004 compiler and Runner with the exact registered rule.
Rollback stops selecting that path; already sealed Observation/Replan artifacts remain readable and
non-executable.

## Related documents

- [WALK-003 contract](WALK-003-mcp-tool-authorization-hypothesis.md)
- [ORCH-002 contract](ORCH-002-deterministic-multi-wave-baseline.md)
- [ADR-0069](../adr/0069-snapshot-bound-mcp-tool-authorization-hypothesis.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
