# WALK-001: File Upload Surface Discovery

- Status: Implemented
- Recon contract: `pajin.dev/discovery-recon/v1alpha1`
- Planner ID: `pajin.walk.file-upload-recon.v1`
- Decision: [ADR-0067](../adr/0067-file-upload-surface-walking-slice.md)

## Scope

WALK-001 is the first executable slice of the Phase 4 hybrid walking skeleton. It performs one
explicitly enabled, single-call HTTP Recon wave against a Campaign-declared OpenAPI document
target and publishes a projection only when the exact registered DISC-003B adapter admits at
least one non-executable `http-file-upload` Surface.

WALK-001 does not upload a file, follow a redirect, crawl another location, resolve `$ref`, infer
an upload from prose, activate a Hypothesis, or grant authority to an emitted route. WALK-002 and
later walking slices consume the sealed projection through the existing ORCH-001 Snapshot
boundary.

## Authority contract

`HTTPFileUploadReconPlanner` binds:

- the complete authoritative Campaign name and exact declared target ID and endpoint;
- `HTTPGetTool` ID and version;
- method `GET` with an empty argument object;
- the exact DISC-003B `DiscoveryAdapterReference` ID, version, and digest; and
- required Surface kind `http-file-upload`.

The binding participates in the deterministic Recon request ID. The additive
`ReconWavePlan.adapterReference` and `requiredSurfaceKinds` fields are sealed in
`recon-plan.json` and repeated in the plan-created and wave-completed events.

Before projection, `SingleReconWaveRunner` requires the trusted admission to use the exact planned
adapter reference and to contain every required Surface kind. The projection event then records
the same adapter ID, version, and digest and preserves the existing source Run, source root,
evidence, Surface Set, and projection root lineage.

## Execution path

```text
Campaign target containing the OpenAPI document
-> HTTPFileUploadReconPlanner
-> one HTTPGetTool request
-> Tool Gateway policy and egress grant
-> host-trusted Docker network receipt
-> sealed source Run
-> exact DISC-003B adapter admission
-> required http-file-upload kind check
-> immutable AttackSurfaceSet projection
-> ORCH-001 Surface Snapshot consumer
```

The source request is permitted only by the existing Campaign Scope, allowed method, authorization
window, Tool risk, shared budget, and rate limits. DISC-003B revalidates the exact response body
against the host-owned network receipt and preserves only route-bound upload topology and declared
media types.

## Negative boundaries

The walking slice fails before projection when:

- the target ID is absent or ambiguous in the Campaign;
- the planner is given a non-DISC-003B adapter reference;
- the live admitted adapter ID, version, or digest differs from the planned reference;
- the admitted Surface Set contains no `http-file-upload` Surface;
- the HTTP response differs from its host-trusted receipt;
- an emitted route exceeds Campaign Scope or method authority; or
- the existing Tool, capability, budget, rate, evidence, or Run integrity checks fail.

A successful source Tool Run remains immutable evidence if the required-kind or adapter equality
check rejects the admission. No projection Run or publication event is created in that case.

## Audit and compatibility

WALK-001 reuses the existing sealed source and projection artifacts. It adds no second Surface
authority. New Recon plans record:

- exact `adapterReference`;
- ordered, unique `requiredSurfaceKinds`;
- deterministic request identity; and
- existing Tool request, evidence, terminal state, and publication lineage.

Legacy Recon plan payloads without the additive fields remain readable and default to no exact
adapter requirement and no required Surface kinds. Existing MCP Recon planners and the default
non-Recon Campaign path retain their behavior.

## Rollback and benchmark impact

Rollback stops selecting `HTTPFileUploadReconPlanner` and continues using the existing opt-in
Recon paths. Already sealed source and projection Runs remain immutable and readable.

WALK-001 establishes only the Recon-to-projection segment of the hybrid chain. It does not claim
chain completion or benchmark improvement. WALK-002 must compile an admitted file-upload Surface
into an exact RAG-injection Hypothesis without expanding Campaign authority.
