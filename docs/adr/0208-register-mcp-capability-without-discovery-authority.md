# ADR-0208: Register an MCP Capability without Discovery Authority

## Status

Accepted

## Context

PAJIN already has a code-registered MCP Tool transport, a fixed Worker-side server catalog,
digest-only MCP boundary discovery, WALK-003 registered-not-authorized hypotheses, and CHAIN-005
coverage semantics. None is a signed executable Capability in the current Control Plane inventory.
The original CAP-005 release set and Worker deployment wire intentionally bind exactly seven
existing KISA, Bug Bounty, and CTF Capabilities.

Adding an MCP Tool name to the existing profile validator would bypass CAP-001/002 and signed
lifecycle authority. Silently changing the seven-item release set would also reinterpret existing
release-set and deployment records.

## Decision

Register `pajin.ai.mcp.instruction-hijacking-inspection@1.0.0` as an exact CAP-001 definition with
the complete CAP-002 seven-role authority set. Bind it to the existing
`mcp.demo-security.inspect-text@1.0.0` Tool and its immutable
`demo-security:inspect_text` registration.

The Capability admits only one fixed synthetic input and Target. It is T0, read-only,
network-disabled, no-cleanup, non-parallel, costs one request unit, and sets
`approvalRequired=true`. The Success Oracle recomputes the exact expected observation from the
typed input and complete normalized MCP identity.

Preserve the CAP-005 seven-item `v1alpha1` release set unchanged. Add an opt-in release-set
`v1alpha2` containing the original seven exact identities plus this one MCP Capability. Add
`CapabilityGraphWorkerDeployment/v1alpha3` for that eight-release inventory. Old deployment
versions continue to require exactly seven releases, and old digests remain stable.

Add `redteam-mcp-v1@1.0.0` as a product ceiling over the unchanged
`CapabilityGraphCampaignJobInput` result and dispatch path. It verifies the exact Capability,
ToolSpec and MCP registration, Campaign, Target, request, one-unit reservation, signed release,
activation, deployment-pinned approval, Permit, and Gateway boundary before execution.

Discovery, schema digest, locator, server advertisement, remote Tool name, Tool categories, legacy
Capability `domain`, and model output remain non-authoritative. The product profile does not infer
activation from DISC-003D, WALK-003, or CHAIN-005.

## Consequences

- REDTEAM-001 gains one executable MCP vertical slice without granting arbitrary MCP, process,
  network, resource, prompt, or plugin execution.
- Registration, activation, approval, Permit, Worker execution, Observation, and Finding remain
  distinct authorities.
- Existing seven-release deployments and every pre-existing digest remain valid.
- An eight-release deployment, exact profile digest, and deployment-pinned approval are all
  required for this action.
- Exact retry remains non-dispatchable through the existing terminal Permit identity.
- Successful inspection remains an Observation and does not satisfy independent Replay or Finding
  confirmation.

## Rejected alternatives

### Activate a discovered MCP Tool

Rejected because discovery is lossy target-controlled metadata and explicitly non-authoritative.

### Execute through the legacy local deterministic campaign only

Rejected because that path does not establish the signed CAP-001/002 release and ActionPermit
product boundary required by REDTEAM-001D.

### Add the MCP Capability silently to CAP-005 v1alpha1

Rejected because the exact seven-item inventory is part of existing signed release-set and Worker
deployment identity.

### Treat the MCP Tool registration as the Capability

Rejected because the Tool defines how to invoke the Worker bridge, while the Capability defines
the authorized semantic action, typed parameters, approval requirement, Oracle, replay, and cleanup
contracts.

## Compatibility and rollback

The change is additive. Readers retain `v1alpha1` release/activation/deployment support. Rollback
disables the new `v1alpha2` release set, deployment `v1alpha3`, and product profile without
rewriting durable records or substituting a legacy Tool path.

## Related documents

- [REDTEAM-001D contract](../orchestration/REDTEAM-001D-registered-mcp-capability-profile.md)
- [CAP-001 contract](../capability/CAP-001-versioned-capability-definition.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [DISC-003 contract](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [ADR-0003](0003-egress-proxy-and-mcp-boundary.md)
- [ADR-0064](0064-bounded-registered-mcp-boundary-discovery.md)
