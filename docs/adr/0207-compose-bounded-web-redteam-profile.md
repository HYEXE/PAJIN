# ADR-0207: Compose a Bounded Web Red Team Profile

## Status

Accepted

## Context

CAP-005 already registers `pajin.bug-bounty.boolean-sqli-lab@1.0.0` with a complete seven-role
authority set and exact `bug-bounty.boolean-sqli-probe@1.0.0` Tool binding. The Tool accepts only
one synthetic local lookup endpoint and runs three Worker-owned GET comparisons. The Gateway
validates the three trusted network receipts, and the CAP-002 Oracle recomputes the Boolean signal
without trusting Worker verdict flags.

Registration and generic Capability Graph execution do not define the narrower REDTEAM Web
product surface. Discovery, a URL, Tool categories, or a future Security Domain label cannot be
used to infer that authority. PENTEST Recon also cannot be widened because its signed GET request,
receipt, Replay, and Finding contracts describe a different semantic action.

## Decision

Add `redteam-web-v1@1.0.0` as an explicit product ceiling over the existing
`CapabilityGraphCampaignJobInput` path. It introduces no new Capability definition, execution
wire, approval, Permit, Gateway, Worker, receipt, Oracle, evidence, or result schema.

The profile admits only:

- `pajin.bug-bounty.boolean-sqli-lab@1.0.0`;
- `bug-bounty.boolean-sqli-probe@1.0.0`;
- scenario `bug-bounty.api.boolean-sqli-lab`;
- GET against `http://host.docker.internal:8770/v1/users/lookup`;
- T2, read-only, networked, no-cleanup, non-parallel execution; and
- exactly three request units in the Capability definition and Graph Proposal.

The deployment Campaign must remain `bug-bounty`, contain exactly one matching
`bug-bounty-api` Target, enable private-network access, permit GET and T2, and include every exact
Tool category. T2 requires the existing deployment-pinned approval before the atomic approval and
ActionPermit transaction.

The existing legacy `CapabilityDefinition.domain=bug-bounty` value is checked as signed identity
only. In accordance with ADR-0204, it is not a Security Domain projection and cannot grant Web,
Profile, Scope, Capability, Tool, Permit, or Worker authority.

The current Tool and Gateway remain responsible for the fixed payload grammar, three network
units, trusted ordered receipts, normalized observations, and sealed evidence. Exact retry remains
non-dispatchable through the existing GRAPH-006 terminal identity.

## Consequences

- REDTEAM-001 gains one executable, synthetic-only Web vertical slice without adding a scanner or
  widening Pentest Recon.
- Under- or over-reservation, another endpoint, scenario, Tool, method, Capability, generic
  MissionEnvelope relabel, or missing approval fails before Permit creation and Worker invocation.
- Tool or domain metadata cannot route a Job into the profile.
- A successful Tool/Oracle outcome is not an independent Replay or confirmed Finding and creates
  no reporting, Scope expansion, additional execution, MCP, browser, system, write, or cleanup
  authority.
- REDTEAM-001D remains a separate registered MCP product slice.

## Rejected alternatives

### Admit arbitrary Web targets with the fixed Tool

Rejected because the current safety evidence, Worker grammar, Ground Truth, and receipt semantics
cover only the synthetic local endpoint.

### Route any Web-classified Capability into the profile

Rejected because Security Domain classification is non-authoritative and the planned DOMAIN
projection is not implemented.

### Reuse PENTEST Recon as the SQL injection action

Rejected because PENTEST Recon and the three-request Boolean comparison have different semantic,
risk, request-unit, evidence, Replay, and Finding boundaries.

### Invoke the legacy Bug Bounty workflow as product authority

Rejected because that workflow has its own compilation and review-only reporting semantics and
does not replace the exact Capability Graph approval/Permit path selected here.

## Compatibility and rollback

The change is additive and preserves every existing Capability digest, release, Campaign input,
Profile, Job/result wire, approval, Permit, receipt, evidence, artifact reader, and benchmark
record. Rollback removes `redteam-web-v1` routing and validation without deleting or reinterpreting
durable authority records.

## Related documents

- [REDTEAM-001C contract](../orchestration/REDTEAM-001C-bounded-web-capability-profile.md)
- [REDTEAM-001A contract](../orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md)
- [REDTEAM-001B contract](../orchestration/REDTEAM-001B-multi-turn-llm-rag-profile.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0015](0015-fixed-bug-bounty-lab-execution.md)
