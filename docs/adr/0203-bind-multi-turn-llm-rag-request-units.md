# ADR-0203: Bind Multi-turn LLM/RAG Request Units before Execution

## Status

Accepted

## Context

ADR-0202 deliberately excludes the KISA A04 memory-persistence scenario from
`redteam-llm-v1`. Its `ai.chat-probe` request contains two turns, and the Tool Gateway derives two
network request units from that prepared request. The CAP-005 definition previously copied the
ToolSpec minimum of one request unit, so a Graph Proposal, T2 approval, and ActionPermit could
reserve one unit for an action that the Gateway correctly charged as two.

The existing Capability Graph wire already binds a definition, prepared request, Proposal,
approval, Permit, and Gateway dispatch. Adding another execution wire would duplicate authority;
leaving the definition at `1.0.0` while changing its cost would hide a material contract change.

## Decision

Add an explicit optional `requestUnitCost` to `ToolCapabilityRegistration`. It is a reviewed
Capability-level reservation for a fixed semantic action, not a caller override. Registrations
without the field continue to use the ToolSpec minimum. The A04 registration alone declares two
units and changes from
`pajin.ai.kisa.memory-poisoning-persistence@1.0.0` to `@1.1.0`.

Add `redteam-llm-rag-v1@1.0.0` as a separate product ceiling over the existing
`CapabilityGraphCampaignJobInput` path. It admits only the exact A04 `1.1.0` definition and exact
`kisa.agent.memory-poisoning-persistence` request. Both `ai-chat-api` and `rag-chat-api` Campaign
Targets are supported when exactly one Target has the request endpoint.

Before Permit creation, the profile requires all of the following to equal two:

1. the number of turns in the prepared `ai.chat-probe` request;
2. the A04 Capability definition's `requestUnitCost`; and
3. the Graph Proposal reservation.

The existing `ActionApprovalEnvelope` binds its reservation and Proposal exactly. The existing
approval-bound Permit transaction copies that reservation into the consumed ActionPermit. The
existing Capability dispatcher then compares the Proposal reservation with the current definition
before entering the Tool Gateway, where the Tool recomputes the same two-unit cost and validates
two trusted proxy receipts. No new approval, Permit, Gateway, Worker, receipt, or result schema is
introduced.

The Campaign remains `ai-redteam`, POST, T2, and A04-bound. The definition remains experimental,
read-only, networked, non-parallel, and no-cleanup. A deployment-pinned T2 approval is still
mandatory.

## Consequences

- A04 can execute through an exact LLM or RAG product Target without understating Graph budget.
- Reservations of one or three units, a single-turn Capability, another scenario, another Tool,
  an unrecognized Target, a missing approval, or a generic MissionEnvelope relabel fail before
  Permit creation and Worker invocation.
- M03 and M06 remain on `redteam-llm-v1@1.0.0` with one request unit. That profile is not widened.
- Existing A04 `1.0.0` releases are historical identities and do not satisfy the current
  code-owned inventory. Activating A04 `1.1.0` requires a separately reviewed signed release.
- The profile does not create Replay, Finding, confirmation, impact, severity, report, Web, MCP,
  browser, system, write, or cleanup authority.

## Rejected alternatives

### Reserve the ToolSpec minimum and rely only on Gateway rate limiting

Rejected because Graph approval and budget authority would understate an action before Gateway
execution.

### Infer request units for every AI request at Proposal time

Rejected because the current Graph proposal compiler is definition-based and no generic reviewed
contract exists for arbitrary dynamic multi-turn actions. The fixed A04 action has an exact,
code-owned two-turn contract.

### Add A04 to `redteam-llm-v1`

Rejected because the single-turn profile's identity and ceiling are already accepted and must not
silently widen to multi-turn or RAG Targets.

## Compatibility and rollback

The execution wire is unchanged. Existing M03/M06 releases, approvals, Permits, dispatches, and
evidence retain their identities. Historical A04 `1.0.0` artifacts remain readable but are not
current `1.1.0` activation authority. Operational rollback stops routing
`redteam-llm-rag-v1`; it does not delete or reinterpret durable authority records.

## Related documents

- [REDTEAM-001B contract](../orchestration/REDTEAM-001B-multi-turn-llm-rag-profile.md)
- [REDTEAM-001A contract](../orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [ADR-0202](0202-compose-approved-single-turn-llm-redteam-profile.md)
