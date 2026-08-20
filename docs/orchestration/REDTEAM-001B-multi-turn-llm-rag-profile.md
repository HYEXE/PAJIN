# REDTEAM-001B: Multi-turn LLM/RAG Request-unit Profile

- Status: implemented locally
- Profile: `redteam-llm-rag-v1`
- Reused execution wire: `CapabilityGraphCampaignJobInput`
- Decision: [ADR-0203](../adr/0203-bind-multi-turn-llm-rag-request-units.md)

## Purpose

Execute the fixed two-turn KISA A04 memory-persistence probe on an LLM or RAG chat Target while
keeping its Capability definition, Graph reservation, T2 approval, ActionPermit, and Gateway
network accounting equal.

## Exact inventory

| Capability | Threat | Tool | Turns / request units | Target type |
| --- | --- | --- | ---: | --- |
| `pajin.ai.kisa.memory-poisoning-persistence@1.1.0` | A04 | `ai.chat-probe@1.0.0` | 2 | `ai-chat-api` or `rag-chat-api` |

No other Capability ID, version, scenario, Tool, threat, turn count, reservation, or Target type is
admitted. M03 and M06 remain exclusively in `redteam-llm-v1`.

## Versioned request-unit authority

`ToolCapabilityRegistration.requestUnitCost` is an optional, code-owned Capability reservation.
When absent, the adapter retains the ToolSpec minimum. A04 `1.1.0` explicitly declares two because
its exact catalog request always performs two bounded POST exchanges. This value participates in
the Capability definition digest and the code-authority context.

Before a Permit can be created, `redteam-llm-rag-v1` requires:

1. the exact code-owned MissionEnvelope profile ID, version, and digest;
2. the exact A04 `1.1.0` definition, `ai.chat-probe@1.0.0` binding, T2/read-only/network/no-cleanup
   metadata, and two request units;
3. the exact catalog A04 scenario and threat with two prepared turns;
4. a Graph Proposal reserving exactly two request units;
5. a deployment-pinned approval whose Proposal and reservation are exact;
6. an `ai-redteam` Campaign declaring A04, POST, and T2; and
7. exactly one matching `ai-chat-api` or `rag-chat-api` Target endpoint.

The unchanged approval-bound transaction copies the two-unit reservation into the consumed
ActionPermit. The unchanged CAP-005 dispatcher rechecks it against the current definition before
Gateway entry. The Gateway then recomputes two network units from the prepared request and requires
the trusted host proxy receipt sequence for both turns.

## Execution and retry

Startup continues to own the SHA-256-pinned Capability Graph deployment, signed seven-release
inventory, explicit activation, Campaign, MissionEnvelope, approval input authority, Graph
database, Run root, Tool registry, Worker, and clock. The product profile adds no caller-supplied
path or authority.

A successful dispatch projects the existing `capability-graph-gateway` result with
`executionProfile=redteam-llm-rag-v1`. Exact retry reuses the terminal Permit and never invokes the
Worker a second time.

## Fail-closed cases

Tests cover:

- successful exact A04 execution on both `ai-chat-api` and `rag-chat-api` Targets;
- Proposal, approval, and Permit reservations equal to two;
- one-unit under-reservation and three-unit over-reservation before Permit creation;
- a single-turn M03 definition relabeled as the multi-turn profile;
- missing deployment-pinned T2 approval;
- generic MissionEnvelope relabeling; and
- exact retry with one Worker invocation.

## Evidence and non-authority

Fixture-backed tests exercise trusted Docker proxy-receipt validation but are not evidence of a
live external Target. The profile creates no Replay, Finding, confirmation, impact, severity,
report, Scope expansion, additional execution, Web, MCP, browser, system, write, or cleanup
authority.

## Remaining REDTEAM-001 boundary

REDTEAM-001C must define a bounded Web Capability profile. REDTEAM-001D must define a registered
MCP Capability profile. Neither can be inferred from the LLM/RAG Tool categories or Capability
surface declarations.

## Compatibility and rollback

The Job and result wires are unchanged. A04 `1.0.0` is a historical identity and cannot satisfy
the current `1.1.0` registration; a reviewed signed `1.1.0` release is required for activation.
Removing product routing disables new `redteam-llm-rag-v1` dispatch without deleting durable
approval, Permit, receipt, evidence, or Run records.
