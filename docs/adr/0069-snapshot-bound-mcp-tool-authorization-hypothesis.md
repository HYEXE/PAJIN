# ADR-0069: Snapshot-Bound MCP Tool Authorization Hypothesis

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-002 proves only that untrusted document content can enter an explicit RAG corpus boundary and
records `rag-document-probe` as a future semantic dependency. DISC-003D separately discovers MCP
interfaces as digest-only, non-executable Surfaces. Neither record authorizes an MCP call.

The next walking-skeleton stage must correlate H-17 with a concrete MCP interface without turning a
discovered name into authority or bypassing PAJIN's Capability, approval, Graph, Permit, and Gateway
boundaries.

## Decision

1. Add a separate WALK-003 MCP Recon planner bound to the exact DISC-003D adapter and required
   `mcp-server` plus `mcp-tool` Surface kinds.
2. Consume the sealed WALK-002 Hypothesis Run and the sealed MCP Recon projection as independent,
   re-verified authorities under one exact Campaign.
3. Require a code-registered rule that names the exact MCP server/tool and an exact
   `CapabilityDefinitionRef`.
4. Resolve that reference from the immutable Capability Registry and require its Tool binding to
   resolve to a live, unchanged `RegisteredMCPTool` for the same remote server/tool.
5. Require exact equality between the discovered MCP input-schema digest and Capability parameter
   schema, plus `mcp-tool` support, the authorization-failure threat class, H-17's required Tool ID,
   and independent-user-approval metadata.
6. Bind the full H-17 Run/artifact lineage, both Snapshot/Surface authorities, full Capability
   definition, Tool binding, and rule into a content-addressed Hypothesis.
7. Persist it in a separate sealed Run with `registered-not-authorized` state and no activation,
   Grant, Permit, request, argument, or dispatch.

## Consequences

- Discovery, registration, and runtime authorization remain distinct trust transitions.
- Tool-name, schema, Campaign, Snapshot, Capability, approval, and prior-Hypothesis substitution
  fail closed before publication.
- Audit can reconstruct why an MCP interface was considered relevant without retaining raw schemas,
  document content, MCP commands, credentials, or arguments.
- The explicit approval requirement is conservative for the first chain. Other controls require new
  registered rule versions rather than weakening this contract.
- WALK-004 may add Observation and Replan authority but cannot treat this artifact as execution
  approval.

## Compatibility and rollback

All types and paths are additive. Existing DISC-003D Recon, MCP invocation, WALK-002, Hypothesis,
and ORCH wire shapes remain readable. Rollback removes WALK-003 composition while leaving its sealed,
non-executable records verifiable.

## Related documents

- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [WALK-002 contract](../orchestration/WALK-002-rag-injection-hypothesis.md)
- [ADR-0064: Bounded Registered MCP Boundary Discovery](0064-bounded-registered-mcp-boundary-discovery.md)
- [ADR-0068: Snapshot-Bound RAG Injection Hypothesis](0068-snapshot-bound-rag-injection-hypothesis.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
