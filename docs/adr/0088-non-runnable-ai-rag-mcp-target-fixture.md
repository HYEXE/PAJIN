# ADR-0088: Register the Walking AI/RAG/MCP Scenario as Non-runnable

- Status: Accepted
- Date: 2026-08-01

## Context

P0-D1 provides an exact catalog wrapper for one runnable Docker SQLi Target. The next roadmap family
is AI/RAG/MCP, and the walking skeleton already contains sealed Hypothesis, approved execution,
replay, confirmation, and retest contracts for a File Upload -> RAG -> MCP authorization chain.

Those walking tests do not implement a P0-C Target lifecycle. Their Gateway evidence is assembled
as a deterministic fixture, explicitly reports `networkLogTrusted=false`, and has no Target reset,
isolation, provider fence, cleanup receipt, or measurement attestation. Registering it as runnable
would confuse validation authority with provider and measurement authority.

## Decision

1. Extend the existing public catalog validation types to a second `ai-rag-mcp` family without
   changing P0-D1 serialized values or digests.
2. Add a code-owned, content-addressed AI/RAG/MCP profile whose availability and network policy are
   fixed to contract-only and not provisioned.
3. Bind one seeded private Ground Truth case to exact existing WALK states and target observations;
   expose only its digest in the public registration.
4. Add a separate fixture selection authority with no adapter digest and with provider execution
   and measurement admission permanently false.
5. Do not add an adapter, execution wrapper, Benchmark observation mapping, or sealed Harness
   integration until a real P0-C provider exists for this family.

## Consequences

- The second Target family has an explicit catalog and Ground Truth contract without overstating
  current runtime capability.
- Cross-family catalog and Ground Truth substitution fail closed.
- The existing walking chain can guide a future provider's exact semantics, but historical fixture
  evidence cannot be counted as a Benchmark measurement.
- A runnable AI/RAG/MCP provider, Holdout isolation, and Mutation authority remain future work.

## Compatibility and rollback

The change is additive. P0-D1 public JSON has the same fields and values; only its validators accept
the new family-specific literals for P0-D2. Existing Manifest, Ground Truth, Target lifecycle,
registry, Harness, and WALK artifacts remain readable.

Rollback removes the P0-D2 profile and fixture selection exports. It must not convert existing
fixture selections into provider authorization or measurement evidence.

## Related documents

- [P0-D2 contract](../benchmark/P0-D2-ai-rag-mcp-target-fixture-catalog.md)
- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [WALK-005A contract](../orchestration/WALK-005-approved-execution-candidate-admission.md)
- [WALK-005C1 contract](../orchestration/WALK-005C1-mcp-confirmation-report-remediation-baseline.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
