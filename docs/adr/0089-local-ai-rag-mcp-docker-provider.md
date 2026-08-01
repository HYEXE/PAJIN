# ADR-0089: Add a Separate Runnable Local-Docker Identity for AI/RAG/MCP

- Status: Accepted
- Date: 2026-08-01

## Context

ADR-0088 deliberately registered the walking AI/RAG/MCP scenario as a non-runnable fixture. Its
selection has no adapter identity and permanently denies provider execution and measurement
admission. P0-D2B needs a real reset, isolation, execution, evidence, and cleanup lifecycle without
changing the meaning of that historical authority.

The Traditional Web/API Docker adapter already implements the required host-local recovery,
fencing, hardening, and receipt evidence. Duplicating that implementation for an AI scenario would
create two lifecycle authorities that can drift. Turning it into an arbitrary command/image runner
would weaken its fixed-profile validation boundary.

## Decision

1. Preserve the P0-D2 fixture profile, catalog, selection, and false authority flags unchanged.
2. Add a separate content-addressed local-Docker profile, Target Factory, adapter, and catalog ID for
   the runnable AI/RAG/MCP scenario.
3. Reuse the existing Docker lifecycle implementation through narrow scenario hooks for Target
   environment, fixed Worker action/input, exact output validation, and measurement mapping.
4. Use one synthetic Target container with explicit document, agent-query, and MCP HTTP endpoints.
   Treat the MCP endpoint as a protocol boundary inside that container, not as a separate MCP
   deployment.
5. Require the host adapter to independently decode and validate exact response bodies and hashes;
   Worker-reported success flags alone are insufficient evidence.
6. Bind runnable catalog selection to the exact Manifest, adapter, image profile, public
   registration, and private Ground Truth before provider mutation. Preserve the Finding, Surface,
   and chain identities but use a distinct Docker matcher digest rather than reusing the Walking
   fixture's untrusted-network evidence semantics.

## Consequences

- The first runnable AI/RAG/MCP benchmark exercises a real internal-network chain and recoverable
  provider lifecycle without claiming model execution or production MCP conformance.
- SQLi and AI providers share fencing and resource policy but retain scenario-specific commands and
  fail-closed result parsers.
- Historical fixture authorities cannot be replayed as runnable selections.
- Image IDs remain trusted local provisioning inputs, and the resulting profile is host-local.
- Separate MCP deployment, model-backed RAG, Holdout, Mutation, catalog distribution, and cross-host
  provider authority remain future work.

## Compatibility and rollback

The change is additive. Existing P0-D1, P0-D2, P0-C, WALK, measurement, and Harness wire contracts
remain readable and keep their previous values. The shared catalog accepts one additional code-owned
AI catalog ID without adding fields.

Rollback stops building and selecting the new local-Docker profile and removes no historical sealed
artifacts. It must not promote the contract-only P0-D2 fixture as a replacement provider.

## Related documents

- [P0-D2B contract](../benchmark/P0-D2B-local-ai-rag-mcp-docker-provider.md)
- [P0-D2 contract](../benchmark/P0-D2-ai-rag-mcp-target-fixture-catalog.md)
- [P0-C2B2B contract](../benchmark/P0-C2B2B-local-docker-provider-evidence.md)
- [ADR-0088](0088-non-runnable-ai-rag-mcp-target-fixture.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
