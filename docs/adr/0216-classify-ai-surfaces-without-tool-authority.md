# ADR-0216: Classify AI Surfaces without Tool Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `ai.model-rag-agent-tool` and
`pajin.locator.ai.model-rag-agent-tool.v1` as semantic identifiers but intentionally does not
implement their locator schema. PAJIN already has strict RAG and MCP discovery locators and a
generic Tool-interface locator. It also has provider/model and agent trace identities inside
specific Supervisor and benchmark execution contracts, but no general canonical AI Surface for a
model or agent.

AI-001A must make the five requested knowledge classes explicit without turning an MCP server,
Tool schema, provider registration digest, model identity, agent metadata, or Domain label into
execution authority. Reusing a Supervisor binding as a general discovery locator would also import
Campaign, endpoint, model-configuration, and shadow-invocation semantics into the wrong layer.
Changing the established discovery `SurfaceLocator` union would alter an evidence-bound wire before
model or agent discovery has a corresponding Observation and Evidence contract.

## Decision

Add a content-addressed AI Surface classification registry with exact code-owned mappings for:

- model: a minimal secret-free provider/model/immutable-revision locator;
- RAG: the unchanged existing HTTP RAG boundary locator;
- agent: an immutable identity using the existing model/Tool trace provenance dimensions;
- MCP: the unchanged server, prompt, resource, and resource-template locators; and
- Tool: the unchanged MCP Tool, MCP URL Tool, and generic Tool-interface locators.

Add an inert `AISecuritySurface` wrapper that binds one locator to the exact AI Domain and
DOMAIN-002 type-set and starts as `registered-not-authorized`. Do not add the new model or agent
locators to the existing discovery `SurfaceLocator` union. Do not change the discovery,
`AttackSurface`, Graph, REDTEAM, walking-chain, or benchmark wires.

The registry and typed Surface deny Profile selection, Scope expansion, Capability activation,
approval satisfaction, Permit issuance, Tool and Worker selection, network and credential access,
Graph admission, runtime-support assertion, and execution authority. Existing MCP and Tool
metadata remain descriptions of how an integration may be represented, never an authority root.

## Consequences

- AI knowledge can be classified consistently before AI-001B introduces any read-only execution
  binding.
- Existing RAG, MCP, and Tool locator validation remains the source of truth.
- General model and agent identity can be represented without embedding a secret or asserting a
  current provider registration, credential lease, endpoint Scope, or invocation right.
- Model and agent values cannot enter existing discovery Evidence or `AttackSurface` wires by
  construction.
- AI-001B must explicitly bind exact provider/model/Tool identities through CAP-002 and the current
  Policy/Approval, ActionPermit, Gateway, budget, credential, and Worker authority path.

## Rejected alternatives

### Treat provider or Tool registration as a Surface and execution authority

Rejected because registration and metadata describe identity and implementation, not current
Campaign, Scope, approval, Permit, credential, budget, or Worker authority.

### Reuse `SupervisorProviderModelIdentity` as the general AI locator

Rejected because it is deliberately bound to the SUP-001 Supervisor context and includes endpoint
and registration semantics that AI-001A must not silently generalize.

### Extend the existing discovery locator union immediately

Rejected because model and agent discovery has no new sealed Observation/Evidence contract in this
slice. An additive classification wrapper preserves existing readers and artifact identities.

### Create a second MCP or Tool execution registry

Rejected because existing locator models and the Capability/Gateway path already separate
representation from action authority.

## Compatibility and rollback

AI-001A is additive. Existing public imports receive new names, but established models, unions,
digests, readers, and runtime behavior are unchanged. Rollback removes the additive registry,
typed Surface, exports, tests, and consumers. Future discovery admission for model or agent
Surfaces requires a new versioned contract rather than a silent union change.

## Related documents

- [AI-001A contract](../discovery/AI-001A-model-rag-agent-mcp-tool-surface-classification.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
- [ADR-0208](0208-register-mcp-capability-without-discovery-authority.md)
