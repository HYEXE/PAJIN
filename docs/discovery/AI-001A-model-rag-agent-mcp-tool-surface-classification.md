# AI-001A: Model, RAG, Agent, MCP, and Tool Surface Classification

- Status: Implemented, typed classification registry only
- API versions:
  - `pajin.dev/ai-surface-locator/v1alpha1`
  - `pajin.dev/ai-surface-classification-registry/v1alpha1`
  - `pajin.dev/ai-security-surface/v1alpha1`
- Authority: `src/pajin/discovery/ai_surfaces.py`
- Decision: [ADR-0216](../adr/0216-classify-ai-surfaces-without-tool-authority.md)

## Purpose

AI-001A implements the locator schema reserved by DOMAIN-002 for
`ai.model-rag-agent-tool`. It classifies model, RAG, agent, MCP, and Tool knowledge under the exact
DOMAIN-001 AI classification and provides a content-addressed typed Surface whose initial state is
`registered-not-authorized`.

This is not an AI assessment Capability. It does not invoke a provider, query a RAG index, run an
agent, call an MCP server or Tool, observe a target, seal Evidence, admit a Graph node, select a
Profile, expand Scope, access a credential, issue a Permit, or authorize execution.

## Registered classifications

| AI class | Registered locator kinds | Representation status |
| --- | --- | --- |
| `model` | `ai-model` | New minimal secret-free provider/model/revision identity; it records a provider-registration digest but does not verify current registration or invocation authority |
| `rag` | `http-rag` | Reuses the existing route-bound `HTTPRAGSurfaceLocator` unchanged |
| `agent` | `ai-agent` | New immutable implementation, provider, model, prompt, Tool-catalog, and runtime-configuration digest identity aligned with existing raw trace provenance dimensions |
| `mcp` | `mcp-server`, `mcp-prompt`, `mcp-resource`, `mcp-resource-template` | Reuses existing MCP discovery locators unchanged; resources remain digest-only |
| `tool` | `mcp-tool`, `mcp-url-tool`, `tool-interface` | Reuses existing schema-bound Tool locators unchanged; Tool classification is not Capability authority |

The registry contains exactly these ten locator kinds in code-owned order. Model and agent locators
are additive AI-001A values and intentionally are not inserted into the established discovery
`SurfaceLocator` union. Therefore they cannot become existing `SurfaceObservation` or
`AttackSurface` values without a future versioned discovery contract and evidence path.

## Typed Surface identity

`AISecuritySurface` binds:

- the exact AI Domain classification;
- the exact DOMAIN-002 AI type-set;
- the complete classification-registry reference;
- one discriminated registered locator;
- the code-owned AI class for that locator; and
- a content-addressed Surface ID and digest.

The value is pre-Observation knowledge. It has no Campaign, Capability, Scope, approval, Permit,
Tool request, Worker, Observation, Evidence, or Finding field. `typedSurfaceOnly` is true, while
`discoveryObserved`, `evidenceSealed`, `graphAdmitted`, `profileSelected`, and every authority
marker are false.

## Model and agent identity limits

The model locator requires a provider ID, model ID, immutable model revision, and exact provider
registration digest. It cannot contain a secret reference. The digest is provenance only; AI-001A
does not reopen the registration, validate its current activation, authorize its endpoint, or
grant credential access.

The agent locator carries the same immutable identity dimensions needed by the existing
model/Tool trace provenance contract. It is not itself a trace, agent registration, prompt, Tool
catalog, provider lease, or invocation request. Mutable aliases such as `latest`, `default`, and
`auto` fail closed.

## Tool and MCP non-authority

An MCP server advertising `tools`, an MCP Tool schema, a URL-bearing argument, or a registered Tool
interface only describes a Surface. Discovery metadata cannot choose a Tool, activate a
Capability, authorize a URL or credential, select a Worker, or issue an ActionPermit. MCP remains a
transport and integration mechanism behind the same Capability and Gateway authority path.

AI-001B now separately binds exact provider/model/RAG/MCP/Tool identities to four existing
read-only CAP-002 Capabilities, request/token/cost ceilings, and the minimum AI Worker boundary.
It stops at non-authoritative action preparation; current Profile, Campaign Scope, budget,
credential lease, Policy/Approval, ActionPermit, Gateway, deployment, and execution remain
independent downstream requirements.

AI-001C now consumes only exact Surface references from an AI-001B preparation while reverifying
an already sealed REDTEAM execution. It admits neutral Observation/Evidence through the existing
Graph writer; it does not turn these Surface values into discovery, Tool selection, Scope, replay,
Finding, or additional execution authority.

## Fail-closed behavior

Definitions, references, the complete registry, and typed Surfaces are content-addressed. The
implementation rejects class/kind/model substitution, registry reordering, Domain relabeling,
mutable revision aliases, digest drift, secret embedding, extra authority metadata, true authority
markers, and boolean coercion. Exact reference resolution does not transfer authority.

## Compatibility and rollback

The implementation is additive. Existing RAG/MCP/Tool locator models, discovery API,
`SurfaceLocator`, `SurfaceObservation`, `AttackSurface`, DOMAIN-002 registry, REDTEAM-001A/B/D,
walking-chain, and benchmark wires remain unchanged. Removing the new module, exports, tests, and
consumers restores the prior state without migrating existing artifacts.

## Verification

`tests/test_ai_surface_classification.py` covers exact Domain/type-set/class membership, existing
locator reuse, model/agent identity constraints, content-addressed resolution, all five typed
classes, MCP/Tool non-authority, discovery-wire compatibility, authority escalation, metadata
injection, identity/order/Domain substitution, digest drift, and boolean coercion.
