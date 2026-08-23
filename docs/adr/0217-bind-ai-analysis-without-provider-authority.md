# ADR-0217: Bind AI Analysis without Provider Authority

## Status

Accepted

## Context

AI-001A classifies model, RAG, agent, MCP, and Tool knowledge but intentionally supplies no
Capability or execution authority. PAJIN already implements exact read-only REDTEAM Capabilities
for KISA M03 and M06, two-turn RAG A04, and one fixed MCP instruction-hijacking inspection. Those
Capabilities already have CAP-002 authority sets and signed lifecycle support, but no common
artifact binds their exact provider, model, RAG, MCP, Tool, request budget, and minimum AI Worker
requirements before authorization.

Treating a provider registration, Profile name, Domain label, model identity, RAG route, MCP
advertisement, or Tool schema as executable authority would bypass the existing Campaign Scope,
Policy, Approval, ActionPermit, Gateway, credential, budget, and Worker boundaries. Adding another
AI executor would also duplicate established REDTEAM behavior and create a second authority path.

## Decision

Register exactly the four existing REDTEAM-001A/B/D read-only Capabilities as code-owned AI-001B
bindings. Each binding reopens and pins its complete CAP-002 reference, compatibility Profile,
DOMAIN-003 AI classification, existing Tool-interface Surface, exact scenario and request units,
and the DOMAIN-004 minimum AI Worker profile.

For provider-backed bindings, derive a content-addressed, secret-free provider/model identity from
a canonical `ProviderRegistration`, immutable model revision, provider-registration digest, and
secret-reference fingerprint. Require exact ordered model/Tool or model/RAG/Tool Surfaces. For the
MCP binding, require only the fixed `demo-security` MCP server and registered Tool Surface. Bind an
attenuating request/token/cost ceiling that does not reserve or spend capacity.

Preparation must revalidate the provider registration when applicable and delegate to the existing
signed CAP-002 activation's `prepare_action`. Stop at `PreparedCapabilityAction`. Do not create a
Product Profile or Campaign decision, satisfy approval, issue a Permit, reserve budget, materialize
a credential lease or dispatchable Worker job, authorize Gateway egress, execute a Tool, produce
Observation/Evidence, admit Graph knowledge, or confirm a Finding.

Keep the implementation in an explicitly imported specialized module instead of changing the eager
Capability package facade. Existing REDTEAM execution remains authoritative; AI-001B is a binding
and preparation boundary, not a new runtime.

## Consequences

- AI-001A identities can be bound to real existing code-backed Capabilities without granting
  execution authority.
- Provider/model, RAG, MCP, Tool, request, token, cost, and minimum Worker requirements become
  exact and content-addressed before approval.
- Provider secrets and credential material remain outside artifacts; a fingerprint detects secret
  reference drift without revealing the reference.
- The existing pre-Gateway AI executor job remains network-disabled and carries no secret request.
  AI-001B does not claim that an executable provider credential lease has been materialized.
- The existing Profile, Campaign Scope, budget reservation, Approval, ActionPermit, Gateway,
  deployment, credential, Worker, receipt, Observation, Evidence, and Graph authorities remain
  independently required.
- AI-001C can define sealed cross-Surface Observation/Evidence admission, but it cannot infer Tool
  authority from this binding.

## Rejected alternatives

### Add a new generic AI executor

Rejected because the existing REDTEAM Capabilities and adapters already own execution semantics.
A second executor would duplicate behavior and create an alternative authority path.

### Treat provider registration or Tool metadata as current authority

Rejected because registration and schemas describe identity and configuration, not current Scope,
approval, Permit, budget, credential, egress, Worker, or execution authority.

### Materialize credentials and egress during preparation

Rejected because preparation precedes current Campaign, approval, Permit, Gateway, deployment, and
budget checks. Credential leasing and bounded egress belong to the downstream execution boundary.

### Generalize to arbitrary models, agents, RAG routes, or MCP servers

Rejected because this slice must remain tied to four already registered read-only Capabilities.
New targets or active behavior require separately reviewed Capabilities and authority contracts.

## Compatibility and rollback

AI-001B is additive. It changes no existing REDTEAM, CAP-002, provider, ToolRequest, Gateway,
Worker, Discovery, Graph, or benchmark wire. Rollback removes the specialized module, tests,
contract, and this ADR without migrating existing artifacts.

## Related documents

- [AI-001B contract](../capability/AI-001B-provider-model-tool-bound-read-only-analysis.md)
- [AI-001A contract](../discovery/AI-001A-model-rag-agent-mcp-tool-surface-classification.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [CAP-002](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ADR-0202](0202-compose-approved-single-turn-llm-redteam-profile.md)
- [ADR-0203](0203-bind-multi-turn-llm-rag-request-units.md)
- [ADR-0208](0208-register-mcp-capability-without-discovery-authority.md)
- [ADR-0216](0216-classify-ai-surfaces-without-tool-authority.md)
