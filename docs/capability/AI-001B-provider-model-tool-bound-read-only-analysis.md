# AI-001B: Provider, Model, and Tool-bound Read-only Analysis

- Status: Implemented, binding and preparation boundary only
- API versions:
  - `pajin.dev/ai-read-only-analysis-capability-binding/v1alpha1`
  - `pajin.dev/ai-provider-model-binding/v1alpha1`
  - `pajin.dev/ai-analysis-budget-ceiling/v1alpha1`
  - `pajin.dev/ai-read-only-analysis-binding/v1alpha1`
  - `pajin.dev/ai-read-only-analysis-preparation/v1alpha1`
- Authority: `src/pajin/capabilities/ai_analysis.py`
- Decision: [ADR-0217](../adr/0217-bind-ai-analysis-without-provider-authority.md)

## Purpose

AI-001B exact-binds the existing REDTEAM-001A, REDTEAM-001B, and REDTEAM-001D read-only
Capabilities to their code-backed CAP-002 authority sets, AI-001A typed Surfaces, and the DOMAIN-004
minimum AI Worker requirements. It reuses the existing Capability lifecycle and action preparation
path. It adds no new Profile, Capability, Tool, executor, provider client, MCP client, Gateway,
Worker, Observation, Evidence, Graph writer, or Finding path.

The binding and preparation artifacts are non-authoritative composition records. They cannot turn
a Profile name, Domain classification, provider registration, model identity, RAG route, MCP
advertisement, or Tool schema into Scope, credential, network, Permit, Worker, or execution
authority.

## Code-owned Capability bindings

The registry contains exactly four bindings in code-owned order:

| Existing contract | Exact Capability | Required AI-001A Surface classes | Request units |
| --- | --- | --- | --- |
| REDTEAM-001A M03 | `pajin.ai.kisa.system-prompt-disclosure@1.0.0` | model, Tool | 1 |
| REDTEAM-001A M06 | `pajin.ai.kisa.jailbreak-policy-bypass@1.0.0` | model, Tool | 1 |
| REDTEAM-001B A04 | `pajin.ai.kisa.memory-poisoning-persistence@1.1.0` | model, RAG, Tool | 2 |
| REDTEAM-001D MCP | `pajin.ai.mcp.instruction-hijacking-inspection@1.0.0` | MCP, Tool | 1 |

Each `AIReadOnlyAnalysisCapabilityBinding` pins the exact compatibility Profile reference,
complete `CodeBackedCapabilityRef`, DOMAIN-003 AI classification, DOMAIN-004 minimum AI Worker
profile, Tool-interface Surface, scenario, threat class, side-effect class, and request-unit cost.
The implementation reopens all code-owned records instead of accepting metadata as authority.

The referenced AI Worker profile requires bounded egress, no host filesystem access, ephemeral
credential leases, and isolated non-root execution. It is a minimum requirement, not a deployment
selection, conformance proof, credential grant, or network policy.

## Provider, model, Surface, and budget binding

Provider-backed M03, M06, and A04 bindings require a canonical current `ProviderRegistration` and
an immutable model revision. `AIProviderModelBinding` content-addresses the exact provider ID,
endpoint, model, revision, provider-registration digest, secret-reference fingerprint, and typed
model Surface. It never embeds the secret reference or credential material, and it grants no
credential access or provider invocation.

The dynamic Surface set is exact and ordered:

- M03 and M06: model, registered Capability Tool;
- A04: model, retrieval-only POST RAG route at the same provider endpoint, registered Capability
  Tool; and
- MCP: the fixed `demo-security` server advertising `tools`, followed by the registered Capability
  Tool, with no provider/model input.

`AIAnalysisBudgetCeiling` records exact integer request, input-token, output-token, total-token, and
micro-USD ceilings. Total tokens must equal input plus output. Provider-backed actions require
positive token ceilings; the MCP-only action must carry zero provider token and cost ceilings. The
record attenuates a future action but neither reserves nor spends a budget.

## Preparation boundary

`prepare_ai_read_only_analysis` revalidates:

- the complete content-addressed binding and canonical Tool request;
- the current provider registration for provider-backed bindings;
- the exact Capability manifest in an existing signed lifecycle activation;
- the exact release already admitted by that activation; and
- the existing Capability-specific Tool request schema and target.

It then delegates to the existing CAP-002 `prepare_action` path. The result is
`prepared-not-authorized` and explicitly records that no Profile or Campaign Scope recheck,
approval, ActionPermit, budget reservation, credential lease, Worker job, Gateway dispatch,
Observation, Evidence, Graph admission, Finding, or execution has occurred.

The existing `AIChatProbeTool` executor can materialize a pre-Gateway `WorkerJob` independently of
this contract. That job currently has `NetworkMode.NONE`, no egress policy, and no secret request.
AI-001B deliberately does not reinterpret it as an executable provider job or materialized
credential lease. The current Product Profile, Campaign Scope, provider usage budget, credential
lease, deployment-bound AI Worker, and Gateway policy remain downstream requirements.

## Required downstream authority path

```text
AI-001A typed Surfaces
-> AI-001B exact provider/model/RAG/MCP/Tool and budget binding
-> current signed REDTEAM Capability activation
-> PreparedCapabilityAction
-> current Product Profile and Campaign Scope
-> Policy / Approval
-> request, token, and cost reservation
-> one-use ActionPermit
-> current Provider registration and ephemeral credential lease
-> Gateway policy re-entry and exact egress policy
-> deployment-bound direct-mTLS AI Worker
-> trusted receipt and sealed Observation/Evidence
```

AI-001B stops at `PreparedCapabilityAction`. Existing REDTEAM execution remains the only supported
execution path; that path still does not consume the new binding before dispatch. AI-001C is a
separate post-execution admission boundary that pairs this exact preparation with an already
sealed REDTEAM result and creates no new execution authority.

## Fail-closed behavior

Validation rejects:

- a non-registered Capability binding or changed digest;
- Profile, CAP-002 authority-set, DOMAIN-003 classification, Worker profile, Tool Surface,
  scenario, threat class, request-unit, network, credential, or side-effect substitution;
- a stale or changed provider registration, mutable model revision, secret embedding, or model
  Surface drift;
- missing, reordered, extra, or wrong-class model/RAG/MCP/Tool Surfaces;
- a RAG route that is not retrieval-only POST at the exact provider endpoint;
- an MCP server other than the fixed registered `demo-security` Tool boundary;
- request/token/cost ceiling mismatch, coercion, or a claimed reservation;
- a stale, forged, mismatched, or unusable signed Capability activation and release;
- Tool target, method, scenario, threat class, turns, checks, or fixed MCP input drift; and
- extra metadata, true authority markers, or permissive boolean and integer coercion.

## Explicit non-authority

No AI-001B artifact selects a Product Profile, expands Campaign Scope, activates a Capability,
satisfies approval, issues or consumes a Permit, reserves budget, materializes a credential lease,
selects a Worker or deployment, authorizes network access, invokes a provider, queries RAG, calls
MCP or a Tool, produces an Observation or Evidence, admits Graph knowledge, confirms a Finding, or
executes an action.

## Compatibility and rollback

The implementation is additive. Existing REDTEAM-001A/B/D, CAP-001/CAP-002, provider,
ToolRequest, Gateway, WorkerJob, Discovery, Graph, benchmark, and artifact wire identities remain
unchanged. The specialized module is intentionally not imported from the eager
`pajin.capabilities` facade, preserving current package import order. Consumers import
`pajin.capabilities.ai_analysis` explicitly.

Rollback removes the module, tests, contract, and ADR. Existing stored artifacts require no
migration.

## Verification

`tests/test_ai_read_only_analysis.py` covers the exact four-Capability inventory, Profile/CAP-002/
Tool/AI-Worker binding, secret-free provider/model identity, exact model/RAG/MCP Surface sets,
request/token/cost ceilings, real signed lifecycle preparation, pre-Gateway network and credential
denial, provider/release/request substitution, Surface and budget mismatch, metadata injection,
authority escalation, digest drift, and boolean/integer coercion.
