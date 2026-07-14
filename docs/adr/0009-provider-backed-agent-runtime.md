# ADR-0009: Policy-bound Provider Runtime for reasoning roles

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

> Provider Validator output is semantic evidence review. ADR 0027 prohibits it from creating
> product-level `confirmed` without a separate successful Candidate-bound ReplayOutcome.

## Context

PAJIN's dynamic team originally used deterministic Planner and Validator implementations while the
Reporter rendered canonical state directly. The Provider Gateway from ADR-0008 provided safe model
transport but did not make the multi-agent workflow model-driven. Connecting a model SDK directly
to a role would bypass Tool Gateway policy, Capability accounting, Docker isolation, egress
evidence, Secret Leases, campaign cancellation, and PAJIN's cost controls.

OpenAI Chat Completions Structured Outputs uses
`response_format.type = json_schema` with `strict = true`. Strict output follows the supplied schema,
while a model refusal is returned separately and must not be parsed as the requested object. Chat
Completions also returns prompt, completion, and total token usage. PAJIN follows these documented
wire contracts while retaining a provider-neutral domain layer. See the official
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs) and
[Chat API reference](https://developers.openai.com/api/reference/resources/chat).

## Decision

### Model calls remain Tool calls

Planner, Validator, and Reporter do not call an SDK or HTTP client directly. At each role boundary,
the Supervisor:

1. creates the role Agent and delegates a Capability containing only the registered Provider Tool,
   exact Provider endpoint, T1 risk, and at most two calls;
2. binds a run-scoped `PolicyBoundProviderPort` to that role;
3. builds a Provider-only control-plane Scope distinct from attack-target Scope;
4. dispatches each model request through Tool Gateway, Docker Worker, egress proxy, and a one-use
   Secret Lease; and
5. consumes the role Capability, ancestor Capability, Tool budget, and model budget only when the
   Worker was actually dispatched.

The Supervisor root grant contains both declared attack targets and trusted registered Provider
endpoints, but child grants never combine them. A Specialist receives one offensive Tool and one
declared target. A reasoning role receives one Provider Tool and one Provider endpoint.

### Role isolation and strict drafts

Each model call contains exactly two messages:

- a trusted `developer` message with a fixed Planner, Validator, or Reporter role contract; and
- an untrusted `user` message containing canonical campaign or run data as JSON.

The model returns a role-specific strict draft rather than PAJIN's full internal state:

- Planner returns bounded steps with `arguments_json`; PAJIN parses the JSON and constructs fresh
  `ToolRequest` objects.
- Validator returns candidate findings that still pass the existing same-run evidence, declared
  target, and `validated` checks.
- Reporter returns a bounded narrative supplement. The canonical report and findings remain
  deterministic, and the narrative is persisted separately in `model-narrative.json`.

The Supervisor validates Planner output again before Agent fan-out. Undeclared targets,
unregistered Tools, Provider control-plane Tools, and unsupported methods fail closed.

### Retry, fallback, and refusal behavior

A Provider transport failure, explicit refusal, invalid JSON, or schema-invalid role output may be
retried once with a fixed repair instruction. After the bounded attempts, Planner and Validator use
configured deterministic runtimes; Reporter uses a deterministic narrative. Every fallback is an
audit event.

`BudgetExceeded`, expired or exhausted Capability lineage, Kill Switch activation, and campaign
duration expiry are not model failures. They bypass fallback and stop the campaign.

### Usage and cost budgets

Campaign budgets add `maxModelCalls` and `maxModelTokens`. Every dispatched model call also counts
toward `maxToolCalls`. Complete Provider usage is required for model-backed roles; inconsistent or
missing token totals are a model-call failure. Prompt and completion tokens are recorded separately.
Cost is calculated only from rates explicitly supplied by trusted `ProviderRegistration`; PAJIN
does not infer current vendor pricing. Actual cost contributes to the existing `maxCostUsd` limit.

## Consequences

### Positive

- The dynamic team becomes model-driven without creating a second, ungoverned network path.
- Role prompts, schemas, Capabilities, evidence, and usage are independently auditable.
- Prompt injection in campaign or Tool data cannot directly replace the trusted role instruction.
- Model-created findings and narratives cannot bypass canonical same-run validation.
- Retries remain bounded and cannot evade budget, Capability, or cancellation controls.

### Trade-offs and residual risks

- A Provider may report incorrect usage. Production integrations should reconcile PAJIN telemetry
  with provider billing and rate-limit data.
- Exact Structured Output schema support differs among OpenAI-compatible vendors; each Provider
  registration needs conformance tests.
- Developer/user message separation reduces instruction confusion but does not eliminate prompt
  injection. Planner semantics, cited evidence, and target/tool boundaries therefore remain
  deterministic checks.
- Fallback output may differ from model output. Reports and events explicitly record fallback so
  mixed-mode runs can be identified.
- Model calls currently use Chat Completions. A Responses API adapter should be introduced as a
  separate Provider transport without changing the role contracts.

## Verification

Unit and integration tests cover strict response schemas, invalid-schema retry, bounded Provider
failure fallback, non-bypassable budget exhaustion, role prompt separation, Provider-only role
Capabilities, same-run finding evidence, usage/cost accounting, Lease revocation, and credential
artifact scanning.

The Docker lab executes this sequence:

```text
Provider Planner
  -> ai.chat-probe Specialist through attack Scope
  -> Provider Validator with same-run evidence
  -> canonical finding acceptance
  -> Provider Reporter subordinate narrative
```

All four calls use the same Tool Gateway and Docker egress mechanism, while three Provider calls
receive separate one-use Secret Leases and role-specific Capabilities.

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\mypy src
.venv\Scripts\pytest -q
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --worker docker --allow-private-provider
docker compose -f containers/compose.ai-lab.yaml down
```
