> Languages: [English](0008-provider-gateway-and-secret-leases.en.md) | [한국어](0008-provider-gateway-and-secret-leases.ko.md)

# ADR-0008: OpenAI-compatible Provider Gateway and Secret Leases

- Status: Accepted
- Date: 2026-07-12

## Context

PAJIN Agents need model access without gaining authority over provider endpoints, model selection,
credentials, or arbitrary function execution. Passing a provider key through Agent state, a plan,
Tool arguments, Docker environment variables, or evidence would make prompts and audit artifacts a
credential exfiltration path. Provider-specific SDK objects would also leak vendor semantics into
the orchestration and validation layers.

OpenAI Chat Completions accepts a list of messages at `POST /chat/completions` and returns choices
containing assistant messages. Streaming uses data-only server-sent events and ends with `[DONE]`.
Function-call arguments are JSON strings supplied by the model and must be validated by the
application before use. These wire-level facts are documented in the official
[Chat API reference](https://developers.openai.com/api/reference/resources/chat),
[streaming guide](https://developers.openai.com/api/docs/guides/streaming-responses), and
[function-calling guide](https://developers.openai.com/api/docs/guides/function-calling).

## Decision

### Trusted registration, untrusted requests

`ProviderRegistration` is trusted configuration. It fixes the provider ID, exact HTTP endpoint,
model, secret reference, streaming permission, Lease TTL, and allowed function names. Agent input
contains only canonical messages, the stream flag, bounded completion settings, and registered
function schemas. Unknown fields, endpoint/model overrides, unregistered functions, non-POST
methods, and target mismatches fail before Worker dispatch.

The deterministic `provider-check` planner accepts exactly one Campaign target, requires its type
to be `openai-compatible-provider`, and binds its endpoint to the registration. Function and
structured-output schemas are detached immutable JSON snapshots: object keys must be strings,
numbers finite, nesting at most 32 levels, node count at most 20,000, and canonical UTF-8 JSON at
most 256 KiB. JSON Schema `$ref` strings remain valid; Python container cycles do not.

The initial adapter intentionally targets the minimal OpenAI-compatible Chat Completions surface.
Support for the Responses API and provider-specific extensions requires a separate adapter and ADR.

### Secret Lease lifecycle

The supervisor-side `SecretBroker` stores plaintext values in memory and exposes only metadata to
the rest of PAJIN. For each approved Worker execution, the Tool Gateway:

1. issues an audience-bound Lease with a 1-300 second TTL and one permitted materialization;
2. records only Lease ID, binding, reference fingerprint, and expiry;
3. materializes the value for the exact Agent/execution audience;
4. passes it to the Docker backend as a separate `SecretMaterial` object;
5. constructs a versioned stdin envelope immediately before process execution; and
6. revokes the Lease in `finally` when Worker execution ends.

The plaintext is not added to `WorkerJob`, Docker command arguments, environment variables,
Capability state, plan, events, reports, or evidence. Worker stdout, stderr, proxy logs, normalized
Tool results, and nested result values are redacted before persistence. Campaign cancellation also
revokes all active Leases.

### Provider normalization

The isolated Worker adds the Bearer credential and sends the fixed request through the campaign
egress proxy. Non-stream responses and SSE deltas become one `ProviderChatResult`. Streamed text,
refusal text, usage, finish reason, and tool calls are accumulated with byte and chunk bounds. Tool
calls are ordered by index; their argument fragments are preserved as raw JSON and separately
parsed to a dictionary with an explicit validity flag. The adapter returns tool-call intent only
and does not execute it.

The supported dialect requires every non-stream response and every SSE identity chunk to contain a
bounded `model` string. The normalized model must exactly equal the registered/requested model.
Missing or mismatched values are rejected; PAJIN never fills a missing response identity from its
own request because doing so would turn an unverified claim into an apparently observed value.

## Consequences

### Positive

- Agents cannot redirect a credential to a different endpoint or select an unregistered model.
- Provider-specific wire formats terminate at the Worker boundary.
- The same policy, Scope, Capability, budget, egress, evidence, and Kill Switch paths govern model
  access and other PAJIN tools.
- One-use, short-lived credentials have an auditable issuance and revocation lifecycle without
  placing their values in audit data.
- A malicious or broken provider response that echoes its credential is redacted before an Agent or
  artifact can observe it.

### Trade-offs and residual risks

- Python strings cannot be reliably zeroized. The current broker is suitable for the local runtime,
  but production deployment needs a platform vault, isolated supervisor, restricted diagnostics,
  and process-level hardening.
- Exact-value redaction cannot catch transformed, encoded, hashed, or partially disclosed secrets.
  Provider credentials should therefore remain narrowly scoped and rapidly rotatable.
- Chat Completions compatibility varies across vendors. Unsupported extensions are rejected rather
  than passed through, and each new dialect requires conformance tests. Providers that omit the
  response `model` identity are not compatible with this adapter.
- The proxy prevents out-of-scope redirects at the network boundary, but provider trust, retention,
  regional processing, and contractual data controls remain deployment responsibilities.
- Provider function calls are only normalized. A future execution loop must perform an independent
  PAJIN Tool lookup, schema validation, policy evaluation, Capability check, and result-message
  binding before any function is run.

## Verification

The deterministic suite covers Lease use, audience mismatch, expiry, revocation, nested redaction,
fixed provider registration, stdin-only injection, artifact leak scanning, and streamed tool-call
assembly. The Docker validation campaign adds four Specialist agents and verifies:

- authenticated non-stream response normalization;
- SSE text and usage normalization through the egress proxy;
- indexed function-call fragment assembly and JSON validation;
- simulated provider-side credential echo redaction;
- four issued and four revoked, fully consumed Leases; and
- no raw credential in any run artifact.

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\mypy src
.venv\Scripts\pytest -q
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin provider-check examples\provider-openai-compatible-lab.yaml --worker docker
```
