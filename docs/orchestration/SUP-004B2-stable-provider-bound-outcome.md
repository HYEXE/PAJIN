# SUP-004B2: Stable Provider Request and Secret-Free Bound Outcome

- Status: Implemented
- Outcome authority: `pajin.dev/provider-bound-chat-outcome/v1alpha1`
- Runtime boundary: `PolicyBoundProviderPort.chat_bound()`
- Decision: [ADR-0122](../adr/0122-bind-stable-provider-requests-to-secret-free-outcomes.md)

## Scope

SUP-004B2 extends the existing policy-bound Provider port with one additive successful-call API.
The caller supplies the exact stable Tool request ID that reaches `ToolGateway`; the port returns
the ephemeral raw `ProviderChatResult` separately from one serializable, content-addressed,
secret-free `ProviderBoundChatOutcome`. The outcome binds the exact request, Gateway decision,
Tool and Worker results, Provider result, evidence reference, untrusted reported usage, and the
conservative Campaign or Campaign-and-dedicated charge from SUP-004B1.

This slice does not schedule or invoke the Shadow Supervisor by itself. It does not durably claim
a checkpoint, prove at-most-once dispatch across a restart or another Run, seal an invocation
receipt, verify the bytes behind a Gateway evidence reference, admit a draft to SUP-003, create or
mutate a Task or Plan, expand Scope, apply a Stop, grant a Capability or Permit, authorize
execution, or enable activation. Those remain SUP-004B3 or later work.

## Stable request and canonical identity

`chat_bound()` accepts one caller-owned request ID that must satisfy the existing portable Tool
request identifier contract. The ID is placed unchanged in the actual Provider `ToolRequest`
before budget reservation or Capability consumption and therefore becomes the Gateway create-only
request reservation and evidence coordinate. Invalid IDs fail before reservation, Capability
consumption, or Worker dispatch.

`canonical_tool_request_digest()` is the single public canonicalization helper shared by Gateway
request reservation, existing Capability activation, and the bound outcome. It reparses the exact
`ToolRequest`, rejects non-strict or oversized JSON, and returns the same SHA-256 that the Gateway
stores as `requestSha256`. A digest implementation cannot drift between these consumers.

The existing Gateway reservation is Run-local. A stable ID prevents a second dispatch only within
that exact Gateway Run. It does not prove a durable cross-process or cross-Run claim.

## Successful outcome contract

The outcome is accepted only when every raw source reparses and all of the following are exact:

- complete Provider registration by digest without exposing its secret reference, Capability
  grant, chat request, and actual Tool request;
- allowed Policy decision, successful Tool result, successful zero-exit Worker result, and
  `executed=true` Gateway outcome;
- request, agent, Tool, Provider, model, endpoint target, streaming mode, and allowed function-tool
  relationships;
- exactly one `evidence/{requestId}.json` reference;
- complete Provider-reported prompt, completion, and total token usage with a consistent total;
  and
- the exact conservative charged prompt/completion/total tokens, cost, model call, Tool call, and
  `campaign` or `campaign-and-dedicated` budget scope.

Domain-separated digests bind the Provider runtime, grant, chat, Tool request, Policy decision,
Tool result, Worker result, Gateway outcome, normalized Provider result, response identity,
target, optional content/refusal/finish reason, normalized tool calls, evidence reference,
Worker identity, and backend. The complete projection derives `outcomeDigest` and
`outcomeId`. `verify_provider_bound_chat_outcome()` reparses the supplied outcome, rebuilds it from
all caller-supplied raw sources, independently recomputes the conservative charged token and cost
bound, and requires exact equality with a separate caller-expected Campaign or dual scope. It does
not read a live budget ledger or prove Run membership.

Raw prompt messages, Provider content or refusal, tool arguments, endpoint, secret reference,
Worker stdout/stderr/network transcript, and raw Gateway or Provider responses are not fields in
the serializable outcome. Their exact digests and bounded byte counts preserve substitution
detection without turning the outcome into another sensitive payload store. The B2 API also
returns the raw Provider result ephemerally, while the existing Gateway evidence artifact remains
unchanged and sensitive; B2 does not remove or sanitize that existing store. Digests bind exact
bytes but are not encryption and do not hide a guessable low-entropy source value.

## Lifecycle and audit

The existing conservative Provider lifecycle remains authoritative. A request reserves the
Campaign-only or dual SUP-004B1 bound before Capability consumption. Proven Gateway
non-execution releases it. Dispatch success, executed failure, timeout, cancellation, invalid
Gateway output, invalid Provider output, or failure to construct the bound outcome keeps the
upper-bound charge. A successful bound call emits the existing `model.call.completed` event with
the new outcome ID and digest; failure emits only the existing bounded failure event.

The outcome is success-only. Its `executed=true` records prior Gateway execution, while
`executionAuthorized=false` grants no new execution. It also fixes
`automaticRedispatchAuthorized`, Task, Plan, Scope, Capability, Permit, and activation markers to
false. No consumer may infer retry or execution authority from the outcome ID, digest, or evidence
path.

Policy, Tool, Gateway, Worker, Provider result, usage, and outcome scalar fields that participate
in successful-call decisions reject boolean/integer coercion. Values such as `1`, `0`, `"true"`,
or `"false"` cannot cross those trust boundaries as JSON booleans or exit code zero.

## Negative boundaries

Construction or verification fails closed for:

- invalid or substituted stable request identity, Tool request, chat, registration, grant, target,
  Provider, model, decision, Tool result, Worker result, Gateway result, or Provider result;
- digest or outcome-ID forgery, source substitution, unknown fields, ambiguous scalar types, NaN,
  infinity, non-canonical JSON, or bounded-size violations;
- denial, non-execution, result identity mismatch, unsuccessful Tool or Worker status, nonzero
  successful exit code, missing or multiple evidence references, or incomplete/inconsistent usage;
- a claimed charge that differs from the independently recomputed conservative request bound or
  the caller-expected Campaign/dedicated scope; and
- raw request, result, secret, Worker transcript, or new authority fields added to the outcome.

## Compatibility, migration, and rollback

`chat_bound()`, the outcome models, verifier, and canonical Tool request helper are additive.
Existing `chat()` and `complete()` signatures, random Tool request IDs, return values, Provider
transport, wire readers, and Campaign-only budget behavior remain unchanged. Existing valid JSON
booleans and integer exit codes remain valid; only previously ambiguous coercions now fail closed.

No data migration is required because this slice does not persist an outcome artifact. Rollback
removes the additive bound-call API and outcome types. The shared canonical request digest and
strict authority-scalar validation may remain as independent hardening. SUP-004B3 must add a
durable intent-before-dispatch journal and sealed consumer-verified Supervisor receipt before any
model-backed draft reaches SUP-003.
