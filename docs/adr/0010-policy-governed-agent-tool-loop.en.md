> Languages: [English](0010-policy-governed-agent-tool-loop.en.md) | [한국어](0010-policy-governed-agent-tool-loop.ko.md)

# ADR-0010: Policy-governed iterative Agent Tool Loop

- Status: Accepted
- Date: 2026-07-12

## Context

ADR-0009 connected PAJIN reasoning roles to a governed Provider, but role output was a single
strict object. Autonomous security work also needs iterative data acquisition: a model requests a
Tool, receives its result, and either finishes or requests another Tool. Treating a Provider
function call as executable authority would let model output bypass Tool Registry, Scope,
Capability attenuation, risk policy, approval, budgets, and Worker isolation.

The official OpenAI function-calling flow is explicitly application-mediated: send available Tool
definitions, receive a Tool call, execute application code, return the result with the matching
call ID, and receive a final response or additional calls. The application remains responsible for
routing and executing each call. Chat Completions can disable parallel calls, and strict functions
require every declared property plus `additionalProperties: false`. See the official
[Function calling guide](https://developers.openai.com/api/docs/guides/function-calling).

## Decision

### A function call is an intent, not a Capability

Provider function names are mapped by trusted `ToolLoopBinding` records to exactly one PAJIN Tool,
target, HTTP method, description, and strict argument schema. The model cannot provide or override
Tool IDs, target URLs, methods, risk tiers, Agent IDs, container images, commands, credentials, or
egress policy.

For each Provider call, PAJIN sends registered strict function schemas with
`parallel_tool_calls = false`. A response is accepted only when it contains zero or one function
call. The Supervisor requires:

- a registered function binding and PAJIN Tool;
- valid JSON object arguments already normalized by the Worker;
- a Tool that is not the control-plane Provider Tool;
- a call fingerprint not seen earlier in the loop; and
- remaining turn, Agent, Tool, Model, token, cost, duration, and Capability budgets.

The fingerprint covers function name, PAJIN Tool ID, fixed target, method, and canonical arguments.
Repeating the same action is blocked rather than retried indefinitely.

### Specialist policy re-entry

The Tool Loop Supervisor owns a root Capability containing registered Provider and bound Tool
authority. The model-facing Agent receives only the Provider Tool and endpoint. Every accepted
intent creates a fresh Specialist Agent and child Capability containing only the mapped PAJIN Tool,
fixed target, observed risk tier, and one call.

The Specialist request passes through the normal Tool Gateway, Campaign authorization, Scope,
method, prohibition, risk, egress, Docker Worker, evidence, and Secret Lease boundaries. Policy
denial is represented as a Tool result; the Provider never receives direct execution authority.

After execution, PAJIN appends the original assistant Tool call and a bounded `tool` message using
the exact `tool_call_id`. Oversized Tool data is replaced by a valid JSON summary containing status,
error, evidence references, and a truncation marker.

### Termination controls

The loop terminates as one of:

- `completed`: the Provider returns final content without another Tool call;
- `awaiting-approval`: a T3/T4 intent is checkpointed before Worker dispatch;
- `denied`: Provider refusal or a supplied approval that does not match the pending intent;
- `budget-exhausted`: turn, Agent, Tool, Model, token, cost, or duration budget stops progress; or
- `failed`: malformed, parallel, unknown, duplicate, or otherwise invalid state.

Provider and Tool calls both consume the shared `maxToolCalls` budget. Provider calls additionally
consume model call, token, and cost budgets. Model failure never resets Tool Loop state or budgets.

### Approval boundary

T0-T2 Tools follow Campaign risk policy. T3 and T4 require a `ToolLoopApproval` bound to the exact
call fingerprint, Tool ID, target, approver identity, approval time, and expiry. Without an approval,
the run stops at `awaiting-approval` and no Specialist or Worker is created. If approval records are
provided but none authorize the pending intent, the continuation is `denied`.

The included `mock.approval-probe` performs a safe deterministic operation but carries T3 solely to
exercise this control. It does not make a local CLI approver string equivalent to production
authentication. Production deployments require an authenticated approval service and signed or
otherwise integrity-protected approval records.

### Checkpoint and continuation

Every meaningful transition writes a new immutable, versioned checkpoint. It includes messages,
seen call fingerprints, pending intent, Tool results, approval IDs, terminal content/error, and a
cumulative budget snapshot. Secret values and Secret references are excluded.

Only `awaiting-approval` checkpoints can be resumed. Resume creates a new continuation run linked by
`resumed_from_run_id`, restores Agent/Tool/Model/token/cost/elapsed usage, reconstructs fresh
Capabilities, executes the exact pending intent if approved, and continues the conversation. A
continuation cannot reset budgets or substitute a different call. Continuation creation atomically
claims the source checkpoint; a claimed checkpoint cannot be resumed again, preventing approval
and side-effect replay.

## Consequences

### Positive

- Multi-turn autonomy reuses the same deterministic security boundary as ordinary Tool execution.
- Model output cannot select infrastructure-level execution details or silently widen Scope.
- Duplicate calls and parallel fan-out cannot multiply side effects.
- T3/T4 work pauses before dispatch and can be resumed from auditable state.
- Checkpoints support crash recovery and external approval workflows without persisting credentials.

### Trade-offs and residual risks

- Checkpoint integrity and one-time claims currently depend on local filesystem integrity.
  Production continuation requires authenticated storage, signatures or MACs, and a transactional
  replay ledger shared by all replicas.
- The initial loop intentionally permits one function call per turn. Parallel execution requires a
  separate dependency, conflict, and aggregate-approval design.
- Tool outputs remain untrusted model input and may contain prompt injection. The developer role
  contract and deterministic Supervisor boundaries remain mandatory on every turn.
- Provider-reported token usage may be inaccurate and should be reconciled with billing telemetry.
- Approval expiry is checked at continuation time; long-running external approval workflows need
  clock synchronization and explicit revocation support.

## Verification

Tests cover the successful Tool call/result/final response flow, strict schemas, disabled parallel
calls, matching call IDs, exact Specialist Capability, duplicate blocking, turn-budget exhaustion,
T3 approval waiting, wrong-target approval denial, cumulative budget restoration, continuation run
linkage, Lease revocation, and cross-run credential scanning.

Docker validation uses two scenarios:

```powershell
.venv\Scripts\pajin tool-loop-run examples\tool-loop-lab.yaml `
  --worker docker --allow-private-provider
.venv\Scripts\pajin tool-loop-approval-check examples\tool-loop-approval-lab.yaml `
  --worker docker --allow-private-provider --approved-by local-security-owner
```

The first completes Provider → Specialist → Provider in two turns. The second proves zero Worker
dispatch before approval, then resumes a linked run and executes the T3 lab Tool exactly once.
