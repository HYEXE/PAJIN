# ADR-0311: Define and Activate Exact Specialist Capabilities without Dispatch Authority

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C3A exact specialist Capability preparation
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-003C2 binds one live specialist assignment to an exact Campaign, Target, Scope, budget,
profile, and executor, but deliberately produces no Capability definition, Tool request, lifecycle
activation, or prepared Capability action. The existing aggregate Web Capability authorizes a
larger diagnostic and validation topology than one selected XSS, SQL-injection, or authorization
specialist task and cannot be relabeled as least-privilege specialist authority.

The next boundary must therefore create exact code-backed Capability material while preserving the
rule that neither model output nor a serialized preparation can dispatch work. It must also bind a
preprovisioned account without allowing account creation, caller-selected routes, payloads,
policies, or transports.

## Decision

Add an additive, non-dispatching AGENTIC-003C3A Capability boundary.

Define three distinct experimental, read-only, T2 Capabilities and Tools:

- `pajin.bug-bounty.web-specialist.dom-xss` / `web.specialist.dom-xss`;
- `pajin.bug-bounty.web-specialist.sql-login` / `web.specialist.sql-login`; and
- `pajin.bug-bounty.web-specialist.authorization` / `web.specialist.authorization`.

Each Tool accepts only the exact preparation ID and digest plus a reference to a signed,
preprovisioned account receipt. The Tool independently resolves immutable preparation, adapter,
and account-receipt registries and re-resolves the current code-owned Target profile, specialist
profile, and executor. Its request identity is derived by the Tool from the exact specialization,
agent, Target, and canonical parameters. Caller-authored routes, payloads, policies, transports,
account creation, and Target mutation remain prohibited.

Each Capability has a complete seven-role authority set. Only materialization and action
compilation produce deterministic, non-executing values. Tool `prepare` and `interpret`, and the
executor, result normalizer, success oracle, replay strategy, and cleanup handler all fail closed
until a later one-shot dispatch binding exists.

A signed lifecycle release may activate exactly one Capability for Range use. Activation rechecks
the current signed release and code-backed definition on every use. `prepare_action()` then emits
one deterministic `PreparedCapabilityAction` tied to that activation, release, Capability,
specialist request, preparation, signed account receipt, and installed adapter. The fixed request
unit charge is a conservative bound of 100 units; it is not measured specialist runtime cost.

This phase creates no Capability Grant, approval authority, ActionPermit, Gateway binding, Worker,
browser or network dispatch, Evidence, Finding, Graph write, report, SARIF, PoC, or delivery
authority. A `PreparedCapabilityAction` is descriptive input for the next durable boundary, not a
bearer authorization.

## Consequences

### Positive

- Each specialist receives a separate Capability and Tool instead of inheriting the aggregate Web
  execution surface.
- Exact signed lifecycle, adapter, and account material is revalidated before a prepared action is
  produced.
- A caller can select only registered references; it cannot widen routes, policy, transport, or
  payload semantics.
- Complete authority-role registration is available before execution, while every execution role
  remains fail closed.
- Deterministic request identity prevents a self-consistent substituted request ID from becoming a
  different action.

### Tradeoffs and residual risks

- Only the deployment-owned local Juice Shop adapter and the three registered specialist
  specializations are supported.
- The fixed 100-unit reservation is conservative and may overreserve until the specialist Worker
  has an independently measured request trace.
- A signed Range activation and prepared action still require an exact one-call, non-delegable
  Grant, fresh signed approval, single-use Permit, durable dispatch transition, Gateway, and
  specialist Worker before any Target I/O is possible.
- Independent Replay, Finding promotion, Graph admission, reporting, SARIF, and redacted PoC
  projection remain AGENTIC-003D work.

## Compatibility, migration, and rollback

The Capability, Tool, parameter, and activation APIs are additive. This phase does not change the
coordination-store schema and does not alter existing aggregate Web Capability, Permit, Gateway,
Worker, Finding, or Graph wire formats. Rollback removes the three specialist Capability
definitions, Tools, activation wrapper, preparation registry, and tests. No Target-side rollback
is required because this phase performs no Target I/O.

## Rejected alternatives

### Reuse the aggregate Web Capability and Tool

Rejected because their multi-diagnostic and validation authority exceeds one selected specialist
task and is not tied to the specialist assignment or executor closure.

### Let the caller provide a Tool request, route, payload, policy, or transport

Rejected because a self-consistent caller-defined request could widen the selected specialist
closure or egress boundary.

### Treat a preparation or account reference as sufficient dispatch authority

Rejected because a preparation is audit material and an account receipt proves provisioning, not
current Capability, approval, Permit, or one-use dispatch authority.

### Install a temporary production executor while the bridge is unfinished

Rejected because partial execution would bypass the future durable plan, Permit callback, Gateway,
and Worker-owned provenance boundaries.

## Related documents

- [ADR-0310: Bind Specialist Action Preparation without Execution Authority](0310-bind-specialist-action-preparation-without-execution-authority.md)
- [ADR-0308: Bind Specialist Profiles to Closed Executor Definitions](0308-bind-specialist-profiles-to-closed-executor-definitions.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
