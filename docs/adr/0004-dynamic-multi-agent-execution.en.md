> Languages: [English](0004-dynamic-multi-agent-execution.en.md) | [한국어](0004-dynamic-multi-agent-execution.ko.md)

# ADR-0004: Dynamic Multi-Agent Execution and Attenuated Delegation

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

> The Validator and final-gate behavior below records the original implementation decision. Under
> ADR 0027, semantic support and same-Run evidence checks alone cannot create product-level
> `confirmed`; a fresh Candidate-bound ReplayOutcome is also required.

- Call-budget allocation amended by: ADR 0020
- Specialist scheduling amended by: ADR 0021

## Context

PAJIN needs multiple specialized agents without turning agent creation into authority creation. A
model-generated plan is untrusted input: it can invent agent identities, tools, targets, budgets,
dependencies, or findings. Framework-owned agent graphs would also couple campaign state and
cancellation semantics to one model runtime.

The system therefore needs a PAJIN-owned execution graph that can use deterministic or model-backed
Planner and Validator adapters while preserving one authorization, policy, evidence, and Worker
boundary.

## Decision

### Roles and graph ownership

1. `MultiAgentCampaignRunner` is the local Supervisor and owns the complete run state.
2. Every run starts with a Supervisor and dynamically creates a Planner, one Specialist per planned
   step, a separate Semantic Validator, and a Reporter. ADR 0027 adds a trusted Restricted
   Reproducer boundary to the product-level validation pipeline.
3. The Planner returns a typed `AgentPlan` but cannot spawn agents or execute tools. The Supervisor
   ignores every planner-provided `agent_id` and binds each request to the actual Specialist.
4. Tasks are stored in a typed acyclic dependency graph with explicit waiting, running, succeeded,
   failed, cancelled, and skipped states.
5. PAJIN persists agents, the task graph, capabilities, budgets, control state, events, evidence,
   findings, and the report as separate run artifacts.

### Capability attenuation

1. The Supervisor receives the only root Capability Grant. Its tools, targets, risk ceiling, call
   budget, expiry, and delegation depth come from the authorized Campaign and registered tools.
2. Every child Grant must reference its parent, increase depth by exactly one, and be a subset of the
   parent's tools, targets, risk tier, call count, and expiry.
3. Planner, Validator, and Reporter Grants contain no tools, no targets, and zero calls.
4. A Specialist receives only its assigned tool, exact declared target, required risk tier, and
   bounded attempt count.
5. Executing a child call decrements the remaining count of that Grant and every ancestor Grant.
   Sibling Grants therefore cannot amplify the root campaign budget.
6. Kill Switch activation revokes the root and all descendant Grants.

### Budgets, retries, and cancellation

1. Agent count and spawn depth are reserved before an agent is created. The Supervisor rejects a
   plan before fan-out when the full required team exceeds the campaign agent budget.
2. Tool calls are checked before dispatch and counted only after actual dispatch. Campaign elapsed
   time and cost are PAJIN runtime state.
3. T0 and T1 tools may retry once after an executed transient failure. T2 and higher tools are not
   retried automatically. Policy-denied requests are never retried.
4. The Kill Switch is one-way and may be activated programmatically, by policy or budget, or by a
   local signal file.
5. Every awaited Planner, Worker, and Validator operation races the Kill Switch and campaign
   deadline. Cancellation reaches the Worker backend, which kills the Docker CLI process, forcibly
   removes the named container, removes egress resources, and then propagates cancellation upward.
6. Pending and running graph tasks become cancelled, active agents become cancelled, Capability
   lineage is revoked, and the partial run is reported with its cancellation reason.

### Independent finding validation

1. The executing Specialist never marks a finding confirmed.
2. A separate Validator role receives the plan and bounded Tool Results.
3. PAJIN applies a deterministic final gate after Validator output: `validated` must be true, the
   target must be declared in the Campaign, evidence must be non-empty, and every cited artifact
   must exist in the same run's Specialist results.
4. Rejected candidates and their reasons are audit events. Only accepted findings enter
   `findings.json` and the final report.

## Consequences

### Positive

- Dynamic agent creation cannot increase authority.
- Tool permissions are task-specific and auditable through the full parent lineage.
- Model runtime adapters remain replaceable because PAJIN owns state and lifecycle transitions.
- Operator cancellation reaches an active Docker Worker instead of waiting for the tool to finish.
- Findings require both an independent agent decision and deterministic evidence provenance.

### Trade-offs and residual risks

- The local scheduler supports only the bounded opt-in concurrency defined by ADR 0021. Distributed
  execution still requires atomic budget and Capability transactions in a durable backend.
- Local JSONL and JSON artifacts are reproducible but not crash-durable workflow checkpoints.
- Provider token and cost accounting remains zero for deterministic runs; model adapters must report
  provider usage before cost budgets can govern paid calls.
- The local signal-file Kill Switch is polled at short intervals. A production control plane needs
  authenticated cancellation APIs and durable cancellation delivery.
- Planner and Validator implementations may share code in deterministic tests, but they execute as
  distinct role identities with different zero/limited Capabilities and evidence boundaries.

## Verification

The normal command uses Docker by default. Simulated execution is an explicit development-only
contract and its CLI, sealed Run context, and report state that it is not real-target evidence.

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
.venv\Scripts\pajin multi-cancel-check examples\multi-agent-cancel.yaml --worker docker
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

The original acceptance requires five completed role agents and one legacy validation Finding in
the normal Docker run; that Finding is not product-level Confirmed until ADR 0027-compliant
reproduction succeeds; a live Worker dispatch followed by cancelled
Specialist/Validator/Reporter tasks, complete Grant revocation, and no residual PAJIN container or
network in the cancellation run; plus passing tests for sibling budget non-amplification, dynamic
fan-out, bounded retry, external signal cancellation, and invented-evidence rejection.
