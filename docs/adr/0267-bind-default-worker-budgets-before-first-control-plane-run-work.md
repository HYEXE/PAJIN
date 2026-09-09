# ADR-0267: Bind Default Worker Budgets Before First Control Plane Run Work

- Status: Accepted
- Scope: OPS-001 first-work Campaign accounting
- Builds on: ADR-0264 and ADR-0266

## Context

The journal can recover conservative Campaign and Supervisor counters, but the default Campaign,
Tool Loop and Replay executors previously constructed fresh controllers per execution. A restarted
Worker could therefore lose counters that were outside a Supervisor invocation. Different CP Runs
may legitimately use an identical Campaign, while approval continuation belongs to its original
Run. Campaign digest alone is not a sufficient default journal selector.

## Decision

Compose a `RunBudgetRegistry` into the default generic and Replay Worker entry points. Before
opening a new execution Run or dispatching a Tool, derive the private journal filename from the
authenticated CP Run ID. Bind the exact Campaign, original typed input and accounting mode in
immutable metadata. Different Runs retain separate allowances; retries and approval continuations
reopen the same Run's history. A Job cannot choose a journal path. Only a first claimed attempt can
enroll a fresh journal; a missing retry/resume journal is an error.

An explicitly Run-bound journal uses schema v3 with `pajin.dev/supervisor-journal-run-binding/v1`
metadata. Unbound journals retain schema v2 and their existing migration. The v3 binding is required
on every read/write transaction. Existing nonempty unbound histories cannot be relabeled as fresh
Runs. Older readers reject v3 instead of ignoring the additional identity.

Default executors use a complete Campaign-only account, because these paths do not invoke the
Supervisor. They do not manufacture a dedicated Supervisor allowance. A separately composed
Supervisor journal may select the Campaign-and-Supervisor mode and use the existing atomic pair;
the modes cannot be downgraded or exchanged after enrollment.

Pass the bound controller through Local and Tool Loop runners, General Attack and Capability Graph
dispatch, and the existing exact Replay runtime. Keep existing approval, Permit, Gateway and
idempotent dispatch checks. Dispatch attempts reserve before awaiting execution; proven
non-dispatch releases the live reservation, while uncertain outcomes retain it. Tool Loop resume
checks that the bound counters cover every sealed checkpoint counter before consuming the local
continuation claim. It never overwrites a durable controller with a checkpoint projection.

## Compatibility and limits

The optional library arguments preserve existing embedded behavior. Default daemons now retain
private per-Run journals under their output/staging root, with optional trusted configuration of
the budget root. In-progress legacy work without a complete journal cannot be silently resumed
with a zero allowance; keep its evidence for explicit reconciliation. Retain v3 journals when
changing executables, and do not rewrite them to v2 or reset their consumption.

Run binding and initial budget enrollment complete before work, but are not one transaction with
the CP lease, Graph, source Run or other journals. Budget ownership fences stale controllers and
does not itself revoke an already running external operation. A copied older complete host cannot
be detected without an independently retained expected checkpoint. Full participant inventory,
trusted Supervisor/urgent-producer composition, enforced quiescence and cross-store restore remain
separate OPS-001 obligations.
