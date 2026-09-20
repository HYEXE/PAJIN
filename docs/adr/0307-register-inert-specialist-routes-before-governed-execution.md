# ADR-0307: Register Inert Specialist Routes before Governed Execution

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003A specialist route qualification
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-001 can select a logical XSS, SQL injection, or authorization specialist. Once AGENTIC-002
passes its final conformance gate, it can durably publish that logical assignment. Neither fact
identifies a least-privilege executable route. The installed Juice Shop Web runner currently owns
one aggregate three-diagnostic sequence.
Mapping an XSS-only assignment directly to that runner would silently execute SQL login and object
access work outside the selected specialist closure.

Skill membership cannot close this gap. A Skill is proposal-only knowledge and does not define a
payload, adapter, Capability, Permit, Gateway call, Worker job, Evidence admission, or Finding.

## Decision

Register a closed, code-owned catalog of exact specialist execution-profile metadata before adding
any executable binding. A profile binds:

- an exact ID, semantic version, and content digest;
- one specialist specialization and threat class;
- exact proposal-only selection and supporting Skill references;
- an exact installed adapter ID, implementation digest, and adapter-catalog digest;
- a bounded ordered diagnostic closure and explicit forward dependency edges;
- the steps and Finding categories that a future independent validator may consider; and
- literal non-authority and fresh-approval markers.

The initial Web catalog contains exactly three inert profiles:

1. XSS: `dom-xss` only;
2. SQL injection: `sql-login` only; and
3. authorization: `sql-login -> object-access`, where SQL login is session-acquisition support and
   only `object-access` / `CWE-639` is promotable by this profile.

Profiles are `registered-inert`, have `executionBinding=unbound`, and set
`runtimeSupportAsserted=false`. They do not reference the aggregate diagnostic bundle, routes,
selectors, payloads, callables, Tool Requests, or Worker jobs. Scope, Capability, Permit, Gateway,
Worker, execution, Evidence, Finding, Graph-admission, report, and Skill-lifecycle-upgrade authority
are all literally false.

Resolution requires the complete `(profile ID, version, digest)` tuple. There is no registration,
ID-only lookup, `latest`, fallback, role search, or model-authored catalog mutation. Catalog
construction re-resolves the exact adapter through the production adapter catalog. Strict reload
rejects hidden model state, subclasses, primitive subclasses, digest drift, dependency substitution,
and adapter-catalog substitution.

## Consequences

### Positive

- Logical specialist selection has a reviewable least-privilege closure before execution exists.
- The authorization dependency is explicit without promoting its SQL login prerequisite as an
  authorization Finding.
- Skill identity, adapter identity, diagnostic closure, and future promotable categories cannot be
  rebound through fuzzy lookup.
- Loading or resolving a profile performs no target or network operation.

### Tradeoffs and residual risks

- The profiles are intentionally non-executable. They do not complete AGENTIC-003.
- The current aggregate Web runner cannot satisfy these closures. Browser bootstrap and diagnostic
  execution must be split into exact per-profile executors before runtime support can become true.
- A future assignment bridge must strict-reload the durable cycle, outbox command, selected
  Candidate, Exploit Group, and profile before separately compiling Scope and task authority.
- Fresh approval, single-use Permit, Gateway, Worker, independent replay, Finding promotion, and
  Graph admission remain separate future boundaries.

## Compatibility, migration, and rollback

The change is additive. Existing Skills, Web adapters, diagnostic bundles, AGENTIC-001 objects, and
governed Web execution remain unchanged. No profile is automatically selected or executed.

Rollback removes the profile catalog and its tests. Because no executable binding or target-side
operation is created, rollback requires no target cleanup or data migration.

## Rejected alternatives

### Bind every specialist to the existing three-diagnostic runner

Rejected because it violates task-scoped least privilege and makes profile labels misleading.

### Treat a selected Skill as an executable recipe

Rejected because Skill text is advisory, potentially model-visible content and owns no execution
authority.

### Allow the model or Supervisor to register profiles dynamically

Rejected because Discovery and planning cannot expand the installed execution surface.

## Related documents

- [ADR-0305: Add a Bounded Agentic Hypothesis Frontier and Exploit Group](0305-add-a-bounded-agentic-hypothesis-frontier-and-exploit-group.md)
- [ADR-0306: Publish Durable Agentic Coordination without Execution Authority](0306-publish-durable-agentic-coordination-without-execution-authority.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
