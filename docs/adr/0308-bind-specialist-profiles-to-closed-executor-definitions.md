# ADR-0308: Bind Specialist Profiles to Closed Executor Definitions

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003B specialist executor closure
- Implementation status: Implemented in the local working tree

## Context

ADR-0307 registered exact XSS, SQL injection, and authorization profiles without making them
executable. The existing Web assessment runner cannot implement those profiles because it always
combines browser route exploration, passive discovery, SQL login, object access, DOM XSS, and
attack-path construction. Relabeling that aggregate runner as an XSS-only or SQL-only specialist
would execute work outside the selected assignment.

A first executor draft also showed why a plain observation object cannot become production
provenance. Caller-written screenshots, request records, or object identifiers can be
self-consistent without proving that the code-owned browser and network produced them. Checking a
transport only when an execution is bound also leaves a time-of-check/time-of-use substitution
window.

## Decision

Add a closed, code-owned executor catalog with three distinct immutable definitions:

1. XSS: authenticated browser bootstrap and exactly two ordered DOM-XSS source/replay phases;
2. SQL injection: exactly two ordered SQL-login source/replay phases and no browser; and
3. authorization: authenticated browser bootstrap, SQL-login source/replay, then object-access
   source/replay.

The authorization executor treats SQL login only as a session-acquisition dependency. If that
dependency is not locally reproduced with a usable token and object identity, execution terminates
with a typed dependency error before object-access requests. Only locally reproduced issues whose
checks are listed in the profile's promotable set may appear as promotion candidates. These are
still unvalidated candidates and carry no Finding or Graph authority.

The specialist browser exposes a separate minimal flow. Its inherited aggregate `run` entry point
fails before browser startup. Specialist browser policies deny account registration, SQL impact,
and object-access paths during bootstrap and XSS work; the XSS phase also permits only GET and HEAD.
The executor validates the complete contiguous phase sequence and rejects unknown, reordered,
missing, or repeated phase groups.

The production executor catalog remains non-executable in this phase. Its binding and execution
entry points fail before browser or network I/O until AGENTIC-003C supplies a receiver-admitted
assignment, current durable and Graph heads, a task Capability, fresh approval, single-use Permit,
and a Gateway/Worker-owned invocation. A testing-only catalog may consume injected observations and
transport responses to verify the deterministic closure, but those artifacts are not production
provenance and cannot grant runtime support.

Every descriptor continues to set Scope, Capability, Permit, Gateway, Worker, Finding, and Graph
authority to literal false. The existing aggregate browser, aggregate runner, attack-path builder,
and governed Web dispatch are not invoked by the specialist test harness.

## Consequences

### Positive

- Each logical specialist now has a distinct, reviewable executor identity and digest.
- SQL-only execution cannot start a browser, and the authorization dependency cannot be promoted as
  an authorization Finding.
- Exact source/replay phase ordering is checked for every profile instead of inferred from a set of
  phase prefixes.
- Production callers cannot convert caller-written observations or mutable transports into
  specialist execution before the governed assignment bridge exists.

### Tradeoffs and residual risks

- AGENTIC-003B proves executor closure with a testing-only injected runtime; it does not prove a
  production browser, Gateway, Worker, or target run.
- The low-level browser and diagnostic components remain inside the trusted implementation. The
  AGENTIC-003C process/Gateway boundary must create and retain production network and browser
  provenance without accepting it back by value from the caller.
- Independent replay, semantic validation, Finding promotion, Graph admission, reports, SARIF, and
  PoC projection remain AGENTIC-003D work.
- A Finding admitted in 003D changes the Graph head. Dynamic replanning therefore needs an explicit
  coordination epoch or rollover contract instead of silently reusing the initial pinned head.

## Compatibility, migration, and rollback

The change is additive. Existing Web assessment and governed execution APIs are unchanged. The
specialist production catalog is inert, so no target cleanup, data migration, or authority
revocation is required. Rollback removes the specialist executor catalog, minimal browser flow,
and their tests while retaining the inert profiles from ADR-0307.

## Rejected alternatives

### Reuse the aggregate runner and filter its output

Rejected because filtering output does not prevent out-of-scope browser, network, or diagnostic
effects.

### Accept a signed or shape-validated observation from the caller

Rejected because a by-value object does not prove that the code-owned browser and network produced
the observation in the current execution.

### Enable the production catalog before the assignment authority bridge

Rejected because profile selection and executor identity are not Scope, approval, Permit, Gateway,
or Worker authority.

## Related documents

- [ADR-0307: Register Inert Specialist Routes before Governed Execution](0307-register-inert-specialist-routes-before-governed-execution.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
