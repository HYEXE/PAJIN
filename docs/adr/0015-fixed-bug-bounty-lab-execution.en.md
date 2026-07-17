> Languages: [English](0015-fixed-bug-bounty-lab-execution.en.md) | [한국어](0015-fixed-bug-bounty-lab-execution.ko.md)

# ADR 0015: Fixed Bug Bounty local-lab execution

- Status: Accepted
- Date: 2026-07-13
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

> Recomputing the original control-set observations is evidence review, not independent
> reproduction. ADR 0027 requires a distinct replay request and evidence lineage before a security
> Finding becomes product-level `confirmed`.

## Context

The Scope Parser and conservative reporter establish authorization and reporting boundaries, but
they do not demonstrate a complete Bug Bounty multi-agent execution. Executing a generic exploit
chosen by a model would exceed the current safety case: it could introduce unbounded payloads,
traffic, endpoints, and data access while treating an agent's claim as validation.

PAJIN needs a real, reproducible vertical slice that exercises the Docker Worker, egress proxy,
Planner, Specialist, Validator, evidence store, and draft reporter without targeting a public
system or real user data.

## Decision

PAJIN adds one executable asset profile, `boolean-sqli-lab`, available only when all of these
conditions hold:

- the `BugBountyProgram` platform is `local-lab`;
- private-network access is explicitly enabled;
- every executable entry point uses `host.docker.internal`;
- the compiled target type is `bug-bounty-api`;
- the approved Tool categories include every category declared by the fixed probe.

The local target contains two synthetic records and binds only to host loopback port 8770. Its
vulnerable profile models one exact Boolean SQL injection signal; its hardened profile rejects
non-numeric identifiers. Neither profile has credentials, persistent state, production data, or an
external submission path.

`BugBountyPlannerRuntime` emits one typed `bug-bounty.boolean-sqli-probe` step for each compiled lab
target. The Tool input contains only the fixed scenario identifier. It rejects other methods,
queries, fragments, and endpoint paths. The trusted Worker owns the three fixed request values and
performs exactly a baseline, false control, and true Boolean comparison through Gateway-injected
egress. The Tool declares a request cost of three so the campaign rate limit measures the actual
number of HTTP requests.

`BugBountyValidatorRuntime` reparses the observations and independently requires:

1. a 200 baseline containing one synthetic record;
2. an empty 200 or 400 negative control;
3. a 200 Boolean probe containing more records than the baseline;
4. a synthetic marker on every observation;
5. evidence produced by the associated Specialist result.

The Validator deliberately ignores the Worker's `vulnerable` value and derived check booleans.
Only its recomputed result becomes a validated `CWE-89` Finding. The generic multi-agent runner then
enforces evidence and target binding before the Bug Bounty reporter checks the current policy
digest and creates conservative local drafts.

`bug-bounty-run` is Docker-only. It has no simulated execution option and never submits externally.
Generic public Bug Bounty programs can still be reviewed and compiled, but the Planner refuses to
execute them until a separate bounded probe profile exists.

## Consequences

This slice demonstrates the complete architecture against a real HTTP target while keeping the
attack grammar and traffic finite. The vulnerable/hardened pair also supplies a deterministic
positive and negative integration test.

It is not a general SQL injection scanner. It does not discover parameters, accept arbitrary
payloads, crawl, enumerate records, calculate CVSS, authenticate to a bounty platform, or prove
that a production target is vulnerable. Adding another vulnerability class requires a new typed
profile, Worker command, request cost, Mode-owned evidence-review and replay contracts, and safety
review.

## Validation

Tests cover profile compilation and private-network restrictions, fixed Tool input, Gateway-only
egress, three-unit rate reservation, independent observation recomputation, hardened rejection,
five-role multi-agent execution, evidence-bound draft generation, Docker-only CLI selection, and
the synthetic target behavior. The Docker integration sequence runs both vulnerable and hardened
profiles through the same digest-approved Campaign.
