# ADR-0227: Bind Cloud Policy Replay and Fixtures without Provider Authority

## Status

Accepted

## Context

CLOUD-001C proves that one separately authorized read-only Cloud request produced a sealed neutral
response receipt. It intentionally keeps the raw provider body and provider-derived resource and
policy fields outside the Graph. Its HTTP status and response-body digest therefore are not an
evaluable policy, do not establish provider semantics, and cannot serve as deterministic Replay
input.

DOMAIN-006 requires `fresh-credential-deterministic-reevaluation` for the Cloud slice. Reusing a
consumed ActionPermit or credential lease would violate the existing one-use authority boundary.
Accepting an unsigned interpreted policy would allow caller-selected data to be confused with the
sealed provider execution. Conversely, provisioning a provider account or emulator in this
repository would fabricate Target Factory, credential, runtime, cost, and cleanup authority that
does not exist.

## Decision

Add a CLOUD-001D boundary with two independent artifacts.

The Replay boundary accepts two already completed and admitted CLOUD-001C policy-read executions.
It reopens each execution through the CLOUD-001C loader using the same caller-configured deployment
trust anchor and its own SQLite authority store. It requires both Graph admissions to remain stored
exactly. Source and Replay preserve the same typed IAM Surface, Campaign Scope, signed Capability
and release, provider adapter and route, request semantics, credential audience, secret-reference
fingerprint, exact policy query, and deterministic evaluator.

Require separate Run, preparation, request, normalized-parameter, MissionEnvelope, Graph Decision,
ActionProposal, approval receipt, consumed ActionPermit, dispatch, credential-lease fingerprint,
signed statement, external execution, source-root, CLOUD-001C admission, and policy-artifact
identities. The two historical credential-use receipts must each show a separately materialized,
single-use, discarded lease. CLOUD-001D does not acquire, materialize, reuse, or authorize either
credential.

Each execution must also carry one bounded `CloudPolicySanitizedArtifact`. The deployment derives
this provider-neutral artifact outside the Graph and signs it with the configured Ed25519 key under
a signature domain distinct from the CLOUD-001C execution statement. The artifact binds its exact
CLOUD-001C admission, external execution, source root, statement digest, detached response receipt,
response-body digest, and trust-anchor digest. It embeds neither the raw response nor credential
material. The signature proves deployment provenance and binding; it does not prove that the
projection captures the provider's complete or effective permission semantics.

Accept only exact principal/action/resource rules with `allow` or `deny` effects. Reject wildcard
or provider-specific matching. Evaluate one exact query with fixed `deny`-overrides-`allow`
semantics: a matching deny produces `explicit-deny`, otherwise a matching allow produces `allow`,
and no match produces `implicit-deny`. Compare the two signed rule sets and deterministic decisions
as one of:

- `policy-input-and-decision-match`;
- `policy-input-changed-decision-match`; or
- `policy-decision-changed`.

These are neutral comparison states. They do not confirm provider policy semantics, resource
existence, or effective permission; create a Hypothesis or Finding; satisfy a Profile validation
floor; or authorize Scope expansion, credential use, provider execution, mutation, Replay, or
another action.

Separately register three code-owned Ground Truth cases for a future disposable provider account
or emulator: exact allow, explicit deny overriding allow, and an implicit-deny negative Control.
Every case requires a fresh single-use credential, disposable account-or-emulator isolation, and
destroyed-account or reset-emulator cleanup evidence. The profile state is
`registered-fixture-ground-truth-not-provisioned-or-measured`; it provisions no Target or
credential, performs no cleanup, binds no live Replay evidence, and emits no numeric metric.

## Consequences

- A response digest cannot be substituted for policy input; both evaluated inputs have explicit,
  signed, content-addressed provenance.
- Fresh-credential Replay requires two complete prior authority lineages and cannot redispatch from
  Graph knowledge or reuse a consumed Permit or lease.
- Deterministic input and decision drift are represented without claiming provider-effective
  access or a Finding.
- The three-case denominator, negative Control, isolation, and cleanup requirements are explicit
  before a provider/emulator measurement adapter exists.
- A future benchmark runner must provision a disposable environment, acquire separately authorized
  credentials, execute and seal each case, verify cleanup evidence, bind results to the registered
  cases, and aggregate DOMAIN-006 metrics before claiming coverage or a validation floor.

## Rejected alternatives

### Evaluate the CLOUD-001C response digest

Rejected because a digest provides content identity but no fields, rules, query semantics, or
provider interpretation suitable for deterministic evaluation.

### Reuse the source Permit or credential lease

Rejected because both are single-use authority. Historical receipts are provenance, not bearer
authorization for another request.

### Trust an unsigned sanitized policy document

Rejected because a caller could substitute policy input independently of the sealed CLOUD-001C
execution and Graph admission.

### Confirm effective permissions when both decisions match

Rejected because two identical exact-match projections can share the same omission or translation
error. Provider-effective authorization requires a separately bounded Oracle or controlled
provider/emulator Ground Truth execution.

### Provision a disposable provider account or emulator now

Rejected because no Target Factory profile, provider runtime, credential acquisition workflow,
cost authority, or cleanup executor is implemented by this slice.

## Compatibility and rollback

CLOUD-001D is additive and explicitly imported. It changes no CLOUD-001A/B/C, DOMAIN-006,
Campaign, Scope, Capability, ToolRequest, approval, ActionPermit, SecretBroker, Worker, Graph,
Replay, Finding, benchmark, or existing artifact wire. Rollback stops producing the CLOUD-001D
validation and fixture profile and removes their module, tests, contract, and this ADR. Existing
sealed executions, signed artifacts, and immutable Graph events require no migration.

## Related documents

- [CLOUD-001D contract](../benchmark/CLOUD-001D-fresh-credential-policy-replay-disposable-fixtures.md)
- [CLOUD-001C](../graph/CLOUD-001C-sealed-cloud-provider-observation-admission.md)
- [CLOUD-001B](../capability/CLOUD-001B-read-only-inventory-policy-capability.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0226](0226-admit-cloud-api-observations-without-credential-use-authority.md)
- [ADR-0211](0211-register-domain-metrics-without-measurement-authority.md)
