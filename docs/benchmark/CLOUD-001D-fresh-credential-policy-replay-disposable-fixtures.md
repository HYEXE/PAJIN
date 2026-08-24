# CLOUD-001D: Fresh-credential Policy Replay and Disposable Fixtures

- Status: Implemented, bounded deterministic comparison and unmeasured fixture Ground Truth
- Artifact bundle: `pajin.dev/cloud-policy-artifact-bundle/v1alpha1`
- Replay projection: `pajin.dev/cloud-policy-replay-validation/v1alpha1`
- Fixture profile: `pajin.dev/cloud-policy-benchmark-fixture-profile/v1alpha1`
- Authority: `src/pajin/workflow/cloud_policy_replay_benchmark.py`
- Decision:
  [ADR-0227](../adr/0227-bind-cloud-policy-replay-and-fixtures-without-provider-authority.md)
- Predecessors: [CLOUD-001C](../graph/CLOUD-001C-sealed-cloud-provider-observation-admission.md),
  [CLOUD-001B](../capability/CLOUD-001B-read-only-inventory-policy-capability.md), and
  [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

CLOUD-001D closes two different first-slice requirements without adding a Cloud provider client,
credential broker caller, Target Factory, emulator driver, or measurement engine:

1. compare deterministic policy evaluation from two separately authorized, fresh-credential
   CLOUD-001C policy reads; and
2. register the disposable account/emulator Ground Truth cases required by a future Cloud policy
   benchmark.

The artifacts remain separate. A Replay comparison is not a Ground Truth measurement, and a
registered fixture is not evidence that an account or emulator was provisioned, executed, cleaned
up, or measured.

## Required predecessor executions

`CloudPolicyReplayBenchmarkGate` accepts two complete CLOUD-001C source/admission tuples and their
own SQLite Graph stores. It re-runs the CLOUD-001C source verifier for each tuple using one
deployment-configured trust anchor. Each source must still have:

- current Cloud activation and exact Campaign Scope;
- one policy-read CLOUD-001B preparation for the same typed IAM Surface and explicit provider GET
  route;
- one exact consumed ActionPermit and durable approval-consumption receipt;
- a trusted signed external execution statement and detached neutral response receipt;
- one signed historical broker-recheck, materialization, use, and discard receipt for its own
  single-use lease; and
- one exact admitted CLOUD-001C Graph event still present in the supplied store.

Source and Replay must preserve the same Surface, Campaign, Capability, signed release, activation
set, provider adapter, route and request semantics, credential audience/binding/scope,
secret-reference fingerprint, deterministic evaluator, and exact policy query. They must use
different Run, preparation, request, normalized parameter, envelope, Decision, Proposal, approval,
Permit, dispatch, credential-lease fingerprint, signed statement, external execution, source root,
Graph admission, and policy-artifact identities. Reusing the source tuple as Replay fails closed.

“Fresh credential” means the two already completed signed executions used distinct fingerprint-only
single-use lease references that were separately consumed and discarded. The builder itself never
receives a bearer lease ID or credential material and performs no broker, provider, Worker, or
network operation.

## Sanitized policy artifact

The CLOUD-001C response body remains external and its digest alone is not policy input. For each
execution the deployment produces one strict bounded JSON `CloudPolicySanitizedArtifact` containing
only:

- the exact CLOUD-001C admission and external execution identities;
- source-root, execution-statement, response-receipt, response-body, and trust-anchor digests;
- the registered evaluator reference;
- uniquely sorted exact principal/action/resource `allow` or `deny` rules; and
- one exact principal/action/resource query.

The deployment signs the artifact with the configured Ed25519 key under a policy-artifact signature
domain distinct from the CLOUD-001C execution signature. The reader accepts only a single-link
regular file below `evidence/`, bounded strict JSON, a non-revoked key valid at sanitization time,
and exact predecessor bindings. Caller-supplied keys, wildcard matching, duplicate rules, raw
provider responses, credential material, and authority-marker coercion fail closed.

This signature establishes provenance from the configured deployment and prevents source swapping.
It does not independently verify that provider-specific policy translation is complete or that the
projected result equals provider-effective permission.

## Deterministic evaluation and comparison

The only registered evaluator performs exact tuple matching and uses this fixed order:

1. any matching `deny` yields `explicit-deny`;
2. otherwise any matching `allow` yields `allow`; and
3. otherwise the result is `implicit-deny`.

No wildcard, hierarchy, inheritance, condition language, provider default, resource expansion, or
network lookup is supported. The Replay output reports:

| State | Meaning |
| --- | --- |
| `policy-input-and-decision-match` | Exact rule sets and deterministic decisions match |
| `policy-input-changed-decision-match` | Exact rule sets differ but decisions match |
| `policy-decision-changed` | Deterministic decisions differ |

Every state remains neutral. It confirms neither provider policy semantics nor effective access,
resource existence, Ground Truth, negative-Control observation, a Profile floor, or a Finding. It
grants no Scope, Capability, approval, Permit, provider/Worker selection, network, credential,
mutation, Target Factory, Replay, or execution authority.

## Disposable fixture Ground Truth

`registered_cloud_policy_benchmark_fixture_profile` returns exactly three code-owned cases:

- an exact matching allow;
- an exact matching deny that overrides a matching allow; and
- an unrelated allow that produces the implicit-deny negative Control.

Each case records a private expected decision and requires
`disposable-account-or-emulator-per-case`, a
`fresh-single-use-ephemeral-lease-per-case`, and a
`destroyed-account-or-reset-emulator-receipt`. Tests run the code-owned evaluator over each case,
but no provider or emulator is contacted.

The profile binds the exact DOMAIN-006 Cloud plan and
`fresh-credential-deterministic-reevaluation` strategy. Its state is
`registered-fixture-ground-truth-not-provisioned-or-measured`. It selects no Target, activates no
factory, provisions no account or emulator, acquires no credential, performs no cleanup, executes
no fixture, binds no Replay evidence, publishes no `cloud.resource-policy-coverage`, establishes no
detection quality, and satisfies no validation floor.

## Required rejection behavior

The implementation fails closed for:

- inventory sources, missing or changed CLOUD-001C Graph admissions, or altered predecessor
  execution authority;
- Surface, Campaign Scope, release, activation, Capability, provider route, request, credential
  principal, evaluator, or query substitution;
- reused Run, preparation, request, Decision, Proposal, approval, Permit, dispatch, lease,
  statement, execution, source, admission, or artifact identity;
- artifact path traversal, non-regular/multi-link files, oversized or duplicate-key JSON, unknown,
  revoked, expired, non-canonical, or invalid signatures, and predecessor-binding drift;
- wildcard or duplicate rules, changed evaluator identity, deny-order changes, comparison or digest
  substitution, and fixture Ground Truth drift; and
- boolean coercion or attempts to enable provider confirmation, effective permission, measurement,
  Profile floor, Finding, Scope, approval, Permit, provider/Worker selection, network, credential,
  mutation, Target Factory, Replay, or execution authority.

## Compatibility and rollback

CLOUD-001D is additive and explicitly imported. It changes no CLOUD-001A/B/C, DOMAIN-006,
Campaign, Capability, ToolRequest, ActionPermit, approval, SecretBroker, Worker, Graph, Finding,
BENCH-001, or existing artifact wire. Rollback removes the module, tests, contract, and ADR-0227
while preserving sealed executions, signed files, and admitted Graph events.

## Remaining work

- No disposable Cloud account or emulator is provisioned.
- No provider-specific policy translator or effective-permission Oracle is implemented.
- No live Replay is scheduled; callers supply two already executed and admitted sources.
- No credential is acquired or reused by CLOUD-001D.
- No cleanup is performed or verified against a live Target.
- No resource/policy coverage, denial correctness, cleanup success, request cost, false-positive,
  recall, or validation-floor metric is emitted.
- Cloud writes, privilege changes, container execution, and general provider discovery remain later
  separately authorized slices.
