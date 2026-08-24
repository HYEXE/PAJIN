# NET-001D: Fresh Worker Replay and Isolated Service Fixtures

- Status: Implemented, bounded Replay comparison and unmeasured fixture Ground Truth
- Replay projection: `pajin.dev/network-service-replay-validation/v1alpha1`
- Fixture profile: `pajin.dev/network-service-benchmark-fixture-profile/v1alpha1`
- Authority: `src/pajin/workflow/network_replay_benchmark.py`
- Decision: [ADR-0223](../adr/0223-bind-network-replay-and-fixtures-without-service-authority.md)
- Predecessors: [NET-001C](../graph/NET-001C-sealed-network-protocol-knowledge-admission.md),
  [NET-001B](../capability/NET-001B-passive-service-identification-capability.md), and
  [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

NET-001D closes two distinct first-slice requirements without creating a Network scheduler,
scanner, Target Factory, or measurement engine:

1. compare one NET-001C source with one separately authorized and sealed passive TCP execution;
   and
2. register the isolated synthetic service cases and negative Control required by a future
   service-identification benchmark.

The two artifacts are intentionally independent. A live label comparison is not a Ground Truth
case, and a registered fixture is not evidence that a Target was provisioned or measured.

## Fresh Worker execution Replay

`bind_network_service_fresh_worker_replay` reopens both sealed Runs through the NET-001C source
loader. For each execution it revalidates current NET-001B activation and Campaign Scope, the
approved Capability Graph job, exactly one consumed ActionPermit and durable approval-consumption
receipt, the sealed request reservation and Tool/Worker Evidence, completed dispatch
reconciliation, Docker Worker result, exact one-request CONNECT egress metadata, and one matching
host-observed CONNECT receipt. It also requires the NET-001C Observation and optional Hypothesis
events to remain stored exactly for the source admission.

Source and Replay must preserve the same:

- typed IP-literal TCP `network-port` Surface;
- signed release, activation set, Capability, Tool, target, method, arguments, and normalized
  parameters;
- Campaign Scope and exact CONNECT allow rule; and
- one-connection, zero-target-write, 1,024-byte passive-banner budget.

They must use different Run and root, request and digest, mission envelope, Graph Decision,
ActionProposal, approval receipt, ActionPermit, dispatch, Worker execution, reservation,
execution Evidence, terminal event, and reconciliation identities. Reusing the source inputs as
Replay fails closed.

The phrase “fresh Worker” is deliberately bounded to a distinct sealed Docker Worker execution
identity behind the existing deployment trust boundary. The artifact does not prove that the two
executions used different physical hosts, container instances, certificates, or live mTLS
subjects.

## Neutral comparison

The projection publishes one of three states:

| State | Meaning |
| --- | --- |
| `protocol-label-match` | Both executions produced the same non-null bounded label |
| `protocol-label-changed` | The labels differ or only one execution produced a label |
| `protocol-label-unresolved` | Neither execution produced a bounded label |

Banner-digest equality is a separate boolean. A label match does not require byte-identical
banners, and a banner change does not by itself mean the protocol changed. Unknown is not a
negative conclusion. All three states keep service Observation confirmation, Ground Truth case
binding, negative-Control observation, benchmark measurement, Profile-floor satisfaction, and
Finding authority false.

The builder performs no dispatch. The Replay inputs must already have their own Policy, approval,
Permit, Gateway, Worker, network, and evidence lineage. The output cannot authorize another
Replay or reuse either consumed Permit.

## Isolated fixture Ground Truth

`registered_network_service_benchmark_fixture_profile` returns six exact synthetic banner cases:

- known-positive `ftp`, `imap`, `pop3`, `smtp`, and `ssh` cases; and
- one unknown-banner `negative-control` case whose expected label is absent.

Each case contains canonical non-secret banner bytes, their SHA-256 identity, the fixed
`tcp-passive-banner-v1` profile, an expected bounded label or no label, zero target application
writes, and a `disposable-loopback-container-per-case` isolation requirement. Tests compare all
six cases with the current standalone Worker classifier so classifier drift is detected.

The profile binds the exact DOMAIN-006 Network plan and
`fresh-worker-protocol-replay` strategy. Its state is
`registered-fixture-ground-truth-not-measured`. It does not select a Target profile, activate a
Target Factory, authorize a provider or fixture, provision a container, open a socket, bind live
Replay evidence, publish `network.service-identification-accuracy`, establish quality, or satisfy
a validation floor.

## Required rejection behavior

The implementation fails closed for:

- altered, foreign, unsealed, unsuccessful, or mismatched source or Replay Runs;
- missing or changed source Graph events;
- Surface, Campaign Scope, release, activation, Capability, Tool, target, method, argument,
  parameter, or protocol-budget substitution;
- reused Run, request, envelope, Decision, Proposal, receipt, Permit, dispatch, Worker execution,
  artifact, terminal, or reconciliation identity;
- label-comparison, banner-match, Domain plan, strategy, fixture, expected label, isolation, or
  digest substitution; and
- boolean coercion or attempts to enable confirmation, Ground Truth binding, negative-Control
  observation, measurement, Profile floor, Finding, Scope, approval, Permit, Tool/Worker
  selection, network, credential, Replay, or execution authority.

## Compatibility and rollback

NET-001D is additive and explicitly imported. It changes no NET-001A/B/C, DOMAIN-006, Campaign,
Capability, ToolRequest, ActionPermit, approval, Gateway, Worker, Run, Graph, Replay, Finding,
BENCH-001, or existing artifact wire. Rollback removes the module, tests, contract, and ADR-0223
while preserving every sealed Run and admitted Graph event.

## Remaining work

- No isolated service container or Target Factory is provisioned by this profile.
- No live Replay is automatically scheduled; callers supply two already sealed executions.
- No protocol label confirms a service, product, version, vulnerability, or Finding.
- No numeric accuracy, recall, false-positive, denial-correctness, request-cost, or validation-floor
  result is emitted.
- DNS resolution, UDP, port enumeration, active application writes, credentials, raw sockets,
  general scanning, and arbitrary Network runtime remain outside NET-001D.
