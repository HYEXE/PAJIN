# ADR-0223: Bind Network Replay and Fixtures without Service Authority

## Status

Accepted

## Context

NET-001C admits a neutral protocol Observation and, for one bounded Worker label, an open
Hypothesis that explicitly requires a separately authorized fresh passive handshake. The source
ActionPermit is already consumed and cannot authorize that handshake. A repeated label is useful
validation evidence, but banner prefixes can change, remain unrecognized, or be misleading; a
match cannot by itself confirm a service or Finding.

DOMAIN-006 already registers `fresh-worker-protocol-replay` and
`network.service-identification-accuracy`, but the registry deliberately contains neither Replay
evidence nor Network Ground Truth. BENCH-001 Ground Truth is Finding-oriented and would misstate a
service-classification fixture as a vulnerability. Network therefore needs a bounded fixture
vocabulary without inventing a measured benchmark result or Target Factory activation.

## Decision

Add two separate content-addressed NET-001D artifacts.

The Replay validation reopens the exact NET-001C source/admission and a second already approved,
executed, and sealed NET-001B passive TCP Run. Both Runs must independently satisfy the existing
current activation, Campaign Scope, approval receipt, consumed ActionPermit, completed dispatch,
Docker Worker, exact egress metadata, and host-observed CONNECT receipt checks. The source Graph
events must still exist exactly in the supplied Graph store.

Require identical Surface, Capability, release, activation-set, Campaign Scope, passive protocol
budget, Tool target, method, arguments, and normalized parameters. Require distinct Run root,
request, envelope, Graph Decision, ActionProposal, approval receipt, ActionPermit, dispatch,
Worker execution, reservation, Evidence, terminal event, and reconciliation identities. In this
contract, “fresh Worker” means a separately sealed Docker Worker execution identity behind the
existing deployment boundary. It does not claim a different physical host, image instance,
certificate, or live mTLS re-authentication.

Compare only the bounded protocol label and banner digest. Publish `protocol-label-match`,
`protocol-label-changed`, or `protocol-label-unresolved`; the last state requires both labels to
be absent. Keep banner-digest equality separate because a stable protocol can emit different
banners. Every state remains neutral and cannot confirm the NET-001C Observation, mutate a
Surface, satisfy a Profile floor, create a Finding, or authorize another action.

Separately register six synthetic passive-banner Ground Truth cases: one known positive for each
of `ftp`, `imap`, `pop3`, `smtp`, and `ssh`, plus one unknown-banner negative Control. Each case
binds canonical banner bytes, a digest, expected bounded label, zero target application writes,
and a disposable loopback-container-per-case isolation requirement. The profile is
`registered-fixture-ground-truth-not-measured`: it selects no Target, activates no factory or
provider, executes no fixture, binds no Replay evidence, and records no numeric metric.

## Consequences

- NET-001C's open Hypothesis can be paired with evidence from a genuinely separate authorization
  and execution lineage without redispatching from Graph knowledge.
- Label matches, changes, and unknown results are represented without turning classifier output
  into service truth.
- The five-label denominator and one negative Control are explicit, deterministic, and tested
  against the current Worker classifier while remaining separate from live Replay evidence.
- A future measurement adapter must provision isolated fixtures, execute fresh authorized Runs,
  bind raw observations to cases, and aggregate DOMAIN-006 metrics before claiming accuracy or a
  validation floor.
- Source and Replay stores are explicit inputs. Their records are treated as authority by the
  existing loaders, not combined into a new Network authority store.

## Rejected alternatives

### Reuse the NET-001C source Permit

Rejected because ActionPermits are consumed-on-issuance non-bearer proofs. Reuse would erase the
separate authorization and execution boundary required by the Hypothesis.

### Confirm the service when labels match

Rejected because two bounded prefix classifications are Replay evidence, not Ground Truth about
the endpoint's service, product, version, vulnerability, or persistence.

### Treat two unknown labels as a negative Control

Rejected because an unrecognized banner does not prove service absence. The Replay state remains
`protocol-label-unresolved`; only the code-owned synthetic unknown fixture is registered as a
benchmark negative Control.

### Emit service-identification accuracy directly

Rejected because live Replay and registered synthetic Ground Truth are separate artifacts. No
isolated fixture was provisioned or measured by the NET-001D binding.

### Claim a fresh physical Worker or certificate

Rejected because sealed execution evidence exposes a distinct Worker execution ID, not a durable
physical-container or live mTLS identity suitable for cross-Run comparison.

## Compatibility and rollback

The change is additive. Existing NET-001A/B/C, DOMAIN-006, Campaign, Capability, approval, Permit,
Gateway, Worker, Run, Graph, Replay, Finding, BENCH-001, and artifact-reader identities remain
unchanged. Rollback stops producing the two NET-001D artifacts and removes their module, tests,
contract, and this ADR; sealed Runs and admitted Graph events require no migration.

## Related documents

- [NET-001D contract](../benchmark/NET-001D-fresh-worker-replay-isolated-service-fixtures.md)
- [NET-001C contract](../graph/NET-001C-sealed-network-protocol-knowledge-admission.md)
- [NET-001B contract](../capability/NET-001B-passive-service-identification-capability.md)
- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0222](0222-admit-network-protocol-knowledge-without-service-authority.md)
- [ADR-0211](0211-register-domain-metrics-without-measurement-authority.md)
