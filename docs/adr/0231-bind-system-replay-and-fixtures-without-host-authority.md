# ADR-0231: Bind System Replay and Fixtures without Host Authority

- Status: Accepted
- Date: 2026-08-25
- Owners: PAJIN architecture and security boundary maintainers
- Scope: SYS-001D

## Context

SYS-001C can reverify one already completed, approved, non-root System inspection and admit only
neutral Graph knowledge. Its result body remains outside the repository; only a digest, byte count,
fixed optional review signal, and detached signed provenance are available.

SYS-001D must compare that admitted source with a separately authorized execution and register
future disposable-host benchmark requirements. It must distinguish deterministic re-analysis of the
same immutable snapshot from a fresh authenticated host inspection. Inferring that distinction from
equal result digests, request names, execution ordering, or Graph knowledge would invent
provenance. Signed execution timestamps can establish ordering, but cannot identify snapshot or
live input provenance. A fresh inspection also cannot be treated as satisfying the DOMAIN-006
System strategy, which is explicitly `immutable-snapshot-reanalysis`.

## Decision

Add a signed, raw-value-free `sourceKind` to the SYS-001C result receipt. An
`immutable-host-snapshot` receipt must include one lowercase SHA-256 snapshot identity, while a
`live-authenticated-host` receipt must not include one. Because the result receipt digest is bound by
the deployment-signed execution statement, SYS-001D can distinguish these inputs without opening
the snapshot or host.

Add a SYS-001D Replay gate that:

1. reopens the exact stored SYS-001C source admission and independently reloads both sealed source
   executions through the current SYS-001C verifier and deployment trust anchor;
2. requires equal Capability release, exact Surface and operation, host-agent deployment, Campaign
   Scope, bounded request semantics, and trust anchor;
3. rejects reuse of any Run, source-root, request, envelope, proposal, Decision, Permit, dispatch,
   approval-consumption, execution, statement, attestation, or result-receipt identity coordinate,
   and requires the replay statement's signed start to be strictly later than the source
   statement's signed finish;
4. classifies two equal non-null snapshot identities as `immutable-snapshot-reanalysis` and two live
   inputs as `fresh-authenticated-inspection`, rejecting mixed kinds or different snapshots;
5. marks the DOMAIN-006 validation strategy satisfied only for same-snapshot re-analysis;
6. emits only `inspection-result-match`, `inspection-result-changed`, or
   `inspection-result-unresolved`, plus exact digest/byte-count/signal equality booleans; and
7. performs no Graph write, Tool call, host-agent invocation, Worker selection, network operation,
   credential use, or Replay scheduling.

An exact body-digest, signed byte-count, and review-signal match is `match`. Equal body digests
with different signed byte counts fail closed. A differing bounded review signal is `changed`. If
both executions have no bounded signal and their opaque result digests differ, the comparison is
`unresolved`; SYS-001D does not interpret raw host metadata to manufacture a change claim.

Register a content-addressed five-case benchmark fixture profile covering every SYS-001A Surface
class. It contains configuration and service known-positive review signals, host and process
negative Controls, and a filesystem privilege-denial Control. Every case requires a disposable
non-root container or VM and complete execution, non-root, result-or-denial, and cleanup evidence.
The profile provisions, executes, cleans up, and measures nothing.

## Consequences

- Immutable snapshot identity is explicit signed provenance instead of a digest-equality inference.
- A disjoint but older execution cannot be relabeled as Replay; signed execution windows establish
  the minimum causal order without claiming physical Worker freshness.
- Fresh authenticated inspections can be compared conservatively but do not satisfy the registered
  immutable-snapshot benchmark strategy.
- A result digest difference without a bounded signal remains unresolved rather than becoming a
  host-state or security conclusion.
- The fixture catalog records coverage, negative-Control, privilege-denial, and evidence-completeness
  requirements without claiming observed outcomes or metrics.
- The validation and fixture profile create no Finding, Profile-floor, root, mutation, or future
  execution authority.

## Alternatives considered

### Infer snapshot or live provenance from result digests

Rejected because equal output digests do not identify the input source, and unequal digests do not
prove a host-state change.

### Accept a caller-supplied unsigned replay mode

Rejected because a caller label would not be deployment-attested execution provenance.

### Treat every second inspection as the DOMAIN-006 Replay

Rejected because a fresh live inspection is not deterministic re-analysis of the same immutable
snapshot.

### Provision and execute disposable hosts in SYS-001D

Rejected because the repository has no authenticated System host-agent runtime or governed System
Target Factory. Registration must precede execution and measurement.

## Security and authority impact

SYS-001D consumes only prior signed and stored provenance. Source admission, trust anchors, result
digests, fixture identities, and comparison states remain knowledge. They do not grant Scope,
Capability activation, approval, Permit issuance, agent or Worker selection, network or credential
access, root, privilege escalation, service control, host mutation, Replay, Finding, or execution
authority.

The fixture profile contains no raw path, configuration value, secret, credential, host identity, or
private key. Its private Ground Truth is a closed expected-outcome vocabulary, not live host data.

## Compatibility and rollback

SYS-001A through SYS-001C are still uncommitted `v1alpha1` work in this checkpoint. The required
receipt provenance field is therefore incorporated before publication rather than introduced as a
post-release wire migration. Existing committed Network, Cloud, AI, Graph, Campaign, Capability,
and benchmark identities do not change.

Rollback removes the SYS-001D module, tests, contract, this ADR, and the pre-publication SYS-001C
source-provenance fields. No admitted Graph event is created by SYS-001D and no host or fixture
cleanup is required.

## Verification

Positive and adversarial tests cover same-snapshot match, fresh-inspection unresolved/change,
separate authority, source-kind/snapshot binding, mixed or different snapshot rejection, authority
reuse, non-causal execution rejection, marker coercion, exact fixture registration, Ground Truth
substitution, and serialization.

## Related contracts

- [SYS-001C](../graph/SYS-001C-sealed-system-host-knowledge-admission.md)
- [SYS-001D](../benchmark/SYS-001D-system-replay-disposable-host-fixtures.md)
- [ADR-0230](0230-admit-system-host-knowledge-without-host-access-authority.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
