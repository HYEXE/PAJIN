# SYS-001D: System Replay and Disposable Host Fixtures

- Status: Implemented
- Version: `v1alpha1`
- Domain: System
- Decision: [ADR-0231](../adr/0231-bind-system-replay-and-fixtures-without-host-authority.md)
- Predecessors: [SYS-001A](../discovery/SYS-001A-host-process-filesystem-service-configuration-surface-model.md),
  [SYS-001B](../capability/SYS-001B-read-only-inspection-capability.md), and
  [SYS-001C](../graph/SYS-001C-sealed-system-host-knowledge-admission.md)

## Purpose

SYS-001D reopens one stored SYS-001C admission and one separately authorized sealed System
inspection. It distinguishes same-immutable-snapshot re-analysis from a fresh authenticated host
inspection and returns only a neutral result comparison. It also registers future disposable-host
Ground Truth requirements without provisioning, executing, cleaning up, or measuring a host.

The implementation is a verification and projection boundary. It is not a System runtime, Replay
scheduler, Target Factory, benchmark Harness, or Finding validator.

## Signed SYS-001C input provenance

`SystemInspectionResultReceipt` now requires `sourceKind`:

- `immutable-host-snapshot` requires exactly one lowercase SHA-256
  `immutableSnapshotSha256`; and
- `live-authenticated-host` requires `immutableSnapshotSha256` to be absent.

The receipt remains raw-result-free. Its digest, including source provenance, is bound into the
deployment-signed SYS-001C execution statement. An unsigned caller label, equal output digest, file
name, or timestamp cannot select the Replay mode.

## Replay inputs

The gate receives:

1. exact SYS-001C source inputs;
2. the corresponding stored `SystemInspectionKnowledgeAdmission`;
3. exact sealed replay inputs;
4. source and replay SQLite Graph authority stores; and
5. the deployment-configured System execution trust anchor.

Both executions are reopened with `load_verified_system_inspection_observation_source`. This
rechecks current activation and Campaign Scope, exact SYS-001B preparation, the approved job,
exactly one consumed ActionPermit and durable approval receipt, Ed25519 execution signature,
recomputed Gateway policy result, Worker direct-mTLS admission, declared non-root runtime,
detached receipt, timing, and request/artifact/runtime budgets.

Only the source must already be admitted. Its Observation and optional Hypothesis events must exist
exactly in the supplied source store. The replay execution remains sealed evidence and is not
automatically admitted to the Graph.

## Equivalent semantics and separate authority

Source and replay must have the same:

- code-backed Capability and signed release;
- exact SYS-001A Surface and metadata-only operation;
- host-agent deployment and deployment trust anchor;
- Campaign Scope and matched exact Surface allow rule;
- request budget and normalized parameters; and
- request fields other than the intentionally fresh request ID.

The signed result byte count is independent comparison provenance. Different result digests may
carry different byte counts, but equal result-body digests with unequal signed `resultBytes` are
internally inconsistent and fail closed.

The following identity coordinates must all differ:

- Run and source-root digest;
- request and request digest;
- MissionEnvelope, proposal, Graph Decision, ActionPermit, and dispatch;
- approval-consumption receipt;
- execution ID and signed statement digest;
- attestation artifact digest; and
- result-receipt ID, receipt digest, and artifact digest.

The replay statement's signed `startedAt` must also be strictly later than the source statement's
signed `finishedAt`. Distinct identifiers alone cannot turn an older sealed execution into Replay.
This causal ordering does not prove a different physical Worker or host instance.

Stable deployment identity, Worker mTLS subject/SPKI, runtime identity digest, confinement digest,
Capability, Surface, and normalized semantics may remain equal; they identify the comparison
boundary rather than a fresh authority coordinate.

## Replay modes

### Immutable snapshot re-analysis

Both receipts must declare `immutable-host-snapshot` and the same non-null snapshot SHA-256. This
mode satisfies the exact DOMAIN-006 System `immutable-snapshot-reanalysis` strategy. The repository
does not open or interpret the snapshot.

### Fresh authenticated inspection

Both receipts must declare `live-authenticated-host`, omit a snapshot digest, and carry disjoint
authorization and execution identities in strict signed causal order. This is a conservative
comparison path. It does not satisfy the DOMAIN-006 immutable-snapshot strategy and does not
authorize another live inspection or establish physical Worker freshness.

Mixed source kinds and different immutable snapshot identities fail closed.

## Neutral comparison

`SystemInspectionReplayComparison` has three values:

- `inspection-result-match`: result-body digest, signed result byte count, and bounded review signal
  are all equal;
- `inspection-result-changed`: a bounded review signal differs or a signaled result digest differs;
  and
- `inspection-result-unresolved`: both executions lack a bounded review signal while their opaque
  result digests differ.

The projection also records exact body-digest, signed byte-count, and review-signal equality
booleans. Equal body digest with unequal byte count is rejected rather than classified as changed or
unresolved. None of these states confirms host existence, running process state, filesystem content,
service state, configuration correctness, vulnerability, or Finding. A `changed` value is not a
security regression and an `unresolved` value is not a negative Control result.

## Disposable-host fixture profile

`SystemInspectionBenchmarkFixtureProfile` is content addressed and pins the DOMAIN-006 System plan,
all five SYS-001A Surface classes, and five sorted private Ground Truth requirements:

| Fixture | Surface | Class | Expected outcome |
| --- | --- | --- | --- |
| configuration drift | configuration | known-positive | fixed configuration metadata drift review signal |
| filesystem privilege denial | filesystem | privilege-denial Control | privilege-denied receipt |
| host baseline | host | negative Control | no review signal |
| process baseline | process | negative Control | no review signal |
| service status | service | known-positive | fixed service-status review signal |

Every case requires a disposable non-root container or VM, zero host mutation, no embedded raw host
value, and four evidence roles:

- deployment execution attestation;
- non-root runtime receipt;
- result receipt or privilege-denial receipt; and
- cleanup receipt.

The profile records coverage, negative-Control, privilege-denial, and evidence-completeness
requirements only. It has no selected Target profile or Target Factory authority, no provisioned
agent, no observed cleanup, no Replay evidence, no numeric metric, and no Profile-floor evidence.
The public profile therefore records `privateGroundTruthRequirementsRegistered=true` while keeping
`privateGroundTruthVerified=false`.

## Non-authority boundary

Replay validation and fixture registration keep the following false:

- host/process/filesystem/service/configuration state confirmation;
- Ground Truth or negative-Control observation;
- privilege-denial or evidence-completeness measurement;
- configuration-control coverage and detection quality;
- Profile validation floor and Finding authority;
- Scope expansion and Capability activation;
- approval and Permit issuance;
- agent and Worker selection;
- network and credential access;
- root and privilege escalation;
- service control and host mutation; and
- Replay scheduling and execution authority.

The implementation imports no socket, HTTP client, subprocess, shell, provider, Docker, VM, or host
inspection API.

## Audit and storage

The returned validation is a deterministic content-addressed projection. SYS-001D writes no Graph
node, edge, event, snapshot, approval, Permit, artifact, benchmark result, or host journal.

Bare `SystemInspectionReplayValidation.model_validate` is structural, content-addressed parsing
only and is not a trusted verification entry point. Trusted wire reload must use
`load_verified_system_inspection_replay_validation` with the deployment-configured trust anchor,
both original SYS-001C evidence roots and inputs, and both exact Graph stores. The loader reopens
both SYS-001C sources with the current verifier, confirms the stored source admission, rebuilds the
expected SYS-001D projection, and requires exact canonical model equality. An embedded trust
anchor, attestation SHA-256, Graph event, or recomputed public projection ID cannot replace that
context. The wire projection makes this explicit with
`deploymentContextReverificationRequired=true` and `selfAuthenticatingProjection=false`.

## Failure handling

The gate and contextful wire loader fail closed for invalid or substituted trust anchors,
signatures, source admissions, Campaign Scope, preparations, Surface or operation semantics,
result receipts, inconsistent signed result byte counts, source kinds, snapshot identities,
authority coordinates, comparison fields, fixture cases, Domain plans, boolean/integer marker
types, or any mismatch between a serialized projection and the current evidence and Graph context.

## Compatibility and rollback

SYS-001D is additive. The required SYS-001C source-provenance fields are incorporated while the
SYS-001A~C `v1alpha1` slice is still an uncommitted checkpoint, so no published reader migration is
required. Committed Web, AI, Network, Cloud, Campaign, Graph, Capability, and benchmark wire
identities do not change.

Rollback removes the SYS-001D workflow module, tests, this contract, ADR-0231, and the
pre-publication source-provenance fields. SYS-001D has no external side effect to clean up.

## Verification

Tests cover same-snapshot match, fresh-inspection unresolved/change, source admission storage,
separate authorization, authority reuse, mixed/different source provenance, result-source binding,
non-causal execution rejection, Domain strategy distinction, exact five-case fixture coverage,
privilege-denial/evidence roles, registered-but-unverified private Ground Truth, authority
escalation, signed result-byte-count drift, coercion, digest drift, structural wire round trip, and
contextful wire reload. The adversarial reload cases substitute the Graph admission and deployment
trust anchor.
