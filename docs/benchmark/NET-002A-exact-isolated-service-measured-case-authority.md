# NET-002A: Exact Isolated-Service Measured-Case Authority

Status: Implemented additive registration boundary

## Purpose

NET-002A registers the one Network measured case that later Phase 24 boundaries may materialize and
measure. It composes the unchanged NET-001D fixture membership, the NET-001B passive TCP contract,
and the exact DOMAIN-006 Network plan into new Network-specific, content-addressed artifacts. It
does not build an image, create a Target or network, choose a provider, dispatch a Worker, or admit a
measurement.

The implementation is `pajin.workflow.network_measured_case_authority`. It is additive and does not
change the existing NET-001A through NET-001D, DOMAIN-006, generic benchmark Ground Truth, or
`WalkingBenchmarkRunObservation` wires.

## Exact membership and ordering

The canonical order is inherited from NET-001D and is used identically for source measurement and
independent Replay:

| Ordinal | Case ID | Ground Truth class | Deployment-private expected outcome |
| --- | --- | --- | --- |
| 1 | `network-fixture:ftp-known-positive` | `known-positive` | exact `ftp` label |
| 2 | `network-fixture:imap-known-positive` | `known-positive` | exact `imap` label |
| 3 | `network-fixture:pop3-known-positive` | `known-positive` | exact `pop3` label |
| 4 | `network-fixture:smtp-known-positive` | `known-positive` | exact `smtp` label |
| 5 | `network-fixture:ssh-known-positive` | `known-positive` | exact `ssh` label |
| 6 | `network-fixture:unknown-negative-control` | `negative-control` | unresolved, with no service label |

The unknown case is a negative Control denominator. An unresolved result is its expected classifier
outcome; it is not an observed negative service, service confirmation, Finding, or permission to
scan another endpoint.

## Public and private authority split

`NetworkMeasuredCaseRegistry` is the versioned public registration. Each entry contains only its
case ID, Ground Truth class, passive-banner protocol profile, measurement role, public case digest,
and a content-addressed commitment to the corresponding private case. The registry does not contain
banner bytes, banner SHA-256 fields, `expectedServiceName`, or the private classifier-outcome field.

`NetworkPrivateGroundTruthBinding` is a separate deployment-private artifact. It reopens the current
code-owned NET-001D fixture profile and binds each full fixture case, banner, expected label, and
classifier outcome to the exact public registry. The public authority carries only this binding's
digest. A digest is an integrity coordinate, not a redaction mechanism; deployment code must still
keep the private binding off public product and report wires.

The public and private artifacts are returned as separate objects by
`registered_network_measured_case_mapping()`. `load_network_measured_case_authority()` requires both
objects, reparses their strict wires, rebuilds all code-owned registrations, and rejects any
membership, order, private data, profile, or digest substitution.

## Fixed-case emitter and image identities

`NetworkTCPBannerEmitterProfile` registers one code-owned case-ID-only contract:

- accepted configuration is one of the six exact case IDs;
- the fixed internal container port is `18080`;
- the Target sends the case-owned banner immediately after accept and then closes;
- the Target reads zero application payload bytes;
- the Worker sends zero application-protocol bytes; and
- caller-provided banners, commands, ports, and images are not accepted.

NET-002A registers immutable content-addressed image contracts in canonical Target, Worker, proxy
order. The Target identity binds the fixed emitter profile, the Worker identity binds the exact
NET-001B passive service-identification binding, and the proxy identity binds one exact IP-literal
TCP CONNECT bridge contract. These are image-contract identities, not fabricated OCI image IDs.
Every role states that an immutable observed image ID is required later, while `dockerImageBuilt`,
`observedImageIdBound`, caller image selection, and runtime use remain false. NET-002B must build or
resolve the images and bind their independently inspected immutable OCI identities before runtime
admission.

## Measurement protocol

`NetworkMeasurementProtocol` binds:

- the exact six-case public registry and private-binding digest;
- the emitter and Target/Worker/proxy image-identity profiles;
- the exact NET-001B `tcp-passive-banner-v1` budget: one TCP connection, zero application writes,
  1024 maximum banner bytes, 5000 ms connect timeout, and 2000 ms read timeout;
- the exact DOMAIN-006 Network `fresh-worker-protocol-replay` plan; and
- six source plus six Replay case requirements in the same canonical order.

Every case requires a fresh disposable Target and fresh Worker execution. Source and Replay runtime
authority identities must be disjoint, the Worker must remain proxy-only, and the Target must have
no published host port. These are future admission requirements, not evidence that any lifecycle or
execution has occurred.

## Validation-floor policy

`NetworkValidationFloorPolicy` preserves all 14 exact DOMAIN-006 Network requirements. Eleven are
required and three retain their registered not-applicable meaning:

- `common.task-success-rate`: `detection-recall-is-primary-outcome`;
- `common.total-cost-usd`: `no-monetary-cost-model`; and
- `common.cleanup-success-rate`: `read-only-no-cleanup-required`.

The cleanup N/A value does not waive Target cleanup. Target reconciliation and zero residue remain
mandatory admission evidence rather than a fabricated numeric Network action metric.

The registered ratio floors require full Ground Truth coverage, known-positive recall, precision,
Replay success, evidence completeness, policy-denial correctness, and
`network.service-identification-accuracy`; false-positive rate must be zero. Exact minimum
denominators are six registered/evaluated cases, five known-positive cases, one negative Control,
six independent Replay cases, and five future pre-dispatch denial Controls for Scope, case, route,
image, and authority substitution. Time-to-first-valid-result, request units, and Tool calls require
measurement but have no fabricated value in NET-002A. The policy is registered but not evaluated or
satisfied.

## Authority ceiling

All NET-002A runtime and projection authority remains false, including:

- Docker image build and observed image binding;
- Target selection or creation, network creation, and provider selection;
- Capability activation, approval, ActionPermit issuance, Gateway execution, and Worker execution;
- live measurement, metric evaluation, and validation-floor satisfaction;
- product projection, Graph mutation, Finding authority, reporting, and external delivery;
- DNS, UDP, port ranges, port enumeration, raw sockets, and active application-protocol writes;
- credential access and external or production targets;
- service confirmation, general scanning, caller-selected configuration, and execution.

Ground Truth, a DOMAIN-006 plan, an image-contract digest, or a future passing metric never grants
execution authority.

## Verification

`tests/test_network_measured_case_authority.py` verifies exact membership and order, NET-001D
binding, public/private leakage boundaries, unknown-Control semantics, case and expected-label
substitution, digest drift, strict extra-field and boolean rejection, fixed emitter configuration,
foreign image/profile rejection, exact source/Replay ordering, DOMAIN-006 applicability and floor
denominators, and every false authority marker.

## Related contracts and decisions

- [NET-001B passive service-identification Capability](../capability/NET-001B-passive-service-identification-capability.md)
- [NET-001D fresh Worker Replay and isolated fixtures](NET-001D-fresh-worker-replay-isolated-service-fixtures.md)
- [DOMAIN-006 domain-aware benchmark registry](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0258 Phase 24 selection](../adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)
