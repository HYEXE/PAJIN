# NET-002C: Independent Fresh-Worker Network Floor Evaluation

- Status: implementation and deterministic in-process conformance complete; real-Docker
  conformance not yet established
- Public evaluation API: `pajin.dev/network-replay-floor-evaluation/v1alpha1`
- Public case API: `pajin.dev/network-replay-case-evaluation/v1alpha1`
- Private binding API: `pajin.dev/network-private-replay-evaluation-binding/v1alpha1`
- Implementation: `src/pajin/workflow/network_replay_evaluation.py`
- Decision:
  [ADR-0258](../adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)

## Purpose and fixed scope

NET-002C evaluates the exact NET-002A six-case Network validation floor from one completed
NET-002B source set and one independently executed NET-002B Replay set. It does not generalize the
fixture catalog or reinterpret an existing Finding-oriented benchmark wire. The canonical order
remains FTP, IMAP, POP3, SMTP, and SSH known-positive cases followed by the unknown negative
Control.

The runner first contextfully reopens the source authority, its separate private binding, all six
sealed NET-001B Runs, the immutable image binding, and zero-residue state. It then invokes the
unchanged NET-002B runner for a second six-case set through the deployment-owned authorizer and
Docker provider. Each Replay case therefore consumes its own normal Run, request, Decision,
approval, one-use ActionPermit, Gateway dispatch, Worker execution, disposable Target, proxy, and
cleanup lifecycle. NET-002C does not mint an alternative action wire or turn the source artifact
into execution authority.

## Independent execution identity

Every source and Replay case binds a private `NetworkReplayExecutionIdentity` covering the outer
measurement Run and binding, inner execution Run/root, request, envelope, Proposal, Decision,
approval and receipt, Permit, dispatch, Worker execution, budget reservation, execution Evidence,
terminal and reconciliation records, Target attempt/container/network, and Worker/proxy/internal
network identities.

The six source identities and six Replay identities must each be unique, and every dynamic source
identity value must be disjoint from every dynamic Replay value. Reusing a source outcome as
Replay, sharing one ephemeral identity across sets, changing the registered case order, or binding
a foreign image or deployment authorizer fails before a C floor can be sealed. The fixed immutable
Target, Worker, and proxy image identities are common contract inputs, not ephemeral execution
identities, and are independently reinspected on reopen.

## Private comparison and unknown Control

The deployment-private case evaluation contains the exact private Ground Truth case, full source
and Replay NET-002B measurements, and both execution identities. It requires equal case-owned raw
banners and banner digests, exact expected labels for the five known-positive cases, an unresolved
label for the unknown Control, successful Replay, complete cleanup, and disjoint identity sets.

The unknown case contributes one negative-Control denominator. Its required state is
`synthetic-negative-control-unresolved`; it is not an observed service, endpoint confirmation,
Finding, or permission to probe another port. Raw banners, expected or observed labels, Worker and
Tool results, runtime coordinates, and Docker identities remain deployment-private.

## Exact DOMAIN-006 evaluation

The public evaluation preserves the exact DOMAIN-006 Network metric order and applicability. Its
canonical observations are:

| Metric | NET-002C observation |
| --- | --- |
| `common.ground-truth-coverage` | `6/6` |
| `common.detection-recall` | `5/5` |
| `common.task-success-rate` | N/A: `detection-recall-is-primary-outcome` |
| `common.false-positive-rate` | `0/1` |
| `common.detection-precision` | `5/5` |
| `common.replay-or-reanalysis-success-rate` | `6/6` |
| `common.time-to-first-valid-result` | first Replay Worker duration in microseconds over `1,000,000` |
| `common.total-request-units` | `12/1` |
| `common.total-tool-calls` | `12/1` |
| `common.total-cost-usd` | N/A: `no-monetary-cost-model` |
| `common.evidence-completeness` | `144/144` |
| `common.policy-denial-correctness` | `5/5` |
| `common.cleanup-success-rate` | N/A: `read-only-no-cleanup-required` |
| `network.service-identification-accuracy` | `6/6` |

Evidence completeness is the twelve registered evidence categories across twelve executions. The
five denial categories remain the registered Scope, case, route, image, and authority
substitutions; they are not caller-selected benchmark cases. Cleanup remains DOMAIN-006 N/A because
the action is read-only, but successful zero-residue cleanup for all twelve Target/Worker/proxy
lifecycles is still mandatory admission evidence.

Every fixed rational, denominator, N/A reason, metric identity, unit, comparison, and order is
validated against the exact NET-002A floor policy. Passing the floor proves only this synthetic
fixed-case classifier benchmark at this artifact lineage.

## Public and private custody

`NetworkReplayFloorEvaluation` is the public-safe, content-addressed result. It contains only exact
NET-002A protocol/floor/image references, source and Replay authority references, six public case
references and comparison states, private commitments, the fourteen aggregate observations,
registered evidence-category names, and literal completion and false-authority markers.

`NetworkPrivateReplayEvaluationBinding` is sealed separately. The C loader reparses both wires,
contextfully reopens the source and Replay NET-002B authorities and every inner NET-001B Run,
recomputes public/private commitments, reinspects images, rechecks global identity disjointness,
and requires no managed Docker residue. A digest commitment is not authorization to disclose the
private artifact.

Public strict models reject unknown fields, nonliteral authority markers, noncanonical arrays,
order changes, membership substitution, rational drift, and digest drift. Private C models retain
the independently strict NET-002B wire parsers while recursively rejecting hidden instance state
and revalidating all C-owned comparison and identity commitments.

## Authority ceiling

The completed result grants no authority for:

- image build, provider selection, or caller-selected image or runtime configuration;
- another Target, network, approval, Permit, Gateway, Worker, source, or Replay execution;
- service confirmation, Graph admission or mutation, Finding authority, or product projection;
- reporting or external delivery;
- DNS, UDP, port ranges, port enumeration, raw sockets, or active application-protocol writes;
- credential access or external/production targets; or
- general Network scanning.

The runner's deployment-owned authorizer and Docker provider are prerequisites used to create the
second fixed set. Neither is selected, issued, or made reusable by the sealed evaluation.

## Verification status

`tests/test_network_replay_evaluation.py` covers the complete twelve-execution in-process path,
contextful source and Replay reopen, exact metrics and N/A reasons, global identity disjointness,
unknown-Control meaning, public/private leakage, false authority, case/metric/digest/identity
substitution, source reuse, foreign images and authorizers, hidden instance state, and exact mapping
types.

The test module also contains an opt-in real-Docker conformance path gated by
`PAJIN_NETWORK_002C_REAL_DOCKER=1`. This checkpoint did not run it because the maintainer host
cannot start the container runtime. In-process results are not Phase 24 exit evidence. NET-002D
must establish exact-commit Linux source/Replay conformance and unconditional zero residue before
the phase can complete.

## Compatibility and rollback

NET-002C is additive. It does not change NET-001A through NET-001D, NET-002A/B, DOMAIN-006, generic
benchmark Ground Truth, Walking observations, Graph/Finding, Gateway, Tool, Worker, or accepted ADR
wire identities. Rollback stops constructing the C runner and removes its Network-specific reader.
Previously sealed evaluations remain historical synthetic benchmark evidence and must not be
treated as product, service-confirmation, Finding, report, delivery, or execution authority.

## Related contracts

- [NET-002A measured-case authority](NET-002A-exact-isolated-service-measured-case-authority.md)
- [NET-002B disposable source measurement](NET-002B-registry-governed-disposable-network-source-measurement.md)
- [NET-001D fresh Worker Replay and fixtures](NET-001D-fresh-worker-replay-isolated-service-fixtures.md)
- [DOMAIN-006 domain-aware validation](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
