# NET-002B: Registry-Governed Disposable Network Source Measurement

- Status: implementation and deterministic in-process conformance complete; real-Docker
  conformance not yet established
- Public authority API: `pajin.dev/network-source-measurement-authority/v1alpha1`
- Public lineage API: `pajin.dev/network-source-case-lineage/v1alpha1`
- Public denial API: `pajin.dev/network-source-denial-receipt/v1alpha1`
- Private binding API: `pajin.dev/network-private-source-measurement-binding/v1alpha1`
- Image binding API: `pajin.dev/network-source-image-binding/v1alpha1`
- Implementation:
  `src/pajin/workflow/network_fixture_runtime.py`,
  `src/pajin/workflow/network_source_measurement.py`, and
  `containers/network-banner-emitter/`
- Decision:
  [ADR-0258](../adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)

## Purpose and exact membership

NET-002B is the source-measurement boundary for the exact NET-002A registration. It runs only these
six cases, in this order:

1. FTP known-positive;
2. IMAP known-positive;
3. POP3 known-positive;
4. SMTP known-positive;
5. SSH known-positive; and
6. unknown negative Control.

The runner contextfully reopens the NET-002A public authority and separate private Ground Truth
binding before it observes an image or starts a Target. The caller cannot add, remove, reorder, or
replace a case. The existing NET-001A through NET-001D contracts, the generic Finding-oriented
benchmark catalog, and Walking observations remain unchanged and are not reinterpreted as Network
metric authority.

## Fixed emitter and immutable images

`containers/network-banner-emitter/banner_emitter.py` accepts exactly one registered case ID. It
selects the corresponding code-owned banner, listens on fixed internal TCP port `18080`, sends the
banner immediately after one accepted connection, closes that connection, and never reads
application bytes. A caller cannot supply a banner, command, port, address, service label, or
protocol action.

The Target Dockerfile has a digest-pinned Python base, a fixed entrypoint, a non-root user, and no
health probe or caller-owned command. NET-002B does not build any image. Before execution it
independently inspects the deployment-provided fixed Target, Worker, and proxy image references and
binds their observed `sha256:` OCI image IDs to the exact NET-002A image contracts. Runtime uses the
observed Worker and proxy IDs while preserving the existing logical Worker job image in Gateway
metadata. Any changed, foreign, reordered, noncanonical, or caller-selected image binding fails
closed.

## Recoverable disposable Target lifecycle

Each case gets a fresh attempt, Target container, and internal Target network. The provider:

- reinspects all three image references before reset;
- creates the Target network with Docker's internal-network flag;
- starts the Target by immutable observed image ID and exact case ID;
- publishes no host port;
- requires read-only root, all capabilities dropped, `no-new-privileges`, bounded PID/memory/CPU
  limits, and user `65532:65532`;
- observes the exact IP-literal Target coordinate and fixed port; and
- removes the Target and network after the Worker/proxy execution has been independently observed
  as absent.

The SQLite operation journal writes intent before every provider call. A successful attempt has
exactly six canonical hash-chained records: reset intent/receipt, isolation intent/receipt, and
cleanup intent/receipt. Per-scope fences increase monotonically. An abandoned attempt is cleaned
under a higher recovery fence and is permanently measurement-ineligible; the source runner stops
after performing recovery and requires a fresh invocation.

Before cleanup, the provider requires exactly one `ready` log followed by exactly one
`banner-emitted` event with sequence one. The private lifecycle evidence therefore binds one banner
emission and zero Target application-read bytes. A missing, duplicate, reordered, foreign, or
additional emitter event fails closed.

## Existing approval, Permit, Gateway, and Worker path

The deployment authorizer receives the already inspected case and Target coordinate and must return
one fresh normal Network action plan. NET-002B does not mint an alternative action wire. Before
dispatch it reconstructs the existing NET-001B preparation and requires:

- one exact IP-literal TCP Surface and one exact host-wide CONNECT Scope rule;
- CONNECT as the only allowed method and explicit private-network authority;
- one fresh Run, request, Graph decision, ActionApproval, and one-use ActionPermit lineage;
- the exact deployment approval issuer and stable authorizer-context digest;
- the existing `network.service-identify` Capability, Gateway, and logical Worker image;
- an immutable observed Worker image ID;
- an immutable observed proxy image ID;
- one exact action-to-Target-network route; and
- the exact host-owned lifecycle observer instance.

The Worker remains attached only to its fresh internal proxy network. The proxy alone bridges that
network to the current Target network. The host observer records immutable Worker/proxy/Target
container and image IDs, exact internal and Target network IDs, zero published ports, and confirmed
absence of Worker, proxy, and internal-network resources before Target cleanup. The existing Tool
adapter accepts exactly one host-trusted CONNECT receipt and a successful passive banner result.
Each approval and Permit can dispatch at most once.

## Code-owned pre-dispatch denials

Before the first allowed case, the runner evaluates these five substitutions without invoking the
Gateway or Worker:

1. Campaign Scope substitution;
2. measured-case substitution;
3. Target-network route substitution;
4. immutable image substitution; and
5. deployment authority-context substitution.

The public authority records the fixed denial order, literal denial result, pre-dispatch stage, and
zero dispatch count. These probes are code-owned Controls, not caller-selected configuration and
not additional benchmark cases.

## Public and private custody

The public `NetworkSourceMeasurementAuthority` contains only:

- the NET-002A authority, protocol, private-binding commitment, and observed-image-binding
  references;
- six public case references in canonical order;
- sealed source Run/root, approval-receipt, Permit, execution-evidence, Target-lifecycle, and
  private-measurement digests; and
- the five public-safe denial receipts and literal verification/authority markers.

It contains no raw banner, banner hash, expected or observed service label, Worker result, Tool
result, Target IP/port, Docker container/network name, or private Ground Truth object.

The separate deployment-private binding contains the exact NET-002A Ground Truth cases, raw banner,
observed label or unresolved result, Worker and Tool results, trusted CONNECT count, zero
application-write count, complete Target/topology/journal/cleanup evidence, and all immutable image
bindings. The unknown Control must remain `protocol-label-unresolved`, have no service label, and
cannot be promoted to service confirmation.

The outer Run seals both artifacts, but public consumers receive only the public authority.
Contextful reload reparses both strict JSON wires, reopens all six sealed NET-001B source Runs,
recomputes each private measurement and public lineage, reinspects every image, revalidates exact
membership and unique ephemeral identities, and requires zero managed Target residue.

## Authority ceiling

NET-002B records a completed synthetic source measurement. It grants no authority for:

- image build or caller-selected image/configuration;
- another Target, network, approval, Permit, Gateway, Worker, or measurement execution;
- Replay, floor evaluation, floor satisfaction, or service confirmation;
- Graph admission or mutation, Finding authority, product projection, reporting, or delivery;
- DNS, UDP, port ranges, port enumeration, raw sockets, or active application-protocol writes;
- credential access or external/production targets; or
- general Network scanning.

The deployment-owned approval issuer and Docker provider remain prerequisites, not authorities
created or selected by the sealed result.

## Verification status

Deterministic tests cover:

- exact emitter membership, fixed port, one-case-ID input, one send, and no receive path;
- canonical image binding, independent reinspection, immutable runtime image substitution, and
  unchanged logical Worker metadata;
- internal no-published-port Target creation, six-record journal, recovery fence, one emission,
  cleanup, and topology rejection;
- exact six-case public/private order, unique disposable identities, unknown-Control semantics,
  public/private leakage, order substitution, digest drift, and foreign labels;
- all five pre-dispatch substitutions, caller-selected backend configuration, and one-use Permit
  reuse; and
- the complete six-case Approval to Permit to Gateway to trusted CONNECT to seal to contextful
  reopen path with an in-process host boundary.

`tests/test_network_source_measurement.py` also contains an opt-in real-Docker conformance test. It
requires the three fixed images to exist and
`PAJIN_NETWORK_002B_REAL_DOCKER=1`. This local checkpoint did not run that test because the
maintainer host cannot start the container runtime. In-process and fake-Docker results are not
Phase 24 exit evidence; exact-commit Linux real-Docker source and Replay conformance remains
NET-002D work.

## Compatibility and rollback

NET-002B is additive. It does not change any NET-001A through NET-001D, DOMAIN-006, generic
benchmark, Walking observation, accepted ADR, Graph, Finding, Tool request, Gateway result, or
Worker result wire. The optional logical-to-observed image map extends `DockerWorkerBackend`; its
default empty state preserves the prior execution context and behavior, and the WEB production
adapter explicitly requires that empty state.

Rollback stops constructing the NET-002B runner and removes the new Network-specific runtime and
authority readers. Previously sealed NET-002B artifacts remain historical source evidence and must
not be treated as Replay, floor, product, Finding, or service-confirmation authority.

## Related contracts

- [NET-002A exact isolated-service measured-case authority](NET-002A-exact-isolated-service-measured-case-authority.md)
- [NET-001B passive service identification](../capability/NET-001B-passive-service-identification-capability.md)
- [NET-001C sealed protocol knowledge admission](../graph/NET-001C-sealed-network-protocol-knowledge-admission.md)
- [NET-001D fresh Worker Replay and isolated fixtures](NET-001D-fresh-worker-replay-isolated-service-fixtures.md)
- [DOMAIN-006 domain-aware validation](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
