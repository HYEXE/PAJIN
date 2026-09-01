# ADR-0258: Select Governed Measured Network Service Identification after Phase 23

- Status: Accepted
- Date: 2026-09-01
- Owners: PAJIN architecture and security boundary maintainers
- Scope: Post-Phase 23 checkpoint review and Phase 24 roadmap selection

## Context

Phase 23 completed the first read-only Operator product flow over an exact measured and independently
validated Web case. ADR-0250 retained Network as the preferred next new-domain runtime candidate,
subject to a fresh review after the Web milestone. ADR-0257 preserved that ordering while making
clear that UX-009 did not count as Network runtime progress.

The fresh review confirms that the existing Network slice has the strongest remaining executable
predecessor chain:

- NET-001A provides exact IP-literal TCP host/port identity without discovery or scan authority;
- NET-001B provides a signed, approval-required, one-connection passive-banner Capability and a
  real Worker action routed through the ordinary Gateway and egress proxy;
- NET-001C reopens one sealed approved execution and admits only neutral protocol knowledge;
- NET-001D binds a separately authorized fresh Worker execution and registers five known-positive
  synthetic banners plus one unknown negative Control; and
- DOMAIN-006 registers the Network `fresh-worker-protocol-replay` strategy and
  `network.service-identification-accuracy` metric together with the common metric applicability.

The review also confirms the remaining runtime gap. No repository-owned service-fixture image,
Network Target Factory, fixture lifecycle, measurement authority, numeric metric aggregator,
validation floor, product projection, or Network-specific real-Docker conformance exists. Current
Worker coverage uses a fake socket. The six NET-001D cases are code-owned Ground Truth requirements,
not provisioned services or measurement evidence.

The existing generic benchmark Target catalog cannot be relabeled as Network support. Its target
families are Web, AI/RAG/MCP, and hybrid, its Docker profiles are scenario-specific, and its
`WalkingBenchmarkRunObservation` and `BenchmarkGroundTruth` wires are Finding-oriented. Extending
their established identities or filling Finding fields with service-classification data would
break or misstate those contracts. Only lower-level canonicalization, signing, recovery, Docker
inspection, and journal patterns may be reused where their semantics remain exact.

AI and the other domains remain less suitable for the next measured runtime. AI still lacks one
concrete deterministic Ground Truth case and carries provider, credential, cost, nondeterminism,
and session-contamination boundaries. The remaining domains require a new provider, host agent,
artifact source, parser, sandbox, device, or credential runtime before measurement can begin.

## Decision

Select Phase 24, Governed Measured Network Service Identification, as the next single vertical
slice. Constrain it to the exact six NET-001D synthetic passive-banner cases. Do not generalize it
to arbitrary targets, DNS, UDP, port ranges, port enumeration, raw sockets, active protocol
writes, credentials, production networks, or general service scanning.

Use one minimal code-owned TCP banner-emitter image with an immutable observed image identity. The
image accepts only one code-owned case ID and maps that ID internally to the exact registered
banner; callers cannot supply arbitrary banner bytes, commands, ports, or images. Each case uses a
fresh disposable container and isolation boundary, no published host port, and one versioned fixed
container port. The Target sends its case-owned banner immediately after accept and reads no
application payload. The PAJIN Worker continues to send zero application-protocol bytes to the
Target.

Keep the Worker on its proxy-only network. The egress proxy alone may bridge to the exact current
fixture network, and the Worker request must use the Target Factory's inspected IP-literal
coordinate. Target creation and coordinate inspection do not authorize the action. The ordinary
Capability activation, Campaign Scope, approval, one-use ActionPermit, Gateway, deployment Worker,
and trusted CONNECT receipt path must be rebuilt after the coordinate exists and before dispatch.

Deliver Phase 24 as four independently reviewable boundaries:

1. **NET-002A: exact isolated-service measured-case authority.** Add Network-specific versioned
   public registration, private Ground Truth binding, immutable image/profile identity, six-case
   membership, DOMAIN-006 plan reference, measurement protocol, validation-floor policy, and
   non-executable selection authority. Do not modify or reinterpret the existing generic benchmark
   catalog, Walking observation, NET-001A/B/C/D, or DOMAIN-006 wires. NET-002A selects no live
   Target, creates no network, and grants no provider, approval, Permit, Worker, measurement,
   product, or execution authority.
2. **NET-002B: registry-governed disposable fixture source measurement.** Materialize each exact
   case through a Network-specific recoverable Docker Target lifecycle. Execute one separately
   approved NET-001B action per case through the existing Gateway/Worker path, seal exact target,
   proxy, Worker, CONNECT receipt, output, and cleanup evidence, and retain raw banner bytes only in
   the private authority path. A code-owned denial set must prove that substituted Scope, case,
   route, image, or authority is rejected before dispatch. No source label confirms a real service
   or enters the Graph.
3. **NET-002C: independent fresh-Worker Replay and Network floor.** Re-run all six cases with
   disjoint Run, request, Decision, approval, Permit, dispatch, Worker execution, Evidence, and
   Target lifecycle identities. Reopen both exact executions and the private case binding before
   evaluating ground-truth coverage, recall, false-positive rate, precision, Replay success,
   time-to-first-valid-result, request units, Tool calls, evidence completeness, policy-denial
   correctness, and `network.service-identification-accuracy`. Preserve the DOMAIN-006 task-success,
   monetary-cost, and cleanup metric N/A semantics; Target lifecycle cleanup remains a mandatory
   admission and residue check rather than a fabricated numeric Network action metric. A satisfied
   floor is benchmark evidence only and grants no endpoint-service confirmation or Finding.
4. **NET-002D: bounded Operator product read and exact conformance.** Seal only public-safe case
   identities, aggregate metrics, applicability, floor state, and explicit false-authority markers
   into a Network measurement product. Expose it through a deployment-pinned zero-argument reader
   and one authenticated Operator-only non-cacheable read. No raw banner, private expected label,
   container coordinate, Graph mutation, Finding, report delivery, or new execution entrypoint may
   be exposed. Complete the phase only after an exact-commit Ubuntu real-Docker workflow executes
   all source and Replay cases, the denial set, cleanup, fresh-process product reload, and an
   unconditional zero-residue audit successfully.

Ground Truth, Domain classification, Graph knowledge, product state, and a passing metric are never
execution authority. The Target Factory may choose only the six code-owned cases, while every
Worker execution remains separately authorized through the existing action path.

## Consequences

- Network becomes the next measured synthetic Domain slice without opening production scanning.
- A new Network-specific Target and measurement contract is required because existing benchmark
  wires cannot honestly represent protocol-label classification.
- The same exact six cases are used for source measurement and independent Replay, but every live
  lifecycle and authorization identity is disjoint.
- The minimal banner emitter avoids third-party FTP, IMAP, POP3, SMTP, or SSH server credentials,
  configuration surfaces, active protocol semantics, and image-maintenance ambiguity.
- Real-Docker runtime cost grows to at least twelve approved Worker executions plus denial and
  product-reload checks; workflow timeouts and residue checks must be explicit.
- A measured classifier result remains a synthetic benchmark result. It does not prove that an
  arbitrary endpoint runs a service, product, version, or vulnerability.

## Rejected alternatives

### Reuse the existing generic benchmark Target catalog and Walking observation

Rejected because their target families, Docker profiles, Ground Truth, and observation fields are
Web/AI and Finding-oriented. Reusing them would either break established wire identities or encode
service labels as vulnerability Findings.

### Run off-the-shelf protocol servers

Rejected for this first slice because full FTP, mail, and SSH images add credentials, active
protocol state, configuration, package, and maintenance boundaries unrelated to the bounded banner
classifier. The code-owned emitter tests only the exact registered banner contract.

### Measure the six banner constants in-process

Rejected because NET-001D already performs classifier drift tests. Phase 24 must prove the real
Target, proxy, Gateway, Worker, trusted receipt, cleanup, and fresh Replay boundaries.

### Confirm a service or create a Finding after a label match

Rejected because synthetic Ground Truth measures the bounded classifier, not the identity or
security state of an arbitrary endpoint. Product output remains a benchmark evaluation.

### Expand to DNS, UDP, ranges, or active probes

Rejected because those coordinates require new Scope, resolver, protocol, write-budget, and safety
contracts. They are not implied by the existing passive IP-literal TCP Capability.

### Select AI or several domain runtimes concurrently

Rejected because Network has the smaller deterministic authority boundary, and a multi-domain
runtime phase would cross unrelated provider, credential, Target, and measurement trust boundaries.

## Security and authority impact

This ADR selects work; it does not itself build an image, provision a Target, create a network,
issue an approval or Permit, run a Worker, admit Graph data, publish a measurement, or expose a
product. Phase 24 implementation must remain synthetic, internal-only, image-pinned, bounded, and
operator-opt-in.

The fixture Target publishes no host port. Worker and Target never share a network; the proxy is
the only bridge. Case membership, banner bytes, fixed port, image identities, and Target lifecycle
must be code-owned and content-addressed. Caller-selected images, commands, payloads, coordinates,
or expected labels fail closed. Every cleanup path must run after isolation and the conformance
workflow must independently query for PAJIN-managed, execution-labelled, and exact-name residue.

No DNS resolution, production endpoint, Internet target, raw socket authority, credential,
application-protocol write, port scan, service confirmation, Finding, Graph mutation, report,
delivery, or cross-domain runtime authority is introduced by this decision.

## Compatibility and rollback

The roadmap decision is additive. Existing NET-001A/B/C/D, DOMAIN-006, Capability, Campaign,
approval, ActionPermit, Gateway, Worker, Graph, benchmark, WEB-002, UX-009, artifact reader, and
wire identities remain unchanged. New Network artifacts require their own versions and readers.

Rollback removes Phase 24 from `PLAN.md` and supersedes this roadmap decision. Once implementation
exists, rollback stops producing the additive NET-002 artifacts and removes the Network-specific
Target, provider, measurement, product, tests, and workflow path without rewriting accepted
NET-001 Runs, Graph events, or registered fixture profiles.

## Verification requirements

Each boundary must cover canonical six-case membership and order, case/banner/digest substitution,
unknown-Control semantics, private/public Ground Truth separation, image and profile drift,
caller-selected configuration rejection, Target coordinate and network substitution, published
ports, direct Worker-to-Target attachment, extra CONNECTs, Worker application writes, missing
trusted receipts, authority reuse, stale approvals, Permit reuse, incomplete cleanup, residue,
metric numerator/denominator and N/A drift, false service confirmation, raw/private disclosure,
Graph/Finding/report escalation, and product reader substitution.

NET-002B through NET-002D additionally require opt-in real-Docker tests. The Phase 24 Exit Gate
requires an exact-commit Ubuntu workflow in which all required tests and the unconditional residue
audit succeed; fake sockets, in-process classifier calls, or a non-Docker fixture do not count.

## Related contracts and decisions

- [ADR-0257](0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [ADR-0223](0223-bind-network-replay-and-fixtures-without-service-authority.md)
- [NET-001D](../benchmark/NET-001D-fresh-worker-replay-isolated-service-fixtures.md)
- [NET-001B](../capability/NET-001B-passive-service-identification-capability.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
