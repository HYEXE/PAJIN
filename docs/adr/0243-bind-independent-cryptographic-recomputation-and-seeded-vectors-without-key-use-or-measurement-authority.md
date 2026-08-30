# ADR-0243: Bind Independent Cryptographic Recomputation and Seeded Vectors without Key-use or Measurement Authority

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: CRYPTO-001D

## Context

CRYPTO-001C can reopen one separately approved and completed offline misuse-analysis execution,
verify its deployment signature and strict detached result receipt, recompute structural agreement
with current CRYPTO-001B authority, and admit only neutral Graph knowledge. The repository does not
read the artifact or result body. Its structural Oracle derives one class-owned review signal from
`review`, or preserves `no-signal` as inconclusive. Neither result establishes semantic
cryptographic truth.

CRYPTO-001D must bind the source to a later, separately authorized execution under a distinct
implementation identity and register the seeded-vector requirements needed by a future
Cryptography benchmark. The consumed source Permit, admitted Observation, open Hypothesis, B
preparation, structural Oracle, or fixed CTF XOR lab cannot authorize or substitute for that
execution.

Equal opaque result digests alone do not prove equal Surface, artifact, custody, rule, analyzer,
Scope, budget, implementation, or semantics. Different digests do not prove a cryptographic
change. Different executable hashes also do not prove independent source code, algorithm design,
organizations, hosts, or freedom from common defects. Finally, a code-owned seeded-vector case is
only a requirement until materialization, execution, Ground Truth, cleanup, and measurement
Evidence are separately supplied and verified.

DOMAIN-006 already registers the Cryptography `independent-recomputation` strategy and the exact
`cryptography.test-vector-coverage` and
`cryptography.independent-recomputation-success-rate` metrics. That registry deliberately contains
neither execution evidence nor numeric measurements.

## Decision

Add a CRYPTO-001D verification and projection boundary that produces two independent artifacts:

1. `CryptographicMisuseAnalysisRecomputationValidation`, which reopens and compares two sealed
   CRYPTO-001C sources; and
2. `CryptographicMisuseAnalysisBenchmarkVectorProfile`, which registers future fixture and
   measurement requirements without materializing or executing them.

For the comparison, require the exact stored source CRYPTO-001C admission, two original source
contexts, two SQLite Graph authority stores, and two separately configured execution trust
anchors. Reopen each execution through the current CRYPTO-001C contextful loader. Recompute current
B authority, consumed Permit and approval provenance, Gateway policy, deployment signature,
runtime and result receipt, and structural Oracle independently. Require the source Observation
and optional Hypothesis events to remain stored exactly. Do not auto-admit the recomputation.

Require exact equality of Campaign and Scope, complete Surface and parent, input kind,
declaration-or-artifact digest and byte count, custody and authorization semantics, rule set,
logical operation and analyzer, output schema, Capability and release, canonical logical request
semantics, resource ceilings, and every zero-live-channel budget. Derive logical-request equality
from a code-owned projection that excludes only the fresh request identity and the deliberately
different sandbox, executable, image, and trust-anchor coordinates.

Do not compare complete preparations, materialized requests, or raw
`normalizedParametersDigest` values for equality. Those digests include implementation-specific
coordinates and must differ across the two executions. Each CRYPTO-001C loader still requires its
own digest to bind exactly to that execution's request, ActionProposal, ActionPermit, and signed
statement.

Require distinct trust-anchor digests, active signer identities, sandbox binding IDs and digests,
analyzer executable digests, and sandbox image digests. Revalidate each trust domain and issuer but
do not require them to differ. Preserve the code-owned B deployment ID and non-root service
identity. This is a bounded, auditable definition of distinct implementation provenance; it is
not evidence of independent source-code lineage, algorithm design, development organization,
supply chain, physical host or Worker, or absence of common-mode failure.

Reject reuse of any Run, source root, request, request digest, normalized-parameters digest,
MissionEnvelope, ActionProposal, Graph Decision, approval, approval-consumption receipt,
ActionPermit, execution, signed statement, runtime receipt, attestation, or result-receipt
identity. Require the recomputation's signed start to be strictly later than the source's signed
finish.

Record that exact signed timestamp ordering, but do not call it a cryptographically bound causal
chain. The current C approval and statement formats neither bind the source root into the
recomputation authorization nor prove clock synchronization across the two configured signers.
Keep source-bound recomputation authorization and cross-signer clock synchronization false. A
stronger causal Replay requires a new versioned source-root challenge and clock-authority contract.

Publish only:

- `cryptographic-analysis-independent-recomputation-match` when opaque body digest, signed byte
  count, result disposition, structural Oracle disposition, and bounded signal all match;
- `cryptographic-analysis-independent-recomputation-changed` when the bounded result or Oracle
  disposition or signal differs; or
- `cryptographic-analysis-independent-recomputation-unresolved` when bounded dispositions and
  signal match but body digest or byte count differs.

Reject equal result digests with unequal signed byte counts. Record the five equality booleans,
but do not interpret either result body. None of the three states confirms misuse, safety,
correctness, regression, a negative conclusion, a Hypothesis, or a Finding. `matched` is opaque
sealed-result reproduction only.

Register exactly eight sorted seeded-vector requirements: one class-owned `review` expectation
and one `no-signal` negative Control for each protocol, key-usage, ciphertext, and configuration
Surface. Bind every case to the exact A/B Surface-to-input, digest-source, operation, logical
analyzer, rule-set, DOMAIN-004 minimum Worker profile, isolation, and zero-channel semantics. Require future
external materialization, two separately authorized implementation executions, complete execution,
runtime, and result evidence, private Ground Truth attestation, and cleanup evidence.

Keep the registry free of vector or seed bytes, keys, key references, ciphertext, plaintext,
configuration, parameters, declarations, expected recovered material, paths, credentials,
commands, plugins, outputs, trust anchors, and execution receipts. Positive and negative expected
outcomes are requirements, not observations. Do not add algorithm, key-size, curve, nonce, IV,
salt, tag, or protocol-parameter dimensions that CRYPTO-001A/B do not model.

Bind the exact DOMAIN-006 plan and its two registered Cryptography metric references. Keep both
metrics required and unmeasured. Emit no value, numerator, denominator, aggregate, validation
floor, or benchmark Result, and do not invent a Cryptography-specific classification-accuracy
metric.

Trusted wire reload requires both original C contexts, both exact Graph stores, both external
trust anchors, and the stored source admission. Bare model parsing is structural only. The loader
reopens both sources, rebuilds the projection, and requires complete canonical equality.

## Consequences

- CRYPTO-001D can establish separately authorized, signed-timestamp-ordered, distinct
  implementation provenance for the same exact logical input without dispatching from Graph
  knowledge. It does not establish a source-bound causal chain.
- The comparison makes exact sealed agreement, bounded-output change, and opaque-output
  uncertainty explicit without manufacturing semantic cryptographic conclusions.
- Matching structural Oracle results do not turn that Oracle into an independent semantic Oracle.
- Different implementation coordinates remain a bounded provenance property, not proof of source,
  organizational, physical, or algorithmic independence.
- The eight-case registry completely covers the current four-class A/B signal vocabulary while
  claiming no algorithm or parameter coverage that the current schemas cannot express.
- `known-positive` means an expected bounded review signal, not a confirmed weakness. `no-signal`
  is a negative Control expectation, not evidence of safety.
- Seeded-vector materialization, Ground Truth verification, provider and fixture execution,
  cleanup observation, coverage, recomputation success, evidence completeness, detection quality,
  and Profile-floor measurement remain future authorities.

## Rejected alternatives

### Treat the CRYPTO-001C structural Oracle as the independent implementation

Rejected because it checks metadata consistency only, opens neither artifact nor result body, and
performs no independent analysis.

### Reuse the fixed CTF XOR host Oracle

Rejected because that scenario-specific Oracle performs a fixed key search and handles recovered
plaintext and key material. Reuse would silently import powers forbidden by CRYPTO-001A~C.

### Infer implementation independence from a second Run or caller label

Rejected because distinct action identities prove separate authorization, not implementation
diversity. The bounded contract requires different externally configured signer, executable,
image, and sandbox identities and still disclaims source-code and organizational independence.

### Require identical complete preparations or sandbox bindings

Rejected because those objects contain the executable and image coordinates that must differ.
CRYPTO-001D compares an exact code-owned logical-input projection and separately verifies the
intended implementation differences.

### Treat exact digest agreement as semantic correctness

Rejected because opaque output agreement can reproduce a shared parser error, common-mode bug, or
incorrect result. It is bounded recomputation evidence, not cryptographic truth or Finding
confirmation.

### Treat two `no-signal` results as a negative conclusion

Rejected because neither implementation's coverage nor false-negative behavior is measured. The
comparison remains inconclusive with respect to safety and absence of misuse.

### Embed or execute seeded vectors now

Rejected because this slice has no governed vector materializer, independent analyzer runtime,
fixture provider, sandbox scheduler, Ground Truth admission, cleanup observer, or benchmark
Harness. Registration must precede materialization, execution, and measurement.

### Emit test-vector coverage or recomputation-success metrics

Rejected because no materialized Ground Truth cases or measured observations are bound. Required
metric references are not numeric Evidence.

## Security and authority impact

CRYPTO-001D consumes only previously approved and sealed provenance. It grants no Scope expansion,
Capability activation, approval, Permit issuance, Graph admission, artifact or result-body access,
custody authority, sandbox invocation, Worker selection, fixture provisioning, Replay scheduling,
Finding, benchmark measurement, or further execution authority.

It grants no network, DNS, host-filesystem, mutation, target-process, debugger, shell, credential,
key, key-store, key-search, protocol-negotiation, plaintext-output, key-output, or target-domain
cryptographic-operation authority. CRYPTO-001C Ed25519 provenance verification remains allowed and
is not target-domain cryptographic execution.

The requirement profile contains no raw artifact, vector, seed, key, key reference, ciphertext,
plaintext, configuration, parameter, declaration, analyzer output, credential, secret, path, URI,
command, plugin, or execution receipt. The validation necessarily retains CRYPTO-001C public
verification keys, evidence-relative JSON references, non-routable Scope coordinates, and sealed
runtime receipts; it contains no private or target-domain key material, raw artifact/result body,
routable target URI, live handle, or caller command. Semantic misuse, negative security claims,
Hypothesis confirmation, Finding truth, source-code independence, Ground Truth verification,
materialization, execution, cleanup, measurement, detection quality, and validation floors remain
false.

## Compatibility and rollback

CRYPTO-001D is additive. CRYPTO-001A through CRYPTO-001C, the fixed CTF XOR Capability and Oracle,
DOMAIN-006, Campaign, Scope, Capability, approval, ActionPermit, Gateway, Graph, Worker, Replay,
Finding, benchmark, artifact, and evidence wire identities remain unchanged. No data migration is
required.

Rollback removes the CRYPTO-001D workflow module, tests, benchmark contract, and this ADR. No Graph
event, external artifact, seeded vector, key state, sandbox, execution, cleanup operation, or
benchmark measurement is created by this boundary.

## Verification

Positive and adversarial tests cover all four Surface classes, all eight requirement cases, exact
match/change/unresolved comparison, equal-digest/unequal-byte rejection, stored source admission,
both contextful C reloads, exact logical-input equality, distinct implementation and
action/execution/evidence identities, strict signed timestamp order and its explicit causal
limitations, aggregate identity reuse, plan and metric binding, registry ordering and digest
identity, Graph immutability, unmaterialized and
unmeasured markers, semantic and authority markers, no raw or key-bearing fields, structural wire
round trip, trusted contextful reload, nested instance forgery, and boolean and integer coercion.

Graph event-count assertions verify that comparison and trusted reload do not append events. A
source import audit verifies that the CRYPTO-001D module does not bind the CTF XOR Oracle, an
artifact/result-body reader, key or credential service, cryptographic-operation adapter, network,
subprocess, fixture provider, sandbox controller, Graph writer, or benchmark aggregator.

## Related contracts

- [CRYPTO-001D contract](../benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md)
- [CRYPTO-001C](../graph/CRYPTO-001C-oracle-recomputed-cryptographic-analysis-knowledge-admission.md)
- [CRYPTO-001B](../capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md)
- [CRYPTO-001A](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0018](0018-bounded-ctf-crypto-artifacts.md)
- [ADR-0240](0240-type-cryptographic-analysis-surfaces-without-key-use-authority.md)
- [ADR-0241](0241-bind-offline-cryptographic-misuse-analysis-without-key-use-or-artifact-access-authority.md)
- [ADR-0242](0242-admit-cryptographic-analysis-knowledge-without-semantic-or-key-authority.md)
