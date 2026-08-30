# CRYPTO-001D: Independent Implementation Replay and Seeded Vector Requirements

- Status: Implemented, bounded comparison and unmaterialized requirement registry
- Version: `v1alpha1`
- Domain: Cryptography
- Validation API: `pajin.dev/cryptographic-misuse-analysis-recomputation-validation/v1alpha1`
- Requirement-profile API: `pajin.dev/cryptographic-misuse-analysis-benchmark-vector-profile/v1alpha1`
- Authority: `src/pajin/workflow/cryptographic_misuse_analysis_recomputation_benchmark.py`
- Decision: [ADR-0243](../adr/0243-bind-independent-cryptographic-recomputation-and-seeded-vectors-without-key-use-or-measurement-authority.md)
- Predecessors:
  [CRYPTO-001A](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md),
  [CRYPTO-001B](../capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md),
  [CRYPTO-001C](../graph/CRYPTO-001C-oracle-recomputed-cryptographic-analysis-knowledge-admission.md),
  and [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

CRYPTO-001D reopens one stored CRYPTO-001C admission and one separately authorized, completed,
and sealed offline analysis for the same logical Cryptographic input. It verifies exact input
equivalence, distinct implementation provenance, separate action and evidence authority, and
strict signed timestamp ordering before returning a neutral comparison of opaque result metadata and the
bounded CRYPTO-001C structural-Oracle output.

CRYPTO-001D also registers eight future seeded-vector requirements: one expected bounded review
signal and one `no-signal` negative Control for each of the four CRYPTO-001A Surface classes. This
registry contains requirements only. It materializes no vector, key, declaration, configuration,
ciphertext, plaintext, artifact, sandbox, execution, cleanup evidence, Ground Truth observation,
or benchmark measurement.

The implementation is a contextful verification and projection boundary. It is not an artifact
reader, result-body interpreter, independent analyzer runtime, cryptographic primitive runner,
key service, Replay scheduler, Target Factory, fixture provider, benchmark Harness, semantic
Oracle, Finding validator, or Graph writer.

## Reopened CRYPTO-001C inputs

The validation gate receives:

1. the exact source CRYPTO-001C observation-source inputs;
2. the corresponding stored `CryptographicMisuseAnalysisKnowledgeAdmission`;
3. exact separately authorized recomputation observation-source inputs;
4. separate source and recomputation SQLite Graph authority stores; and
5. separate deployment-configured CRYPTO-001C execution trust anchors.

Each execution is reopened through
`load_verified_cryptographic_misuse_analysis_observation_source`. The loader independently
rebuilds current CRYPTO-001B activation, Campaign Scope, preparation, and approved job; resolves
exactly one consumed ActionPermit and durable approval-consumption receipt; recomputes Gateway
policy; verifies the configured Ed25519 signature, runtime assertion, and detached result receipt;
and recomputes the workflow-owned structural Oracle. It opens neither the analyzed artifact nor
the result body and invokes neither the CRYPTO-001B Capability Oracle nor the fixed CTF XOR Oracle.

Only the source must already be Graph-admitted. Its Observation event and, when present, its
immediately following Hypothesis event must exist exactly in the supplied source store. The
recomputation remains separately sealed evidence and is not admitted automatically.

## Exact logical-input equivalence

Source and recomputation must have exactly equal:

- Campaign identity, current Campaign Scope, and matched exact non-routable allow rule;
- complete CRYPTO-001A Surface, protocol parent, Surface class, locator kind, and Surface digest;
- input kind, bound declaration-or-artifact digest source, artifact SHA-256, and artifact byte
  count;
- custody authority, object, authorization reference and digest, and custody binding semantics;
- code-owned rule set, logical operation, logical analyzer, and output schema;
- code-backed Capability, signed release, activation-set semantics, and minimum Cryptography
  Worker profile;
- the canonical logical request semantics after excluding only the fresh request identity and the
  explicitly distinct sandbox, executable, image, and trust-anchor coordinates; and
- artifact, output, runtime, memory, process, and all zero-live-channel ceilings.

The complete CRYPTO-001B preparations, materialized requests, raw
`normalizedParametersDigest` values, and sandbox bindings must not be equal because they bind the
intentionally distinct implementation coordinates below. Each CRYPTO-001C loader requires its own
raw normalized-parameters digest to match that execution's request, ActionProposal, ActionPermit,
and signed statement exactly. CRYPTO-001D compares only an exact code-owned logical-request
projection that removes the enumerated implementation coordinates; a caller-supplied equivalence
label, implementation name, or selected field list is never accepted.

A different Surface or parent, input kind, artifact or declaration digest, artifact size,
custody or authorization coordinate, rule set, logical operation or analyzer, schema, Scope,
Capability release, or budget is an incomparable input and fails closed. It is not a changed
cryptographic result.

## Distinct implementation provenance

The source and recomputation must bind distinct:

- deployment-configured trust-anchor digests and active signer identities, including active key
  IDs and Ed25519 public keys;
- sandbox binding IDs and digests;
- analyzer executable SHA-256 values; and
- sandbox image SHA-256 values.

Each trust domain and issuer is revalidated through its own deployment-configured anchor but need
not differ. The code-owned CRYPTO-001B deployment ID and non-root run-as identity also remain
equal. Those values identify the reviewed trust interface and service class; they are not
caller-selected implementation or organizational-independence identities.

These checks establish only `distinctImplementationCoordinatesVerified=true`: two separately
configured verification authorities signed executions under different executable, image,
sandbox, and active-signer coordinates. They do not verify independent source-code lineage,
algorithm design, development organization, supply chain, physical host or Worker, process or
container instance, absence of shared dependencies, or freedom from common-mode defects. A claim
about any of those properties requires separate signed build and organizational provenance.

## Separate authority and signed timestamp order

The following coordinates must all differ between source and recomputation:

- Run and source-root digest;
- request, request digest, and raw normalized-parameters digest;
- MissionEnvelope, ActionProposal, Graph Decision, and ActionPermit;
- approval envelope and approval-consumption receipt;
- execution and signed-statement digest;
- sandbox-runtime receipt;
- source-root-qualified attestation identity and file digest; and
- source-root-qualified result-receipt identity, ID, receipt digest, and file digest.

Relative evidence filenames may remain equal in separate source roots. A filename alone is not an
Evidence identity and cannot satisfy or violate the distinct-authority requirement.

Aggregate comparison rejects reuse hidden behind a different outer object. The recomputation
statement's signed `startedAt` must be strictly later than the source statement's signed
`finishedAt`. Distinct identifiers alone cannot relabel an older or concurrent execution as an
ordered independent-implementation comparison.

This is a strict comparison of timestamps authenticated by two configured trust anchors, not a
cryptographically bound causal chain. The current CRYPTO-001C approval and statement formats do
not bind the source root into the recomputation request and do not attest cross-signer clock
synchronization. The projection therefore records `signedTimestampOrderVerified=true`, while
`sourceBoundRecomputationAuthorizationVerified=false` and
`crossSignerClockSynchronizationVerified=false` remain explicit. Strong causal Replay would
require a new signed source-root challenge and common clock-authority contract.

Both ActionPermits remain consumed historical provenance. Neither the stored Graph admission nor
this projection authorizes the recomputation, another artifact read, or another execution.

## Neutral recomputation comparison

`CryptographicMisuseAnalysisRecomputationComparison` has exactly three values:

- `cryptographic-analysis-independent-recomputation-match`: opaque result-body digest, signed
  result byte count, result disposition, structural Oracle disposition, and bounded review signal
  are all equal;
- `cryptographic-analysis-independent-recomputation-changed`: the bounded result or Oracle
  disposition or review signal differs; and
- `cryptographic-analysis-independent-recomputation-unresolved`: bounded dispositions and review
  signal are equal, but the opaque result-body digest or signed byte count differs.

The projection also records exact body-digest, byte-count, result-disposition, Oracle-disposition,
and signal equality booleans. Equal result-body digests with different signed byte counts are inconsistent sealed
provenance and fail closed before comparison. A disposition or signal difference takes precedence
over an opaque-body difference and produces `changed`.

`matched` is opaque sealed-result reproduction only. It does not establish that either
implementation read or interpreted bytes correctly, that an algorithm or protocol is secure or
insecure, that misuse exists, or that a negative result is complete. `changed` is not a
cryptographic regression or vulnerability claim. `unresolved` and two matching
`inconclusive-no-signal` verdicts are not evidence of safety or absence of misuse.

The validation binds the exact DOMAIN-006 Cryptography `independent-recomputation` strategy. It
does not emit a numeric independent-recomputation success rate, satisfy a validation floor, or
turn the CRYPTO-001C structural Oracle into an independent semantic Oracle.

## Seeded-vector requirement registry

`CryptographicMisuseAnalysisBenchmarkVectorProfile` is content addressed and contains exactly
eight sorted requirements:

| Surface class | Positive requirement | Negative-Control requirement |
| --- | --- | --- |
| `protocol` | `review` / `cryptography.protocol-policy` | `no-signal` / no review signal |
| `key-usage` | `review` / `cryptography.key-usage-policy` | `no-signal` / no review signal |
| `ciphertext` | `review` / `cryptography.ciphertext-structure` | `no-signal` / no review signal |
| `configuration` | `review` / `cryptography.configuration-policy` | `no-signal` / no review signal |

Each requirement binds the exact CRYPTO-001A class and CRYPTO-001B input, digest-source,
operation, logical-analyzer, rule-set, DOMAIN-004 minimum Worker profile, isolation, and
zero-channel semantics. Every case fixes `syntheticTestOnlyRequired=true` and requires future
external materialization of one synthetic test-only input, two separately authorized
implementation executions, and complete evidence for:

- a private Ground Truth and materialization attestation;
- both execution attestations and embedded offline runtime receipts;
- both detached bounded result receipts; and
- disposable-fixture cleanup.

The registry embeds no vector or seed bytes, key, key reference, ciphertext, plaintext,
configuration, cryptographic parameter, declaration, expected recovered key or plaintext,
artifact path, URI, credential, command, plugin, analyzer output, trust anchor, or execution
receipt. A code-owned requirement ID is not a materialized seed or proof that a corresponding
artifact exists.

Positive requirements expect only the bounded class-owned review signal. They do not name or
confirm a weakness, insecure algorithm, parameter, key relation, exploitability, impact, or
Finding. A negative Control expects `no-signal`; that expected routing value is not proof that the
future vector is safe or that an implementation has complete coverage.

The profile state is `registered-seeded-vector-requirements-not-materialized-or-measured` and
fixes `seededVectorRequirementsRegistered=true`,
`privateGroundTruthRequirementsRegistered=true`, `positiveControlsRegistered=true`, and
`negativeControlsRegistered=true`. These are registry-membership facts only.

## DOMAIN-006 benchmark boundary

The requirement profile binds the exact DOMAIN-006 Cryptography plan, its
`independent-recomputation` strategy, and only the registered Cryptography-specific metric
references:

- `cryptography.test-vector-coverage`; and
- `cryptography.independent-recomputation-success-rate`.

Both metrics remain required and unmeasured. The profile contains no value, numerator,
denominator, observation, aggregate, floor, or benchmark Result. It does not invent a
Cryptography-specific classification-accuracy metric. Common false-positive, precision, recall,
evidence-completeness, and other applicability remain governed by the unchanged DOMAIN-006 plan.

`vectorMaterialized=false`, `privateGroundTruthVerified=false`,
`groundTruthCaseObserved=false`, `negativeControlObserved=false`,
`fixtureExecutionAuthorized=false`, `providerExecutionAuthorized=false`,
`sandboxProvisioned=false`, `cleanupObserved=false`, `recomputationEvidenceBound=false`,
`benchmarkMeasurementObserved=false`, `testVectorCoverageMeasured=false`,
`independentRecomputationSuccessRateMeasured=false`, `evidenceCompletenessMeasured=false`,
`detectionQualityEstablished=false`, and `profileValidationFloorSatisfied=false` remain explicit.

## Non-authority and zero-channel boundary

The validation and requirement profile keep all of the following false:

- semantic misuse, protocol-policy, key-usage, ciphertext-structure, configuration-value,
  vulnerability, Hypothesis-confirmation, negative-security-claim, and Finding truth;
- independent source-code, algorithm, organization, supply-chain, host, Worker, or common-mode
  independence verification;
- artifact, result-body, declaration, configuration, ciphertext, plaintext, key, key-reference,
  parameter, seed, vector, raw output, or credential embedding or access;
- Scope expansion, Capability activation, approval, Permit issuance, Graph admission, and Finding
  authority;
- sandbox invocation, Worker selection, fixture provisioning, Replay scheduling, and execution;
- network, DNS, host-filesystem access, artifact writes, mutation, target-process execution,
  debugger attach, and shell commands; and
- credential or key access, key-store sessions, key search, target-domain cryptographic
  operations, protocol negotiation, Capability or external Oracle invocation, and plaintext or
  key-material output.

CRYPTO-001C's Ed25519 provenance-signature verification remains the only cryptographic primitive
invoked by this verification path. It is not a seeded-vector computation, a target-domain
cryptographic operation, key-use authority, or semantic Oracle.

The implementation imports or calls no artifact resolver, result-body reader, key or credential
service, cryptographic primitive suite, CTF XOR solver or host Oracle, socket, HTTP or DNS client,
subprocess, shell, container or VM controller, Target Factory, benchmark aggregator, Graph writer,
or fixture materializer.

## Audit, storage, and trusted reload

The returned validation and requirement profile are deterministic, content-addressed projections.
CRYPTO-001D writes no Graph node, edge, event, snapshot, approval, Permit, artifact, result,
benchmark measurement, fixture record, sandbox journal, or cleanup receipt.

Bare `CryptographicMisuseAnalysisRecomputationValidation.model_validate` is structural parsing
only and is not a trusted verification entry point. Trusted wire reload must provide both
original CRYPTO-001C source contexts, both exact Graph authority stores, both
deployment-configured trust anchors, and the stored source admission. The contextful loader
reopens both sources through the current CRYPTO-001C verifier, confirms source-event membership,
rebuilds the expected projection, and requires exact canonical equality. The projection therefore
records `deploymentContextReverificationRequired=true` and
`selfAuthenticatingProjection=false`.

## Failure handling

The gate and trusted loader fail closed for absent, malformed, altered, foreign, or mismatched
source evidence; reused source/recomputation Graph authority stores; missing or substituted source
Graph events; stale activation or Scope;
preparation, Surface, parent, artifact, custody, authorization, rule, operation, logical analyzer,
schema, Capability, release, or budget drift; equal implementation or active-signer coordinates;
reused action, execution, or evidence identity; invalid signed timestamp order; result digest and
byte-count inconsistency; Oracle disposition or signal confusion; comparison, plan, strategy, metric,
requirement, expected-outcome, synthetic-only, isolation, or evidence-role substitution; extra
nested model state;
boolean or integer coercion; and attempts to enable any materialization, measurement, truth, or
action-authority marker.

## Compatibility and rollback

CRYPTO-001D is additive. It changes no CRYPTO-001A/B/C, fixed CTF XOR, DOMAIN-006, Campaign,
Capability, approval, ActionPermit, Gateway, Graph, Worker, Replay, Finding, benchmark, artifact,
or evidence wire identity. No artifact, key, vector, result body, metric, or Graph data migration
is introduced.

Rollback removes the CRYPTO-001D workflow module, tests, this contract, and ADR-0243. It creates
no external execution, admitted Graph event, materialized fixture, key state, sandbox, or benchmark
measurement requiring cleanup or migration.

## Verification

Focused tests cover all four Surface classes; all eight positive and negative-Control
requirements; exact-match, changed, and unresolved comparisons; equal-digest/unequal-byte-count
rejection; exact logical-input equality; source admission membership; two contextful CRYPTO-001C
reloads; distinct trust-anchor, signer, executable, image, sandbox, action, execution, and evidence
coordinates; strict signed timestamp order and explicit absence of source-bound authorization or
cross-signer clock proof; aggregate identity reuse; Graph event-count preservation;
DOMAIN-006 plan and exact metric references; registry order and digest identity; no raw material,
key, ciphertext, plaintext, configuration, or parameter fields; all unmaterialized, unmeasured,
semantic, independence, and authority markers; structural wire round trip; contextful trusted wire
reload; nested instance forgery; and boolean and integer coercion.

Graph event-count assertions verify that comparison and trusted reload do not append events. A
source import audit verifies that the CRYPTO-001D module does not bind a CTF XOR solver, socket,
subprocess, artifact/result-body reader, key service, cryptographic-operation adapter, fixture
materializer, Graph writer, or benchmark aggregator.
