# FORENSICS-001D: Independent Parser Comparison and Seeded Evidence Requirements

- Status: Implemented, bounded comparison and unmaterialized requirement registry
- Version: `v1alpha1`
- Domain: Digital Forensics
- Validation API: `pajin.dev/forensic-evidence-analysis-replay-validation/v1alpha1`
- Requirement-profile API: `pajin.dev/forensic-evidence-analysis-benchmark-fixture-profile/v1alpha1`
- Authority: `src/pajin/workflow/forensic_evidence_analysis_replay_benchmark.py`
- Decisions:
  [ADR-0247](../adr/0247-bind-independent-forensic-parser-comparison-and-seeded-evidence-without-source-or-measurement-authority.md)
  and [ADR-0249](../adr/0249-cross-link-forensic-replay-identity-clarification.md)
- Predecessors:
  [FORENSICS-001A](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md),
  [FORENSICS-001B](../capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md),
  [FORENSICS-001C](../graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md),
  and [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

FORENSICS-001D reopens one stored FORENSICS-001C admission and one later, separately authorized,
completed, and sealed parser execution over the same asserted immutable forensic source. It
verifies exact source, custody, logical-analysis, Scope, and confinement equivalence; automatically
distinguishes deterministic re-parse from independent parser provenance; and returns only a
neutral comparison of opaque result metadata and the bounded FORENSICS-001C structural-Oracle
output.

FORENSICS-001D separately registers twelve future seeded evidence requirements: one expected
class-owned review signal, one `no-signal` negative Control, and one corrupted-input bounded-
rejection Control for each disk, memory, log, and generic artifact Surface. The registry contains
requirements only. It materializes no evidence, provisions or invokes no parser or sandbox,
observes no rejection or cleanup, verifies no Ground Truth, and emits no measurement.

The implementation is a contextful verification and projection boundary. It is not a source or
result-body reader, parser runtime, Replay scheduler, Target Factory, fixture provider, benchmark
Harness, parsed-field adjudicator, semantic Oracle, Finding validator, or Graph writer.

## Reopened FORENSICS-001C inputs

`ForensicEvidenceAnalysisReplayBenchmarkGate`, exposed by
`bind_forensic_evidence_analysis_replay`, receives:

1. the exact source FORENSICS-001C observation-source inputs;
2. the corresponding stored `ForensicEvidenceAnalysisKnowledgeAdmission`;
3. exact separately authorized comparison observation-source inputs;
4. source and comparison evidence roots and SQLite Graph authority stores;
5. one deployment-configured source-membership trust anchor shared by both contexts; and
6. explicit deployment-configured source and comparison parser-execution trust anchors.

Each execution is reopened through
`load_verified_forensic_evidence_analysis_observation_source`. The loader independently rebuilds
current FORENSICS-001B activation, Campaign Scope, preparation, and approved job; resolves exactly
one consumed ActionPermit and durable approval-consumption receipt; recomputes Gateway policy;
verifies the nested source-membership and outer parser-execution Ed25519 signatures, exact Grant,
runtime assertion, and detached result receipt; and recomputes the workflow-owned structural
Oracle. It opens neither the forensic source nor the parser result body.

Only the source must already be Graph-admitted. Its Observation event and, when present, its
immediately following Hypothesis event must exist exactly in the supplied source store. The second
execution remains separately sealed evidence and is not admitted automatically. Validation and
trusted reload append no Graph event to either store.

## Same source-membership authority and immutable source semantics

Both contexts must be verified by the same deployment-configured source-membership trust anchor.
The two source assertions may have distinct envelope identity, signature, and validity timestamps,
but they must assert exactly equal immutable source semantics:

- complete FORENSICS-001A Surface, class, locator, and provenance coordinate;
- source-root kind and SHA-256, source artifact-record SHA-256, and provenance-record SHA-256;
- artifact SHA-256 and byte count;
- custody binding, authority, object, authorization identity and digest;
- immutable object version and source-membership purpose; and
- identical pre/post state and no-mutation/provenance-preservation assertions.

The shared trust anchor proves only that both assertions came from the same configured deployment
authority and were not altered. It does not independently verify source existence, Run seal,
artifact membership, authenticity, immutability, chain of custody, evidence format, or provenance
truth.

## Exact logical-analysis equivalence

Source and comparison must have exactly equal:

- Campaign identity, current Campaign Scope, and matched exact parser-bound allow rule;
- complete Surface, Surface reference, class, locator, provenance, artifact digest and bytes;
- input kind, logical operation, logical parser, rule set, and output schema;
- custody and authorization semantics;
- code-backed Capability, signed release, activation-set semantics, and minimum Forensics Worker
  profile;
- read-only/no-exec input, read-only root, non-root identity, no-new-privileges, network/DNS-disabled
  and provenance-preserving isolation requirements;
- artifact, output, runtime, memory, process, parser-work, recursion, decompression-ratio, and
  absolute expanded-byte ceilings; and
- every zero network, DNS, host-read, source-write/copy, evidence-mutation, credential/secret,
  device, plugin, lateral-movement, target-execution, and shell channel.

The complete preparations, requests, normalized-parameter digests, and sandbox bindings must not
be compared for raw equality because they contain the deliberately different concrete parser
coordinates below. Equality is derived from a code-owned semantic projection that excludes only
fresh authority/evidence identity and the required implementation differences. Each C loader still
requires its own complete raw values to match that execution's Permit, approved job, signed
statement, runtime receipt, and detached result receipt exactly.

## Automatic replay mode and parser-execution provenance

The caller does not select a replay mode. The gate compares the complete concrete implementation
coordinates and accepts exactly one of two modes:

- `deterministic-reparse` requires the same parser-execution trust anchor and active signer,
  parser executable SHA-256, parser configuration SHA-256, sandbox image SHA-256, and sandbox
  binding semantics; and
- `independent-parser-comparison` requires all of those execution trust, signer, executable,
  configuration, image, and sandbox coordinates to differ.

Partial implementation drift fails closed. A changed executable with a reused signer or image is
neither deterministic re-parse nor the bounded independent provenance required here.

In independent mode, the following concrete implementation coordinates differ:

- parser-execution trust-anchor digest and active signer key identity;
- parser executable SHA-256;
- parser configuration SHA-256;
- sandbox image SHA-256; and
- sandbox binding ID and digest.

The following action and evidence identity coordinates must also be disjoint: preparation, Run,
evidence-root digest, request, MissionEnvelope, ActionProposal, Graph Decision, approval,
approval-consumption receipt, ActionPermit, dispatch, execution, Gateway outcome, signed
statement, runtime receipt, outer evidence, result receipt, and structural-Oracle verdict.

The normalized-parameter digest is recomputed and bound inside each complete C context, but it is
not a fresh execution identity: deterministic mode may reuse it, while independent mode may
change it only as a consequence of the required concrete parser-coordinate differences. The
Capability Grant's authority semantics must match after excluding Grant ID and issuance/expiry
timestamps. Those excluded values may be equal or different and do not prove separate action or
evidence provenance.

The comparison execution's signed `startedAt` must be strictly later than the source execution's
signed `finishedAt`. Distinct identifiers alone cannot relabel an older or concurrent execution as
comparison evidence.

Independent mode establishes only bounded implementation-provenance diversity. Deterministic mode
establishes only a repeated concrete implementation context. Neither mode proves
independent source code, algorithm design, parser library lineage, development organization,
supply chain, physical host or Worker, clock authority, or absence of common-mode failure. The
logical parser remains the same code-owned FORENSICS-001B semantic contract.

## Neutral comparison

`ForensicEvidenceAnalysisReplayComparison` is mode neutral and has three values:

- `forensic-analysis-result-match`: opaque result-body digest, signed result byte count,
  result disposition, structural-Oracle disposition, and bounded review signal all match;
- `forensic-analysis-result-changed`: a bounded result disposition, Oracle disposition, or
  review signal differs; and
- `forensic-analysis-result-unresolved`: dispositions and signal match while opaque digest or
  byte count differs.

`ForensicEvidenceAnalysisReplayMode` is either `deterministic-reparse` or
`independent-parser-comparison`. The validation combines mode and comparison into exactly six
`state` values:

- `deterministic-reparse-match`, `deterministic-reparse-changed`, or
  `deterministic-reparse-unresolved`; and
- `independent-parser-comparison-match`, `independent-parser-comparison-changed`, or
  `independent-parser-comparison-unresolved`.

Equal `resultBodySha256` values must retain equal signed `resultBytes`; an equal digest with a
different byte count is inconsistent sealed provenance and fails closed. Different digests may
have equal or different byte counts.

`match` is opaque sealed-result reproduction only. `changed` does not confirm evidence, parser, or
security-state change. `unresolved` is not a negative conclusion. None of the states confirms
source format, parsed fields, provenance, parser correctness, semantic truth, Ground Truth, a
Hypothesis, or a Finding. FORENSICS-001D never opens or interprets either result body.

## Seeded evidence requirement profile

`registered_forensic_evidence_analysis_benchmark_fixture_profile` returns a content-addressed
`ForensicEvidenceAnalysisBenchmarkFixtureProfile` that pins the exact
DOMAIN-006 Forensics plan, all four FORENSICS-001A Surface classes, and twelve sorted private
Ground Truth requirements:

| Surface | Known-positive expected outcome | Negative-Control expected outcome | Corrupted-input expected outcome |
| --- | --- | --- | --- |
| disk | `review` / `forensics.disk-analysis` | `no-signal` | `bounded-corruption-handling` / bounded rejection |
| memory | `review` / `forensics.memory-analysis` | `no-signal` | `bounded-corruption-handling` / bounded rejection |
| log | `review` / `forensics.log-analysis` | `no-signal` | `bounded-corruption-handling` / bounded rejection |
| generic artifact | `review` / `forensics.artifact-analysis` | `no-signal` | `bounded-corruption-handling` / bounded rejection |

Every case binds the class-owned input kind, operation, logical parser, rule set, exact DOMAIN-004
Forensics profile, immutable source/custody and provenance-preservation requirements, resource and
parser-safety ceilings, offline non-root read-only/no-exec isolation, zero-live-channel semantics,
and two distinct parser implementation executions.

Successful known-positive and negative-Control cases require future evidence for:

- private Ground Truth and immutable evidence materialization;
- source membership, custody, and provenance;
- source parser execution, offline runtime, and bounded result;
- comparison parser execution, offline runtime, and bounded result;
- independent provenance-preservation adjudication; and
- cleanup.

For `ForensicEvidenceBenchmarkExpectedOutcome.BOUNDED_CORRUPTION_HANDLING`, corrupted-input
Controls require the same source/custody, isolation, execution, provenance, Ground Truth, and
cleanup lineage, but require bounded rejection evidence from both parser contexts
instead of successful FORENSICS-001C result receipts. A future versioned rejection contract must
define that evidence before those cases can be executed or measured. This registry does not extend
the C result disposition beyond `review` and `no-signal`.

The profile embeds no raw disk, memory, log, artifact, provenance, custody, parser output, parsed
field, corrupted bytes, seed, path, URI, object key, case/operator/device identity, credential,
secret, command, plugin, trust anchor, or execution receipt. It requires zero network/DNS requests,
host reads, source writes/copies, evidence mutations, credential/secret reads or uses, device
sessions, plugin loads, lateral movement attempts, target executions, shell commands, and debugger
attaches.

The profile records requirement coverage only:

- four of four current Surface classes represented;
- four known-positive review requirements;
- four no-signal negative Controls;
- four corrupted-input bounded-rejection Controls; and
- twelve total requirements.

Those counts are registry membership, not numeric benchmark observations.
`privateGroundTruthRequirementsRegistered=true` means only that the requirements are code owned.
Private Ground Truth verification, evidence materialization, provider and fixture authorization,
parser execution, rejection observation, cleanup observation, independent comparison evidence,
and measurement remain false.

## DOMAIN-006 plan and metrics

The profile and validation bind the exact DOMAIN-006 `independent-parser-comparison` strategy and
these four required domain metric references:

- `forensics.artifact-coverage`;
- `forensics.parsing-accuracy`;
- `forensics.provenance-preservation-rate`; and
- `forensics.corrupted-input-handling-rate`.

Only validation in automatically derived `independent-parser-comparison` mode records
`domainValidationStrategySatisfied=true`. The `deterministic-reparse` mode keeps that marker
false and cannot satisfy a Replay or Profile validation floor.

All four metrics remain unmeasured in both modes. The projection contains no metric value, numerator, denominator,
aggregate, benchmark Result, quality assertion, or Profile-floor evidence. Registering all four
Surface classes does not measure artifact coverage. A signed source assertion does not measure
provenance preservation. Expected parsed fields do not measure accuracy. Corrupted-input
requirements do not demonstrate safe handling.

DOMAIN-006 marks `common.cleanup-success-rate` `not-applicable` for the initial read-only slice.
Future cleanup evidence remains a fixture hygiene and evidence-completeness requirement; it does
not silently turn that metric into required or measured.

## Non-authority boundary

Parser comparison and requirement registration keep the following false:

- source existence, Run seal, artifact membership, authenticity, immutability, custody, provenance,
  format, parsed-field, parser-correctness, semantic, security, or negative truth;
- Ground Truth, positive/negative Control, corrupted-input rejection, or cleanup observation;
- artifact coverage, parsing accuracy, provenance preservation, corrupted-input handling,
  task-success, comparison-success, evidence-completeness, benchmark quality, or Profile-floor
  measurement;
- Hypothesis confirmation and Finding authority;
- Scope expansion, Capability activation, approval, Permit issuance, or Graph admission;
- source access, custody authority, parser or sandbox invocation, or Worker selection;
- network, DNS, host filesystem, source write/copy, evidence mutation, credential/secret access,
  device, plugin, lateral movement, target execution, shell, or debugger authority; and
- Replay scheduling and further execution authority.

The implementation imports no source/result-body reader, parser, archive decoder, container or VM
controller, socket or HTTP client, subprocess or shell, fixture provider, Ground Truth adjudicator,
Graph writer, or benchmark aggregator. It may call the existing C contextful loader, which reads
only each root's two canonical bounded metadata files.

## Audit and trusted reload

The returned validation and requirement profile are deterministic content-addressed projections.
FORENSICS-001D writes no Graph node, edge, event, snapshot, approval, Permit, evidence artifact,
source, parser result, fixture, benchmark result, sandbox journal, or cleanup receipt.

Bare `ForensicEvidenceAnalysisReplayValidation.model_validate` is structural,
content-addressed parsing only and is not a trusted verification entry point. Trusted wire reload
must use `load_verified_forensic_evidence_analysis_replay_validation` with both original
C inputs, both exact evidence roots and Graph stores, the projection's embedded source admission,
the shared source-membership trust anchor, and both parser-execution trust anchors. The loader
reopens both C sources, verifies the embedded admission against the source Graph store, rebuilds
the expected projection, and requires exact canonical equality. Embedded public keys, signatures,
Graph events, or recomputed projection IDs cannot replace that deployment context.

## Failure handling

The gate and contextful wire loader fail closed for invalid or substituted evidence roots, trust
anchors, signatures, source admissions, Campaign Scope, preparations, Surface/provenance/source
state, custody, parser/rule/configuration/image identities, sandbox assertions, budgets, result
receipts, reused authority coordinates, non-causal timestamps, inconsistent equal-digest byte
counts, comparison fields, requirement cases, DOMAIN-006 plan or metric references, marker
coercion, nested unmodeled state, or any mismatch between a serialized projection and current
evidence and Graph context.

## Compatibility and rollback

FORENSICS-001D is additive and does not change FORENSICS-001A through FORENSICS-001C public wire
identities. DOMAIN-006, Campaign, Scope, Capability, approval, ActionPermit, Gateway, Graph, Worker,
Replay, Finding, benchmark, artifact, and evidence contracts also remain unchanged. No migration is
required.

Rollback removes the FORENSICS-001D workflow module, tests, this contract, and ADR-0247.
FORENSICS-001D creates no Graph event, external source, parser execution, fixture, cleanup action,
or benchmark measurement requiring migration or cleanup.

## Verification

Tests cover all four Surface classes, deterministic and independent mode derivation, partial
implementation drift rejection, independent-mode-only DOMAIN-006 satisfaction,
match/change/unresolved states, equal-digest/unequal-byte rejection, stored source admission, exact
same source-membership authority and immutable source semantics, same versus distinct parser
executable/configuration/image/sandbox/trust/signer provenance, complete separate action/evidence
coordinates, aggregate identity reuse, non-causal execution, Graph event-count preservation, exact
twelve-case requirement coverage, four positive/four negative/four corrupted Controls, all four
exact DOMAIN-006 metric references, registered-but-unverified private Ground Truth,
unmaterialized/unmeasured and no-authority markers, coercion, digest drift, structural wire round
trip, nested-instance forgery, and contextful trusted reload.

Adversarial reload cases substitute the source admission, evidence root, Graph context,
source-membership anchor, and either parser-execution anchor. Source-import review verifies the
absence of runtime, parser, raw-reader, Graph-writer, fixture-provider, and measurement adapters.
