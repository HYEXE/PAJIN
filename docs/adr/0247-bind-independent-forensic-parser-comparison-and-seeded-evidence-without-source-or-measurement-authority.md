# ADR-0247: Bind Independent Forensic Parser Comparison and Seeded Evidence without Source or Measurement Authority

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: FORENSICS-001D

## Context

FORENSICS-001C can reopen one separately approved and completed parser execution, verify its
deployment source-membership and parser-execution signatures under disjoint trust roles, recompute
the structural Oracle, and admit only neutral Graph knowledge. The repository reads only the
content-addressed execution bundle and detached digest-only result receipt. It neither opens the
forensic source nor interprets the parser result body, and the authenticated deployment assertions
do not become independent source, custody, provenance, parser-correctness, or semantic truth.

FORENSICS-001D must compare that stored source with a later, separately authorized execution while
retaining the exact logical Surface, source, custody, Scope, rule, and confinement semantics. The
later execution may repeat the same complete concrete parser context or use a completely distinct
bounded parser-execution provenance context; partial implementation drift is not a mode. The slice
must also register the seeded evidence cases needed by a future Digital Forensics benchmark.
Neither the admitted Observation nor its optional open Hypothesis can authorize the second
execution.

Equal opaque result digests do not prove equal forensic meaning or parser correctness. Different
digests do not prove that the evidence or a security condition changed. Different executable,
configuration, image, sandbox, and signer identities provide a bounded implementation-provenance
distinction; they do not prove independent source code, algorithms, organizations, supply chains,
physical hosts, or freedom from common-mode defects.

DOMAIN-006 already registers the exact Forensics `independent-parser-comparison` strategy and four
domain metrics: artifact coverage, parsing accuracy, provenance preservation, and corrupted-input
handling. That registry contains no fixture, execution, Ground Truth, or numeric measurement.

## Decision

Add a FORENSICS-001D verification and projection boundary that produces two independent artifacts:

1. `ForensicEvidenceAnalysisReplayValidation`, which contextfully reopens and compares two
   sealed FORENSICS-001C sources and derives one of two bounded modes; and
2. `ForensicEvidenceAnalysisBenchmarkFixtureProfile`, which registers future seeded evidence and
   measurement requirements without materializing or executing them.

For the comparison, require the exact stored source FORENSICS-001C admission, exact source and
comparison observation-source inputs, two evidence roots, two SQLite Graph authority stores, one
shared deployment-configured source-membership trust anchor, and explicit source and comparison
parser-execution trust anchors. Reopen both executions through the current FORENSICS-001C loader.
Recompute current B authority, consumed Permit and approval provenance, Gateway policy, both
deployment signatures, runtime and result receipts, and structural Oracle independently. Require
the source Observation and optional immediately following Hypothesis to remain stored exactly. Do
not auto-admit the comparison execution or the comparison projection.

The one shared source-membership trust authority establishes that both contexts are evaluated
against the same configured source/custody authority. Its two signed assertions may have distinct
envelope identities and validity times, but their complete immutable source state must match:
Surface and provenance coordinates, source-root kind and digest, artifact and provenance records,
artifact digest and byte count, custody authority/object/authorization, immutable object version,
purpose, and pre/post no-mutation state. This equality remains attributable deployment assertion,
not independently anchored source, custody, or provenance truth.

Require exact equality of Campaign and Scope, complete FORENSICS-001A Surface, class, locator and
provenance, input kind, logical operation and parser, code-owned rule set, artifact and custody
semantics, Capability and signed release, activation semantics, output schema, non-root identity,
read-only/no-exec isolation, parser-work and archive-safety ceilings, resource ceilings, and every
zero-live-channel counter. Derive equality from code-owned semantic projections that exclude only
fresh action/evidence identities and the concrete parser implementation coordinates required to
differ.

Derive the mode from the complete concrete implementation coordinates:

- `deterministic-reparse` requires the same parser-execution trust anchor and active signer,
  parser executable digest, parser configuration digest, sandbox image digest, and sandbox binding
  semantics; and
- `independent-parser-comparison` requires all of those trust, signer, executable,
  configuration, image, and sandbox coordinates to differ.

Reject partially changed implementation provenance rather than accepting caller-selected mode.
Revalidate every trust domain and issuer. Different identifiers in independent mode do not prove
organizational or physical independence. Deterministic mode proves only a repeated concrete
implementation context, not deterministic parser semantics.

Reject reuse of preparation, Run, evidence-root, request, normalized-parameter, MissionEnvelope,
ActionProposal, Graph Decision, Capability Grant, approval, approval-consumption receipt,
ActionPermit, dispatch, execution, signed statement, runtime receipt, outer evidence, result
receipt, or structural-Oracle identity. Require the comparison statement's signed start to be
strictly later than the source statement's signed finish. Signed timestamp order does not prove
cross-signer clock synchronization or a cryptographically source-bound Replay challenge.

Publish the automatically derived `ForensicEvidenceAnalysisReplayMode` and a mode-neutral
`ForensicEvidenceAnalysisReplayComparison` with only:

- `forensic-analysis-result-match` when result-body digest, signed byte count, result
  disposition, structural-Oracle disposition, and bounded signal all match;
- `forensic-analysis-result-changed` when a bounded result or Oracle disposition or signal
  differs; or
- `forensic-analysis-result-unresolved` when dispositions and signal match but opaque digest
  or byte count differs.

Derive the validation `state` from both values. The only states are
`deterministic-reparse-{match|changed|unresolved}` and
`independent-parser-comparison-{match|changed|unresolved}`.

Only `independent-parser-comparison` satisfies the exact DOMAIN-006 Forensics strategy.
`deterministic-reparse` remains a bounded comparison that does not satisfy that strategy or a
Replay/validation floor.

Reject equal result digests with unequal signed byte counts. None of the three states confirms
evidence format, parsed fields, a security condition, parser correctness, a negative conclusion,
Ground Truth, a Hypothesis, or a Finding.

Register exactly twelve sorted seeded evidence requirements: one class-owned `review` expectation,
one `no-signal` negative Control, and one corrupted-input bounded-rejection Control for each disk,
memory, log, and generic artifact Surface. Bind every requirement to the exact A provenance model,
B Surface-to-input/operation/logical-parser mapping, rule set, DOMAIN-004 minimum Worker profile,
isolation, parser safety ceilings, zero-channel semantics, and two-implementation comparison
requirement.

Successful positive and negative cases require future source/custody, two parser-execution,
runtime, result, provenance-preservation, Ground Truth, and cleanup evidence. Corrupted-input cases
require two bounded rejection outcomes instead of inventing successful C result receipts. The
registry embeds no evidence bytes, parser output, parsed field, path, URI, case/operator/device
identity, credential, secret, command, plugin, trust anchor, or execution receipt.

Bind the exact DOMAIN-006 Forensics plan and all four domain metric references. Keep every metric
required and unmeasured. Emit no value, numerator, denominator, aggregate, benchmark Result, or
validation-floor assertion. Registering all four Surface classes and corrupted-input Controls does
not itself measure coverage, accuracy, provenance preservation, or safe rejection.

Trusted wire reload requires both original C inputs, both exact evidence roots and Graph stores,
the shared source-membership trust anchor, both execution trust anchors, and the stored source
admission. Bare model parsing is structural only. The loader reopens both sources, rebuilds the
projection, and requires complete canonical equality.

## Consequences

- FORENSICS-001D can establish a signed-time-ordered deterministic re-parse or independent parser
  comparison of the same asserted immutable source without dispatching from Graph knowledge.
- The comparison makes opaque agreement, bounded disposition change, and uncertainty explicit
  without manufacturing forensic conclusions.
- Reusing one source-membership trust authority separates source/custody consistency from parser
  implementation comparison; neither deterministic nor independent mode makes either trust role
  Ground Truth.
- The twelve-case registry covers all four current Surface classes and explicitly reserves a
  corrupted-input denominator while remaining unmaterialized and unmeasured.
- A `known-positive` requirement means an expected bounded review signal. A `no-signal` Control is
  not evidence of safety, and a corrupted-input requirement is not an observed rejection.
- Parser runtime, fixture materialization, private Ground Truth verification, parsed-field
  adjudication, cleanup observation, metric aggregation, Profile-floor validation, and Finding
  confirmation remain future authorities.

## Rejected alternatives

### Treat the FORENSICS-001C structural Oracle as an independent parser

Rejected because it checks metadata consistency only and opens neither source nor result body.

### Compare only two result digests

Rejected because equal digests can hide different source, custody, Scope, parser, configuration,
budget, or authority contexts, while different digests have no bounded semantic interpretation.

### Require different source-membership authorities

Rejected because this slice compares parser implementations over the same asserted immutable
source. Changing source authority would conflate source/custody disagreement with parser diversity.

### Infer parser independence from executable hashes

Rejected because different binaries, configurations, images, and signers do not establish
independent source lineage, algorithms, organizations, hosts, or absence of common defects.

### Register only positive and no-signal cases

Rejected because eight cases would omit the explicit corrupted-input handling denominator required
by DOMAIN-006 for the first Forensics benchmark profile.

### Represent corrupted-input rejection as a successful C receipt

Rejected because FORENSICS-001C accepts only completed `review` or `no-signal` results. A future
bounded rejection requires its own evidence contract and cannot be fabricated as successful parser
output.

### Execute fixtures or emit metrics now

Rejected because this slice has no governed evidence materializer, parser runtime, isolated
fixture provider, private Ground Truth verifier, cleanup observer, or measurement Harness.

## Security and authority impact

FORENSICS-001D consumes only previously approved and sealed metadata provenance. It grants no
Scope expansion, Capability activation, approval, Permit issuance, Graph admission, source or
result-body access, custody authority, parser or sandbox invocation, Worker selection, Replay
scheduling, fixture provisioning, Finding, benchmark measurement, or further execution authority.

It grants no network, DNS, host-filesystem, source write/copy, evidence mutation, credential or
secret access, device session, plugin load, lateral movement, target execution, shell, or debugger
authority. It establishes no source, custody, provenance, format, parsed-field, parser-correctness,
semantic, negative-security, Hypothesis, Finding, Ground Truth, or measurement truth.

The validation necessarily retains configured public verification keys, evidence-relative JSON
references, non-routable Scope coordinates, and sealed runtime receipts. It contains no private key,
raw source/result/provenance/custody body, routable target address, live handle, or caller command.

## Compatibility and rollback

FORENSICS-001D is additive. FORENSICS-001A through FORENSICS-001C, DOMAIN-006, Campaign, Scope,
Capability, approval, ActionPermit, Gateway, Graph, Worker, Replay, Finding, benchmark, artifact,
and evidence wire identities remain unchanged. No data migration is required.

Rollback removes the FORENSICS-001D workflow module, tests, benchmark contract, and this ADR. The
boundary creates no Graph event, source artifact, parser execution, fixture, cleanup operation, or
benchmark measurement that requires external cleanup.

## Verification

Positive and adversarial tests cover all four Surface classes, exact twelve-case requirement
coverage, deterministic and independent mode derivation, partial implementation drift rejection,
match/change/unresolved comparison, equal-digest/unequal-byte rejection, stored source admission,
shared source-membership authority, exact immutable source semantics, same versus distinct parser
implementation provenance, aggregate identity reuse, strict signed timestamp order, independent-
mode-only DOMAIN-006 satisfaction and four metric bindings, registry order and digest identity,
Graph immutability, unmaterialized/unmeasured markers, structural wire round trip, contextful
trusted reload, nested-instance forgery, and boolean/integer coercion.

Source-import review verifies that the module does not bind a source/result-body reader, parser,
container or VM controller, socket or HTTP client, subprocess or shell, Graph writer, fixture
provider, Ground Truth adjudicator, or benchmark aggregator. The permitted C loader continues to
read only the two canonical bounded metadata files in each configured evidence root.

## Related contracts

- [FORENSICS-001D contract](../benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md)
- [FORENSICS-001C](../graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md)
- [FORENSICS-001B](../capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md)
- [FORENSICS-001A](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0244](0244-type-forensic-evidence-surfaces-without-source-access-or-evidence-mutation-authority.md)
- [ADR-0245](0245-bind-forensic-parser-preparation-without-source-read-or-evidence-mutation-authority.md)
- [ADR-0246](0246-authenticate-forensic-source-membership-and-parser-execution-with-distinct-deployment-trust.md)
