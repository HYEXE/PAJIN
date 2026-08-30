# FORENSICS-001C: Sealed Forensic Analysis Knowledge Admission

- Status: Adopted, neutral Observation and optional bounded open Hypothesis
- API versions:
  - `pajin.dev/forensic-evidence-source-membership-trust-anchor/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-execution-trust-anchor/v1alpha1`
  - `pajin.dev/forensic-evidence-source-membership-attestation/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-result-receipt/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-execution-statement/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-execution-bundle/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-knowledge-candidate/v1alpha1`
  - `pajin.dev/forensic-evidence-analysis-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/forensic_evidence_analysis_admission.py`
- Decision: [ADR-0246](../adr/0246-authenticate-forensic-source-membership-and-parser-execution-with-distinct-deployment-trust.md)

## Purpose

FORENSICS-001C admits one neutral `forensics.analysis-observation` after rechecking an already
approved, Permit-bound, deployment-produced FORENSICS-001B parser execution. A structurally exact
`review` disposition may additionally produce one bounded open
`forensics.forensic-proposition` Hypothesis.

The workflow authenticates two different historical assertion chains: source membership and
custody under a source/custody trust anchor, and parser execution under a parser-execution trust
anchor. It does not resolve or open the forensic source, source records, provenance records, or
result body. It adds no source provider, repository reader, parser, sandbox runtime, Worker,
credential broker, Graph writer, Replay scheduler, or Finding producer.

FORENSICS-001A Surfaces remain `registered-not-authorized`, and FORENSICS-001B preparations remain
`prepared-not-authorized`. Historical evidence authorizes no later source access or execution.

## Distinct deployment-owned trust anchors

`ForensicEvidenceSourceMembershipTrustAnchor` authenticates only source-membership and custody
statements. It binds a versioned provider contract, trust domain, issuer, supported source-root
kind, and a uniquely ordered verification keyring with exactly one active key.

`ForensicEvidenceAnalysisExecutionTrustAnchor` authenticates only parser-execution statements. It
binds an independent trust domain, issuer, keyring, exact FORENSICS-001B sandbox, code-backed
Capability, signed release, deployment, logical parser, executable digest, configuration digest,
and image digest.

Both anchors are deployment-owned and verification-only. Their types, digests, verification
paths, and key lifecycles are distinct, and their keyrings cannot share a verification key. They
grant no current Campaign, approval, Permit, source access, provider invocation, sandbox
invocation, Graph admission, Replay, Finding, or execution authority.

The caller and all files beneath the evidence root are untrusted and cannot select, replace, or
extend either anchor. An embedded anchor, anchor reference, key, provider endpoint, path, or
credential is rejected. If either production anchor is not explicitly injected by deployment
configuration, the loader fails closed before accepting an execution bundle or creating a Graph
proposal. Repository fixtures and test keys are not production trust.

`ForensicEvidenceAnalysisKnowledgeAdmissionGate` receives the evidence root only through its
deployment-owned constructor configuration. The root must already exist, be absolute, be a
directory, and not itself be a symlink. Caller input and evidence metadata cannot carry, select,
replace, or alias that root. For each evidence-file read, the shared bounded regular-file reader
rejects every symlink or junction path component and a symlink or junction leaf. A missing or
invalid configured root fails closed.

## Source-membership and custody assertion

`ForensicEvidenceSourceMembershipAttestation` is a strict canonical JSON statement nested with
its distinct source/custody signature inside the signed execution bundle. It is verified only
against the deployment-owned source/custody anchor and binds:

- the exact complete FORENSICS-001A Surface and derived opaque Surface reference;
- source-root kind and digest, source-artifact-record digest, provenance-record digest, artifact
  digest, and artifact byte count;
- the complete FORENSICS-001B custody reference, custody object ID, authorization ID, and
  authorization digest;
- the exact provider-contract version and an opaque immutable object-generation coordinate;
- the bounded read-only parser-analysis purpose, validity interval, issue time, signer, and key;
  and
- its own content-addressed identity.

The A Run root and B custody or authorization digest are coordinates, not trust roots. Their exact
agreement is necessary but insufficient. The attestation is accepted only after signature, issuer,
key lifecycle, validity, provider contract, complete Surface, record, custody, authorization,
object-generation, digest, and byte-count bindings all agree.

Successful verification means only that the configured source/custody issuer made those exact
historical assertions. The loader does not inspect a provider, authorization document, source
Run, source artifact record, provenance record, mount, or artifact bytes. It therefore does not
independently verify source existence, author identity, legal custody, acquisition completeness,
source format, digest, byte count, immutability, or provenance sanitization. Authenticated
assertions and independently recomputed facts remain separate fields; independent fact markers
stay false in this version.

## Signed parser execution

`ForensicEvidenceAnalysisExecutionBundle` contains one
`ForensicEvidenceSourceMembershipBundle`, which contains the canonical source-membership
attestation and its distinct source/custody signature, together with a canonical parser-execution
statement and the outer parser-execution signature. The source signature is verified only against
the source/custody anchor, and the outer signature is verified only against the parser-execution
anchor. The outer statement exact-binds the nested source statement identity, source signature
digest, and source/custody anchor digest in addition to:

- the parser trust domain, issuer, sandbox, deployment, logical parser, executable,
  configuration, and image identities;
- the current Campaign and Run, plus the exact Capability Grant ID and canonical digest;
- the rebuilt exact FORENSICS-001B preparation, exact GET request, target, and normalized
  parameters;
- Graph Decision, ActionProposal, Capability Grant, approved job, current signed activation, and
  current signed release;
- exactly one consumed `ActionPermit` and one durable approval-consumption receipt;
- a recomputed allowed Gateway decision and sanitized Gateway outcome whose digest includes the
  exact Capability Grant digest;
- the verified nested source-membership attestation identity and source-signature digest;
- one content-addressed runtime receipt;
- one detached result-receipt reference, file digest, receipt identity, and content digest; and
- execution start, finish, attestation, receipt, and statement times in causal order.

The statement records one bounded historical source read performed under the already consumed
authority. It cannot authorize another source read, provider lookup, mount, copy, parser run,
Worker job, sandbox invocation, Graph write, Replay, or Finding.

## Runtime and no-mutation assertions

`ForensicEvidenceAnalysisSandboxRuntimeReceipt` directly binds the exact B Surface and custody
coordinate, operation, rule set, logical parser, executable/configuration/image digests,
deployment, non-root identity, output schema, resource ceilings, runtime identity, confinement
digest, and attestation time. It does not duplicate `inputKind`. The loader binds `inputKind`
transitively by exact reconstruction of the complete B preparation in the signed outer statement
and by requiring the detached result receipt's explicit `inputKind` to agree with that
preparation.

The signed deployment statement asserts that the input was mounted immutable, read-only, and
no-exec; the root filesystem was read-only; network and DNS were disabled; no-new-privileges and
disabled core dumps were enforced; and configured runtime, memory, process, parser-work,
recursion, decompression-ratio, absolute decompressed-byte, artifact, and output ceilings were
respected. Observed counters must remain within the exact B ceilings.

It also binds pre/post artifact SHA-256 and byte-count equality, pre/post immutable
object-generation equality, and literal-zero observations for source writes and copies, evidence
mutations, host-filesystem reads, credential and secret reads or uses, device sessions, plugin
loads, network and DNS requests, lateral-movement attempts, target-process executions, and shell
commands.

These are authenticated historical runtime assertions. They do not independently prove that no
transient mutation happened outside the attested boundary, that no compromised provider lied, or
that the source was immutable throughout its custody history. C uses separate assertion markers
and does not rewrite FORENSICS-001A/B false-state fields.

## Strict detached result receipt

`ForensicEvidenceAnalysisResultReceipt` is a strict digest-only JSON manifest. It directly binds
the execution, request, preparation identity and digest, exact Surface, artifact digest and byte
count, input kind, operation, logical parser, rule set, fixed output schema, external result-body
SHA-256, bounded byte count, JSON media type, receive time, and one disposition:

- `review`; or
- `no-signal`.

The result receipt has no standalone custody fields. Custody agreement is transitive: its exact
preparation identity and digest are checked against the complete B preparation carried by the
signed outer statement, and the loader requires the source-membership bundle, runtime receipt,
outer statement, and reconstructed preparation to agree on the same custody binding.

The receipt contains no caller-selected signal. For `review`, the admission policy derives exactly
one signal from the code-owned FORENSICS-001B mapping:

| Surface class | Derived signal |
| --- | --- |
| `disk` | `forensics.disk-analysis` |
| `memory` | `forensics.memory-analysis` |
| `log` | `forensics.log-analysis` |
| `artifact` | `forensics.artifact-analysis` |

For `no-signal`, no signal is derived. Both dispositions are semantically inconclusive. A valid
signature, completed parser process, result-body digest, JSON media type, or derived signal does
not prove the caller-declared class, source format, parser correctness, result truth, absence of a
condition, vulnerability, or Finding.

The receipt and Graph payload embed no raw source or result bytes, raw disk/memory/log/artifact,
raw source-artifact/provenance/custody record, mutable path, URI, object key, filename, host,
device, case, operator, custodian, personal information, credential, secret, credential reference,
parser message, stack trace, rule detail, or caller prose. Field-level hashes of private,
credential, secret, or low-entropy values are also forbidden because hashing is not redaction. The
whole externally retained result body remains outside Graph and is not opened during admission.

## Current authority and evidence revalidation

Before Graph proposal construction, the loader:

1. requires both deployment-owned trust anchors and proves that they are type-distinct,
   digest-distinct, and have disjoint verification keys;
2. revalidates the complete FORENSICS-001A Surface and rebuilds the exact FORENSICS-001B
   preparation from the current signed activation, release, Campaign, Surface, operation, custody,
   sandbox, request, and agent identity;
3. thereby rechecks exact parser-bound Scope, deny precedence, and GET Rules of Engagement;
4. rechecks the Decision, ActionProposal, exact Capability Grant ID and canonical digest, approved
   job, request, target, normalized parameters, preparation digest, and activation-set identity;
5. resolves exactly one matching consumed ActionPermit and one durable approval-consumption
   receipt from the existing authority store;
6. recomputes the Gateway decision from the current Campaign, Grant, request, and network-disabled
   Forensics Tool specification, and recomputes the sanitized Gateway outcome with the exact
   Capability Grant digest;
7. verifies the nested source/custody signature, source-membership statement, provider contract,
   key lifecycle, validity, complete Surface, records, custody, authorization, object generation,
   artifact digest, byte-count assertion bindings, and the outer statement's exact binding to the
   nested statement, signature, and source/custody anchor;
8. verifies the independent parser-execution signature, execution statement, runtime receipt,
   result receipt, sanitized Gateway outcome, causal timing, and evidence-file identities; and
9. checks all resource ceilings, pre/post equality assertions, zero-channel observations,
   code-owned disposition/signal mapping, and complete cross-document identity agreement.

The loader accepts only the signed execution bundle and detached result receipt as bounded
metadata evidence beneath the Gate-owned deployment-configured evidence root. Their sole valid
references are code-owned names derived from the SHA-256 of the exact file bytes:

- `evidence/forensic-evidence-analysis-execution-<bundle-bytes-sha256>.json`; and
- `evidence/forensic-evidence-analysis-result-receipt-<receipt-bytes-sha256>.json`.

It rejects a caller-selected root, alternate filename or reference alias, missing, multiply
linked, path-escaping, symlinked, oversized, changed, non-JSON, or duplicate-key file. It never
accepts a caller-selected provider path, opens source or result-body bytes, invokes a custody
provider, launches a parser or sandbox, selects a Worker, accesses a credential service, creates
a Permit, or dispatches a Gateway request.

## Observation, Evidence, and bounded Hypothesis

The Observation proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit, where succeeded means only that the
  authenticated historical execution reached its completed lifecycle;
- one target-derived `forensics.analysis-observation` with confidence `1.0` and fixed neutral
  prose;
- exactly two restricted `Evidence` nodes: one for the outer signed parser-execution bundle,
  which nests the separately signed source-membership attestation, and one for the detached result
  receipt;
- one `produces` edge; and
- two `supported-by` edges.

The Observation value digest binds both trust anchors, the nested source attestation and source
signature, the outer parser-execution statement and signature, exact A/B lineage, exact Capability
Grant ID and canonical digest, current authority chain, Gateway outcome including the Grant
digest, runtime and no-mutation assertions, result receipt, external result-body digest
declaration, disposition, derived signal, and complete source-root digest. Evidence nodes carry
only the two SHA-256-derived canonical references above and fixed labels; no caller filename or
alias can enter Graph. No separate source-attestation Evidence node or reference is created.
Graph prose contains no forensic content, source-form assertion, parser result, personal data,
credential, path, custody narrative, semantic conclusion, or negative conclusion.

A `review` disposition may create exactly one agent-derived, confidence `0.5`, open
`forensics.forensic-proposition` Hypothesis and one `enables` edge from the neutral Observation.
Its fixed text states only that the exact Surface carries a bounded class-owned review signal and
requires separately authorized validation. It does not name or confirm a forensic fact, source
format, actor, timeline, credential, weakness, exploitability, impact, root cause, or Finding.

A `no-signal` disposition creates no Hypothesis and no negative conclusion.

## Existing Graph authority and exact retry

Admission requires a current non-empty Graph Snapshot, the exact existing
`GraphAdmissionAuthority`, its event log, trusted-lineage registry, and the registered C producer.
Observation admission uses compare-and-set against the bound current head. An optional Hypothesis
must immediately follow its Observation; intervening Graph activity fails closed.

Observation and Hypothesis proposals are content-addressed. Exact retry reopens and revalidates
only the same bounded metadata evidence, both deployment anchors, and current authority. It returns
the prior immutable events and appends no duplicate. It performs no source or result-body read,
provider access, Tool or Gateway dispatch, sandbox or Worker execution, credential access, parser
run, Replay, or other side effect. C creates no Forensics-specific Graph store or writer.

## Explicit non-authority

Candidates remain `sealed-knowledge-not-admitted`; successful admissions become
`registered-not-authorized`. Candidate and admission artifacts fix all of the following to false:

- raw source, result, provenance, custody, personal, credential, secret, path, and caller-prose
  embedding;
- independent source-existence, source-authenticity, legal-custody, acquisition-completeness,
  global-immutability, source-format, evidence-class, parser-correctness, result-truth,
  negative-security-claim, vulnerability, Hypothesis-confirmation, and Finding authority;
- source resolution, provider invocation, source/result-body read, mount, copy, or mutation;
- Scope expansion, Capability activation, approval satisfaction, Permit issuance, Gateway
  dispatch, sandbox invocation, Worker/profile/job selection, and budget reservation;
- network, DNS, host-filesystem, device, plugin, credential, secret, lateral-movement, target
  execution, and shell authority; and
- Replay, Ground Truth, Control, measurement, benchmark Result, Finding confirmation, and further
  execution authority.

An authenticated source assertion, signed parser execution, neutral Observation, restricted
Evidence reference, or open Hypothesis is knowledge only. None is a bearer token or action
authority.

Disk, memory, log, and artifact remain sibling classes. Matching content or provenance digests do
not establish extraction, parent/child origin, shared custody, or copy equivalence. Such a relation
requires a separate exact externally authenticated provenance statement and a versioned Graph
admission rule.

## Fail-closed behavior

Admission rejects absent production anchors; shared anchor keys; caller- or evidence-selected
anchors; absent or invalid Gate-owned evidence roots; caller-selected roots or reference aliases;
missing, changed, oversized, multiply linked, non-JSON, duplicate-key, symlinked, or path-invalid
metadata evidence; source/custody or parser signature, issuer, key lifecycle,
validity, provider-contract, Campaign, activation, release, Scope, preparation, Decision,
Proposal, Grant ID, Grant digest, approval, Permit, request, target, normalized-parameter, custody,
authorization, Gateway Grant digest,
object-generation, source-root, record, artifact digest/size, class, rule-set, operation, parser,
executable, configuration, image, deployment, run-as, runtime/confinement, resource, timing,
pre/post equality, zero-channel, output-schema, result-receipt, disposition, signal, file-digest,
or source-root-digest substitution; missing or ambiguous Permit/approval records; source-form or
semantic escalation; stale Graph heads; Graph authority substitution; proposal/event drift; extra
model-instance state; true authority markers; and boolean or integer coercion.

## Compatibility and rollback

FORENSICS-001C is additive and explicitly imported. FORENSICS-001A/B, Run-integrity, Campaign,
Scope, Capability, ToolRequest, approval, ActionPermit, Gateway, DOMAIN-002/004, Worker, Graph,
Replay, Finding, and benchmark wires retain their versions. No source provider, resolver,
production key, parser runtime, result-body reader, credential broker, data migration, or default
workflow is added.

Rollback removes the specialized workflow, tests, this contract, and ADR-0246. Already admitted
immutable Graph events and deployment-owned evidence remain historical records and require no
migration.

## Verification requirements

Focused verification must cover all four Surface-to-signal routes and all four no-signal routes;
neutral-only and optional-Hypothesis admission; absent deployment anchors; source/parser anchor
substitution and shared keys; evidence-selected anchors; absent, relative, nonexistent, or
symlinked Gate-owned roots; caller root selection and reference aliases; source-membership,
authorization,
object-generation, record, digest, and byte-count drift; signature and key lifecycle failures;
current activation, Campaign, exact Scope, Decision, Proposal, Grant ID and canonical digest,
approval, Permit, request, Gateway outcome including the Grant digest, preparation, parser,
executable, configuration, image, deployment, run-as, runtime,
resource, pre/post equality, and zero-channel substitution; missing or ambiguous authority records;
raw/PII/credential/path/caller-prose injection; source-form, semantic, negative-claim, Replay, and
Finding escalation; malformed, duplicate-key, oversized, path-escaping, and symlinked evidence;
stale Graph heads; producer registration; Graph cardinality; exact retry; integer and boolean
coercion; and forged nested Pydantic state.

FORENSICS-001D remains responsible for separately authorized deterministic re-parse or
independent-parser comparison, disposable seeded evidence fixtures, corruption Controls, Ground
Truth, metrics, and validation floors. An exact C retry is not Replay.
