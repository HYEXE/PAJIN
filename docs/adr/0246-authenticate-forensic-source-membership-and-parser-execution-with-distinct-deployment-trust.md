# ADR-0246: Authenticate Forensic Source Membership and Parser Execution with Distinct Deployment Trust

## Status

Accepted

## Context

FORENSICS-001A represents a caller-declared disk, memory, log, or generic artifact class together
with caller-declared Run-root, source-artifact-record, provenance-record, artifact SHA-256, and
byte-count coordinates. The typed Surface is content-addressed and
`registered-not-authorized`, but it does not prove that the Run, records, or artifact exist; that
the Run root is authentic or externally anchored; that the artifact is a member; or that custody,
immutability, digest, size, class, or format has been verified.

FORENSICS-001B binds that complete Surface to a current signed Capability release, exact Campaign
Scope, an opaque custody coordinate, a logical parser, and a configuration-only read-only sandbox.
Its `pajin.forensics.unverified-immutable-evidence-custody-coordinate` identifier and authorization
digest remain coordinates rather than a trust root or bearer authorization. Preparation stops at
`prepared-not-authorized` and produces no source read, parser execution, result, Observation,
Evidence, Graph admission, Hypothesis, Finding, or Replay authority.

FORENSICS-001C needs to admit knowledge about one historical parser execution without allowing a
caller-controlled coordinate, evidence file, local Run seal, or parser signer to authenticate a
forensic source. Source custody and parser execution are different trust boundaries. They can have
different operators, compromise modes, key lifecycles, and evidence semantics. A parser execution
signature cannot prove acquisition provenance or source membership, while a custody signature
cannot prove which parser image ran or how the runtime was confined.

Forensic sources and results can also contain raw evidence, case and operator identifiers, device
or host data, personal information, credentials, secrets, and legally sensitive provenance.
Hashing such values is not redaction. The admission boundary therefore cannot open or project raw
source, result-body, or provenance content into the Canonical Graph.

The production immutable-evidence provider, custody system, and verification keys remain
deployment decisions. Repository code and test fixtures must not be represented as a production
provider or production trust anchor.

## Decision

Add the FORENSICS-001C admission contract with two distinct deployment-owned, verification-only
trust anchors:

1. `ForensicEvidenceSourceMembershipTrustAnchor` verifies a canonical source-membership and
   custody attestation nested with its distinct signature inside the signed execution bundle. It
   binds an exact provider contract, trust domain, issuer, key lifecycle, and verification keyring
   to the complete FORENSICS-001A Surface and FORENSICS-001B custody coordinate.
2. `ForensicEvidenceAnalysisExecutionTrustAnchor` verifies a canonical detached
   parser-execution statement. It binds an exact trust domain, issuer, key lifecycle, verification
   keyring, Capability release, FORENSICS-001B sandbox, deployment, parser executable,
   configuration, and image identities. The outer execution statement exact-binds the nested
   source attestation, its source/custody signature, and the source/custody trust-anchor digest.

The anchor types, digests, verification paths, and key lifecycles are independent. A single object
cannot satisfy both roles. The two configured keyrings must not share a verification key. Neither
anchor is accepted from the evidence root, source attestation, parser statement, result receipt,
Campaign, request, or caller. They are supplied only by deployment configuration. Missing,
malformed, inactive, expired, revoked, cross-role, or evidence-selected production trust fails
closed before any Graph proposal is created.

`ForensicEvidenceAnalysisKnowledgeAdmissionGate` receives the evidence root only from
deployment-owned constructor configuration. The configured root must be an absolute, existing,
non-symlink directory. Caller input and evidence metadata cannot carry, select, replace, or alias
it. For each evidence-file read, the shared bounded regular-file reader rejects every symlink or
junction path component and a symlink or junction leaf. An absent or invalid root fails closed.

The FORENSICS-001A Run root and FORENSICS-001B custody binding, custody object ID, authorization ID,
and authorization digest remain unverified coordinates. Matching their shape or digest does not
authenticate a source, establish artifact membership, prove current authorization, or establish a
chain of custody. C authenticates a source assertion only after the separately configured
source/custody trust anchor verifies a canonical statement that exactly binds:

- the complete revalidated FORENSICS-001A Surface and all six provenance-coordinate dimensions;
- the complete FORENSICS-001B custody reference and authorization digest;
- a bounded provider-contract version and immutable object-generation coordinate;
- the exact source-root, artifact-record, provenance-record, artifact digest, and byte-count
  assertions;
- the bounded read-only analysis purpose and validity interval; and
- the statement identity, issue time, signer, and key-lifecycle state.

This establishes that the configured source/custody issuer made the signed historical assertions.
It is not an independent repository read of the source, records, or provider, and it does not by
itself prove legal custody, acquisition completeness, original-author identity, source format, or
global immutability. The C contract records authenticated assertions separately from independently
recomputed facts. Because C opens no raw source or provenance bytes, independent source digest,
size, format, and custody verification remain false. Any future provider-backed independent
verification requires a new versioned contract and explicit source-read authority.

The parser-execution statement must bind the exact current FORENSICS-001B preparation and its
current signed activation and release; current Campaign and exact parser-bound Scope; Graph
Decision, ActionProposal, the exact Capability Grant ID and canonical digest, approved job,
request, target, and normalized parameters; exactly one durable approval-consumption receipt and
one matching consumed ActionPermit; a recomputed allowed Gateway decision and sanitized outcome
whose digest includes the exact Capability Grant digest; the nested authenticated
source-membership attestation, its source/custody signature, and source/custody trust-anchor
digest; one runtime receipt; one strict detached result receipt; and causal execution, receipt,
and statement times.

The runtime receipt binds the exact B sandbox, parser executable, configuration, image,
deployment, non-root identity, immutable read-only no-exec input, read-only root filesystem,
disabled network and DNS, no-new-privileges, disabled core dumps, runtime/confinement identity,
resource ceilings, and observed resource counters. It also binds signed pre/post artifact digest
and byte-count equality, immutable object-generation equality, and zero observed source writes,
copies, evidence mutations, credential and secret access, device and plugin use, lateral movement,
target execution, and shell commands. These are authenticated deployment assertions with narrow
semantics. They are not a proof that no transient mutation occurred outside the attested boundary
or that the source was immutable for its entire custody history.

`ForensicEvidenceAnalysisSandboxRuntimeReceipt` does not duplicate `inputKind`. The loader binds
it transitively by exact reconstruction of the complete B preparation in the signed outer
statement and by requiring the detached result receipt's explicit `inputKind` to agree with that
preparation.

`ForensicEvidenceAnalysisResultReceipt` is a strict digest-only JSON artifact. It directly binds
the exact execution, request, preparation identity and digest, Surface, artifact digest and byte
count, input kind, operation, logical parser, rule set, output schema, external result-body
SHA-256, bounded result byte count, JSON media type, receive time, and one code-owned disposition.
It has no standalone custody fields. Custody agreement is transitive through the receipt's exact
preparation identity and digest, the complete B preparation carried by the signed outer statement,
and cross-document agreement among that preparation, source-membership bundle, and runtime
receipt. It embeds no source, result body, provenance or custody record, path, URI, object key,
filename, case/operator/device/host identifier, personal information, credential, secret, parser
message, stack trace, or caller prose. The result body remains in external custody and is not
opened during admission.

The workflow may derive only a fixed class-owned neutral review signal from a structurally exact
`review` disposition. A valid signature, completed process, parser exit state, media type, result
digest, or review signal does not verify the caller-declared evidence class, source format, parser
correctness, result semantics, a negative security conclusion, or a Finding. A `no-signal`
disposition remains inconclusive.

After all current authority and external evidence checks succeed, C may propose exactly one fixed
neutral `forensics.analysis-observation`, exactly two restricted digest-only Evidence nodes for
the outer signed parser-execution bundle and detached result receipt, and optionally one bounded
open `forensics.forensic-proposition` Hypothesis for the class-owned review signal. The execution
bundle nests the separately signed source/custody attestation, and its outer parser-execution
statement exact-binds that nested statement and signature. No separate source-attestation Evidence
node or reference is created. The sole valid Evidence references are code-owned names derived from
the SHA-256 of the exact file bytes:
`evidence/forensic-evidence-analysis-execution-<bundle-bytes-sha256>.json` and
`evidence/forensic-evidence-analysis-result-receipt-<receipt-bytes-sha256>.json`. A caller-selected
filename or alias cannot enter Graph. Graph prose is code-owned and contains no caller-controlled
or raw forensic content. The Hypothesis identifies only a need for separately authorized
validation of the exact Surface and signal. It does not name or confirm a fact, weakness,
credential, actor, timeline, root cause, exploitability, impact, or Finding.

Admission uses the existing Graph authority, producer registry, event log, and compare-and-set
head. Exact retry revalidates the same bounded metadata evidence and current authority, returns the
prior immutable events, and appends no duplicate. It does not reopen source or result-body bytes,
invoke a provider, dispatch a Tool, create a Worker job, launch a sandbox, execute a parser, or
reuse the consumed Permit.

Successful admission remains `registered-not-authorized`. C creates no source or custody access,
new approval or Permit, Scope expansion, Capability activation, credential use, lateral movement,
evidence mutation, target execution, Replay, Finding, or further execution authority.
FORENSICS-001D owns separately authorized deterministic re-parse or independent-parser comparison,
seeded fixtures, Controls, measurements, and validation floors.

All FORENSICS-001A and FORENSICS-001B serialized false-state markers remain unchanged. C represents
authenticated historical assertions in separate versioned models; it never changes an A/B model
instance to claim verified custody, format, execution, or result truth.

## Consequences

- A compromised or caller-selected parser signer cannot authenticate source custody, and a source
  custodian cannot authenticate parser execution.
- A self-consistent Run root, custody digest, authorization digest, or self-signed evidence bundle
  cannot reach Graph admission.
- A compatible-but-different Capability Grant cannot be substituted because the signed outer
  statement binds its exact ID and canonical digest and the sanitized Gateway outcome binds that
  digest.
- A caller-selected evidence root, filename, or reference alias cannot become a Graph Evidence
  identity; the Gate owns the root and both Evidence references are byte-SHA-256-derived names.
- Repository fixtures can exercise verification behavior without creating a production provider,
  resolver, credential, private key, or runtime claim.
- Deployment without both explicit production trust anchors has no FORENSICS-001C admission path.
- Signed source and runtime statements remain attributable historical assertions. Independent
  byte, format, semantic, or custody truth requires a separately authorized boundary.
- The Graph contains only minimized, restricted, content-addressed evidence references and fixed
  neutral knowledge rather than raw forensic data.
- Historical authorization and execution evidence cannot be reused as a bearer token for another
  source read, parser execution, or Replay.

## Rejected alternatives

### Treat the A Run root or B custody/authorization digest as the trust root

Rejected because these are caller-supplied identity coordinates. They establish neither issuer,
key lifecycle, source membership, current authorization, nor external anchoring.

### Use one trust anchor for source custody and parser execution

Rejected because it collapses independent provenance and execution failure domains. Compromise of
one signer would then manufacture both the input's legitimacy and the parser's execution history.

### Let a statement, evidence root, or caller select a verification anchor

Rejected because attacker-controlled evidence could choose its own signer. Both anchors are
deployment-owned inputs outside the evidence set.

### Treat a valid signature as independent fact verification

Rejected because a signature authenticates the signer and signed bytes, not the truth of source
format, custody history, parser behavior, result semantics, or absence of mutation outside the
attested boundary.

### Admit raw result, source, provenance, or custody data to Graph

Rejected because forensic material can contain evidence, personal information, credentials,
secrets, mutable paths, and private case metadata. Hashing field values is not redaction.

### Infer source form or semantic truth from class, parser, or signal

Rejected because the A class is caller-declared, the B parser is a logical contract, and the C
signal is a bounded review hint. None independently verifies content semantics.

### Reuse the consumed Permit for retry or Replay

Rejected because exact retry is idempotent Graph admission for the same historical execution.
Replay is a new action with separate Scope, approval, Permit, budget, execution, and evidence.

### Ship a repository production provider or production verification key

Rejected because provider selection, credentials, private keys, and operational trust belong to
deployment configuration. Test keys and fixtures are never production authority.

## Compatibility and rollback

FORENSICS-001C is additive. It does not change FORENSICS-001A/B models, Run-integrity wires,
Campaign, Scope, Capability, ToolRequest, approval, ActionPermit, Gateway, Worker, Graph, Replay,
Finding, or benchmark wire versions. It adds no source provider, resolver, production key, parser,
sandbox runtime, credential broker, data migration, or default workflow.

Rollback removes the specialized admission workflow, tests, contract, and this ADR. Already
admitted immutable Graph events and externally retained evidence remain historical records and
require no migration.

## Related documents

- [FORENSICS-001C contract](../graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md)
- [FORENSICS-001B](../capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md)
- [FORENSICS-001A](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0016](0016-tamper-evident-run-integrity.md)
- [ADR-0131](0131-authenticate-sealed-action-results-before-oracle.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
