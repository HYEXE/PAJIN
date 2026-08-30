# CRYPTO-001C: Oracle-recomputed Cryptographic Analysis Knowledge Admission

- Status: Implemented, neutral Observation and optional bounded open Hypothesis
- API versions:
  - `pajin.dev/cryptographic-misuse-analysis-execution-trust-anchor/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-result-receipt/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-oracle-policy/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-oracle-verdict/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-execution-statement/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-execution-bundle/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-knowledge-candidate/v1alpha1`
  - `pajin.dev/cryptographic-misuse-analysis-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/cryptographic_misuse_analysis_admission.py`
- Decision: [ADR-0242](../adr/0242-admit-cryptographic-analysis-knowledge-without-semantic-or-key-authority.md)

## Purpose

CRYPTO-001C admits one neutral `cryptography.analysis-observation` after rechecking an already
approved, Permit-bound, deployment-produced CRYPTO-001B offline analysis. A code-owned structural
Oracle recomputes whether the strict result-receipt metadata is internally consistent with the
exact CRYPTO-001B preparation. A `review` disposition may additionally produce one bounded open
`cryptography.misuse-weakness` Hypothesis.

The workflow adds no artifact resolver, analyzer, sandbox runtime, Worker, key store, KMS, HSM,
PKCS#11 client, protocol client, cryptographic primitive, result-body reader, semantic misuse
detector, or Finding producer beyond the Ed25519 verification used only for provenance. CRYPTO-001A
Surfaces remain `registered-not-authorized`, and
CRYPTO-001B remains preparation-only. Historical execution records authorize no subsequent
artifact access, Capability/external Oracle invocation, Replay, or execution.

## Deployment-owned source and trust

`CryptographicMisuseAnalysisObservationSourceInputs` supplies a bounded evidence root, one
execution-attestation reference, the expected Run, current activation, current Campaign, the
exact CRYPTO-001B preparation, and an approved `CapabilityGraphCampaignJobInput`. The signed
statement names the second evidence file, a detached result receipt. The admission gate receives
its `CryptographicMisuseAnalysisExecutionTrustAnchor` separately through deployment
configuration; source files cannot select or replace it.

The trust anchor binds the exact CRYPTO-001B sandbox, code-backed Capability, signed release,
trust domain, issuer, and a uniquely ordered Ed25519 keyring with exactly one active key. It is
verification-only. It does not bind a current activation or Campaign and grants no approval,
Permit, artifact access, sandbox invocation, Graph admission, or execution authority.

A valid signature proves only that the configured issuer signed the statement and that the
statement has not changed. Repository code does not independently inspect a custody system,
authorization document, analyzer executable, image registry, process identity, mount table,
network namespace, seccomp profile, cgroup, or running sandbox.

## Signed completed execution

`CryptographicMisuseAnalysisExecutionBundle` carries a canonical execution statement and a
detached Ed25519 signature. The statement binds:

- the trust domain, issuer, sandbox binding, and deployment;
- the current Campaign and Run;
- the rebuilt CRYPTO-001B preparation and exact GET analysis request;
- request and normalized-parameter identities;
- one consumed `ActionPermit` and one durable approval-consumption receipt;
- a recomputable allowed Gateway decision and sanitized outcome digest;
- one content-addressed `CryptographicMisuseAnalysisSandboxRuntimeReceipt`;
- a detached result-receipt path, file digest, receipt identity, and content digest; and
- execution start, finish, statement issue, and runtime-attestation times.

The statement records one request and one artifact read. Network requests, DNS queries, artifact
writes, host-filesystem reads, credential reads, key-material reads, key-store sessions,
cryptographic operations, key searches, protocol negotiations, Capability Oracle invocations,
plaintext outputs, key-material outputs, target-process executions, and shell commands are zero.
It cannot authorize another artifact read, sandbox invocation, Worker selection, Oracle call,
Replay, Graph write, Finding, or execution.

## Runtime receipt

The sandbox runtime receipt binds the exact Surface, input kind, rule set, operation, logical
analyzer, analyzer-executable digest, sandbox-image digest, deployment, non-root identity,
artifact digest and byte count, custody binding and authorization-document digest, resource
ceilings, runtime-identity digest, confinement digest, and attestation time.

The configured deployment asserts that custody authorization, artifact digest, artifact read,
analyzer executable, sandbox image, non-root confinement, disabled network and DNS, read-only
root, read-only no-exec artifact mount, no-new-privileges, resource limits, and disabled core
dumps were verified. These are signed historical assertions, not a fresh repository inspection or
new artifact-access authority. The receipt embeds no raw identity metadata, artifact, key,
plaintext, or configuration.

## Strict detached result receipt

`CryptographicMisuseAnalysisResultReceipt` is a strict digest-only JSON manifest. It binds the
execution, request, preparation, input kind, operation, analyzer, exact rule set, exact Surface,
artifact digest and byte count, fixed output schema, result-body digest, bounded result byte
count, JSON media type, receive time, and one `resultDisposition` value:

- `review`; or
- `no-signal`.

The receipt contains no caller-selected signal. It embeds no result body, artifact, artifact path,
key or key reference, ciphertext, plaintext, configuration, parameter, credential, rule, or
plugin supplied by the caller. The exact code-owned rule-set reference remains metadata only.
`resultBodySha256` is a declared content identity for externally retained bytes; neither
the loader nor the structural Oracle opens those bytes. A receipt does not establish semantic
result correctness, misuse, a negative security claim, a Finding, or execution authority.

## Workflow-owned structural Oracle

`CryptographicMisuseAnalysisOraclePolicy` is code-owned and content-addressed. It binds the exact
CRYPTO-001B rule-set reference, four-row Surface-to-signal map, and output schema. It permits no
caller decision, artifact read, result-body read, key-material access, cryptographic operation,
semantic truth, Finding, or execution.

`recompute_cryptographic_misuse_analysis_oracle_verdict` is a pure metadata function. It
canonicalizes the current preparation and detached receipt, then recomputes their exact agreement
over:

- Surface class and complete CRYPTO-001A reference;
- B Surface/input/digest/operation/analyzer mapping;
- rule-set identity and code-owned signal vocabulary;
- custody binding, authorization digest, artifact digest, and byte count;
- fixed output schema and output-size ceiling; and
- result-receipt identity, result-body digest declaration, and result byte count.

It reads neither the artifact nor the result body, accesses no key, performs no cryptographic
operation, and invokes no Capability Oracle. The caller supplies only `resultDisposition`; the
Oracle derives the remaining result deterministically:

| Surface class | `review` signal | Oracle disposition |
| --- | --- | --- |
| protocol | `cryptography.protocol-policy` | `structurally-consistent-review` |
| key usage | `cryptography.key-usage-policy` | `structurally-consistent-review` |
| ciphertext | `cryptography.ciphertext-structure` | `structurally-consistent-review` |
| configuration | `cryptography.configuration-policy` | `structurally-consistent-review` |

For every Surface class, `no-signal` derives no review signal and produces
`inconclusive-no-signal`. Neither Oracle disposition is a semantic verdict. In particular,
`structurally-consistent-review` does not confirm misuse, and `inconclusive-no-signal` does not
support a negative security conclusion.

## Current authority revalidation

Before Graph lineage registration, the loader:

1. rebuilds the exact CRYPTO-001B preparation using the current activation, release, Campaign,
   Surface, operation, custody and sandbox bindings, request, and agent identity;
2. rechecks the Graph Decision, ActionProposal, Capability Grant, approval, exact request,
   preparation digest, and activation-set identity;
3. resolves exactly one matching consumed ActionPermit and one durable approval-consumption
   receipt from the existing SQLite authority store;
4. recomputes the Gateway decision from the current Campaign, Grant, request, and network-disabled
   Cryptographic Tool specification;
5. verifies the deployment-configured trust anchor, key lifecycle, Ed25519 signature, runtime
   receipt, result receipt, and sanitized Gateway outcome;
6. checks exact Surface lineage, custody, artifact digest and size, rule set, operation, analyzer,
   executable, image, non-root identity, resource ceilings, causal timing, zero-live/key/crypto
   budgets, detached paths, file digests, receipt identities, and source-root digest; and
7. recomputes the workflow-owned structural Oracle verdict from the canonical preparation and
   result receipt.

The loader never invokes the Tool, resolves custody, reads artifact or result-body bytes,
validates cryptographic semantics, launches a sandbox, calls a Worker, accesses a network or key
service, or creates another Permit.

## Observation and Evidence

The Observation proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `cryptography.analysis-observation` with confidence `1.0` and fixed neutral
  prose;
- two restricted `Evidence` nodes for the signed execution bundle and detached result receipt;
- one `produces` edge; and
- two `supported-by` edges.

The workflow-owned Oracle verdict is not a third caller-supplied Evidence file. Its policy and
verdict digests are bound into the source-root digest, candidate, Observation value digest, and
proposal identity. The value digest also binds the exact preparation, Surface, artifact digest,
operation, input kind, analyzer, rule set, output schema, request, approval receipt, trust anchor,
signed statement, Gateway outcome, runtime and confinement receipts, result receipt and declared
body digest, result bytes, disposition, derived signal, and source-root digest.

Graph prose contains no raw artifact or result, key, key reference, ciphertext, plaintext,
configuration, protocol parameter, path, credential, rule detail, cryptographic conclusion,
misuse statement, or negative conclusion.

## Bounded open Hypothesis

A `review` disposition derives exactly one class-owned review signal and may create one
agent-derived, confidence `0.5`, open `cryptography.misuse-weakness` Hypothesis. One `enables` edge
connects the neutral Observation to that Hypothesis. Fixed text states only that structurally
consistent metadata carries a bounded review signal and that a separately authorized future
re-analysis must evaluate the same signal for the exact Surface and artifact digest.

A `no-signal` disposition creates no Hypothesis and no negative conclusion. No Hypothesis names
or confirms misuse, an insecure algorithm or parameter, a key relation, exploitability, impact,
or a Finding.

## Existing writer and exact retry

The gate requires a current non-empty Graph Snapshot, the exact existing
`GraphAdmissionAuthority`, its SQLite event log, and its trusted-lineage registry. Observation
admission uses compare-and-set against the bound current head. An optional Hypothesis must
immediately follow the Observation; intervening Graph activity fails closed.

Both proposals are content-addressed. Exact retries reopen and revalidate the same two bounded
evidence files, current authority, and pure structural Oracle before returning prior events. They
append no duplicate Graph event and perform no artifact/result-body read, Tool or external
Gateway dispatch, sandbox/Worker execution, Capability/external Oracle call, network/key access,
or target-domain cryptographic operation beyond provenance-signature verification. CRYPTO-001C
adds no Cryptography-specific Graph store or writer.

## Explicit non-authority

Candidates remain `sealed-knowledge-not-admitted`; successful admissions become
`registered-not-authorized`. Candidate and admission artifacts fix all of the following to false:

- raw artifact, analysis output, key, key reference, ciphertext, plaintext, and configuration
  embedding;
- artifact-format, configuration-value, runtime-support, dependency, semantic-misuse,
  vulnerability, Hypothesis-confirmation, negative-security-claim, and Finding authority;
- artifact mutation, Scope expansion, Capability activation, approval, and Permit issuance;
- artifact or custody access, sandbox invocation, Worker selection, network or DNS access;
- key-material or credential access, cryptographic operations, key search, protocol negotiation,
  and a new Oracle invocation;
- plaintext or key-material output, target execution, debugger attach, Replay, and further
  execution.

Signed execution provenance, a structurally consistent verdict, a neutral Observation, and an
open Hypothesis are knowledge only. None can be converted into action authority.

## Fail-closed behavior

Admission rejects absent, changed, oversized, multiply linked, non-JSON, duplicate-key, or
path-invalid evidence; signature, issuer, key lifecycle, trust-anchor, Campaign, activation,
Scope, preparation, Decision, Proposal, Grant, approval, Permit, request, target, normalized
parameters, custody, authorization digest, artifact digest or size, Surface lineage, input kind,
rule set, operation, analyzer, executable, image, deployment, run-as identity, resource ceiling,
timing, zero budget, output schema, result receipt, disposition, Oracle policy, Oracle verdict, or
digest substitution; class/signal confusion; missing or ambiguous Permit or approval records;
stale Graph heads; Graph authority substitution; proposal/event drift; extra model-instance state;
true authority markers; and boolean or integer coercion.

## Compatibility and rollback

CRYPTO-001C is additive and explicitly imported. CRYPTO-001A/B, the fixed CTF XOR Capability,
Campaign, Scope, Capability, ToolRequest, approval, ActionPermit, DOMAIN-002/004, Worker, Graph,
Replay, Finding, and benchmark wires retain their versions. No artifact resolver, analyzer,
sandbox runtime, key service, result-body reader, or data migration is added.

Rollback removes the specialized workflow, tests, this contract, and ADR-0242. Already admitted
immutable Graph events and deployment-owned evidence require no migration. New result
dispositions, signal mappings, output semantics, semantic Oracles, key access, cryptographic
operations, or runtime behavior require a new versioned contract instead of silent expansion.

## Verification requirements

Focused verification must cover all four Surface-to-review-signal routes, all four no-signal
routes, both Oracle dispositions, neutral-only admission, optional open Hypothesis admission,
exact retry, signature and detached-receipt tampering, key lifecycle, missing or substituted
Permit and approval identities, recomputed Gateway policy, current Scope drift, result overflow,
Surface/parent/input/rule/operation/analyzer/custody/artifact/executable/image/run-as substitution,
runtime and resource ceilings, zero key/credential/crypto/Oracle channels, Oracle policy and
verdict recomputation, class/signal confusion, evidence paths and source-root identity, stale Graph
heads, producer registration, Graph cardinality, raw/semantic/negative-claim/authority escalation,
integer and boolean coercion, and forged nested model state.

CRYPTO-001D remains responsible for separately authorized independent implementation replay,
seeded vector Ground Truth, disposable offline fixtures, Controls, metrics, and validation floors.
