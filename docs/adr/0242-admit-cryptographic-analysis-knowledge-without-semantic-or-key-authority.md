# ADR-0242: Admit Cryptographic Analysis Knowledge without Semantic or Key Authority

## Status

Accepted

## Context

CRYPTO-001A defines content-free protocol, key-usage, ciphertext-digest, and sanitized-
configuration Surfaces. CRYPTO-001B binds one exact Surface to a signed, read-only,
network-disabled offline-analysis preparation, code-owned rule vocabulary, immutable custody
coordinate, and bounded sandbox configuration. It deliberately provides no artifact resolver,
analyzer runtime, Worker, result, conclusive Capability Oracle, Observation, Evidence, or Graph
authority.

PAJIN needs to admit bounded knowledge from an analysis that a deployment separately approved and
completed. Treating the B preparation as execution evidence, accepting an unsigned result,
opening target-controlled result bodies inside Graph admission, trusting a caller-selected signal,
or interpreting structural metadata as cryptographic truth would violate current authority,
privacy, provenance, and single-writer boundaries.

The existing fixed single-byte XOR lab is not a general answer. Its inline ciphertext, fixed key
search, plaintext and key output, Worker command, and host recomputation Oracle are
scenario-specific powers that CRYPTO-001C must not inherit.

## Decision

Add a CRYPTO-001C source-verification and Graph-admission boundary in
`src/pajin/workflow/cryptographic_misuse_analysis_admission.py`. Do not add a repository-owned
artifact reader, misuse analyzer, sandbox runtime, Worker, key service, cryptographic operation,
semantic result interpreter, or Finding producer. Detached Ed25519 provenance verification is the
only cryptographic primitive added and grants no target-domain key-use or analysis authority.

Require an external deployment to provide exactly two detached JSON evidence files:

1. an Ed25519-signed `CryptographicMisuseAnalysisExecutionBundle`; and
2. a strict digest-only `CryptographicMisuseAnalysisResultReceipt` named by the signed statement.

Configure `CryptographicMisuseAnalysisExecutionTrustAnchor` when constructing the admission gate.
Source inputs cannot provide or override it. Bind the anchor to the exact CRYPTO-001B sandbox,
code-backed Capability, release, trust domain, issuer, and a uniquely ordered Ed25519 keyring with
exactly one active key. Treat the anchor as verification-only, not current activation, Campaign,
approval, Permit, artifact access, sandbox, Graph, or execution authority.

Require the signed statement to bind the current Campaign and Run, rebuilt CRYPTO-001B
preparation and GET request, consumed ActionPermit, durable approval-consumption receipt,
recomputable Gateway decision, content-addressed sandbox-runtime receipt, execution window, and
detached result receipt. Require the runtime receipt to match the exact Surface, input kind,
custody and authorization digest, artifact digest and size, rule set, operation, analyzer,
executable and image digests, deployment, non-root identity, and resource ceilings.

The deployment statement must record exactly one request and one artifact read. Network, DNS,
artifact write, host-filesystem, credential, key-material, key-store, cryptographic-operation,
key-search, protocol-negotiation, Capability Oracle, plaintext-output, key-output, target-process,
and shell-command counts remain zero. Signed runtime assertions cover authorization, digest and
read completion, exact executable and image, non-root confinement, disabled network and DNS,
read-only root, read-only no-exec artifact mount, no-new-privileges, resource ceilings, and
disabled core dumps. Repository verification establishes statement origin and integrity; it does
not independently inspect those deployment conditions.

Accept only `review` or `no-signal` as `resultDisposition`. The result receipt contains no
caller-supplied signal and no raw output. It binds exact execution, request, preparation, Surface,
input kind, rule set, operation, analyzer, artifact digest and byte count, output schema, declared
result-body digest, bounded result bytes, and receive time.

Register a workflow-owned `CryptographicMisuseAnalysisOraclePolicy`. Its pure structural Oracle
must canonicalize the current preparation and result receipt and recompute their exact agreement
without reading the artifact or result body, accessing a key, performing a cryptographic
operation, or invoking the CRYPTO-001B Capability Oracle. Bind the policy to the exact B rule set,
output schema, and four fixed Surface-to-signal rows.

Derive the Oracle verdict rather than accepting it from the caller:

- `review` on protocol derives `cryptography.protocol-policy`;
- `review` on key usage derives `cryptography.key-usage-policy`;
- `review` on ciphertext derives `cryptography.ciphertext-structure`;
- `review` on configuration derives `cryptography.configuration-policy`; and
- `no-signal` on any class derives no signal.

A derived review signal produces `structurally-consistent-review`. No signal produces
`inconclusive-no-signal`. Both verdicts describe structural metadata only. The first does not
confirm misuse; the second does not support a negative security claim.

Rebuild current B authority, resolve exactly one consumed Permit and one durable approval receipt,
recompute Gateway policy, verify the configured signature and both evidence files, then recompute
the structural Oracle before registering Graph lineage.

Construct one Observation proposal containing exactly one succeeded Action, one target-derived
`cryptography.analysis-observation`, two restricted Evidence nodes, one `produces` edge, and two
`supported-by` edges. Bind the Oracle policy and verdict digests into the content-addressed source
root, Observation value, candidate, and proposal. The verdict is recomputed state, not a third
caller-supplied evidence file.

Permit an optional confidence `0.5`, agent-derived, open `cryptography.misuse-weakness`
Hypothesis only for a derived review signal. It must use fixed class-specific text and one
`enables` edge, and require separately authorized future re-analysis of the same Surface and
artifact digest. `no-signal` creates no Hypothesis and no negative conclusion.

Submit the Observation and, when present, immediately following Hypothesis through the existing
`GraphAdmissionAuthority` with compare-and-set heads. Exact retries return prior immutable events
after revalidating the same two bounded evidence files, current authority, and pure structural
Oracle. They append no duplicate event and invoke no Tool or external Gateway dispatch,
sandbox/Worker execution, Capability/external Oracle, network, key service, or cryptographic
operation beyond provenance-signature verification.

## Consequences

- CRYPTO-001C proves that the configured deployment signed one bounded completed execution and
  that its strict result manifest is structurally consistent with current B authority.
- The workflow-owned Oracle is deterministic and caller-independent, but it is not an independent
  analyzer, semantic Oracle, replay, or cryptographic truth source.
- The result-body digest remains a declaration. Neither the loader nor Oracle opens the result
  body or validates the analysis semantics behind it.
- Deployment assertions about custody, digest verification, executable identity, and sandbox
  confinement are authenticated historical provenance, not live repository attestation.
- A bounded review signal motivates only an open Hypothesis. It establishes no protocol-policy,
  key-usage, ciphertext, configuration, weakness, vulnerability, impact, or Finding truth.
- `inconclusive-no-signal` is not evidence of safety or absence of misuse.
- Raw artifacts, outputs, keys, ciphertext, plaintext, configuration, and parameters remain under
  external custody and outside Graph prose.
- Scope, Capability, approval, Permit, artifact or custody access, sandbox or Worker invocation,
  network, DNS, credential or key use, cryptographic operation, key search, protocol negotiation,
  Oracle invocation, plaintext or key output, mutation, Replay, Finding, and further execution
  authority remain false.
- CRYPTO-001D owns separately authorized independent implementation replay, seeded vectors,
  Controls, Ground Truth, fixtures, metrics, and validation floors.

## Rejected alternatives

### Treat CRYPTO-001B preparation as execution evidence

Rejected because preparation performs no authorization verification, artifact read, sandbox
attestation, analyzer invocation, result sealing, or Graph admission.

### Accept a caller-selected review signal or Oracle verdict

Rejected because a caller could relabel a Surface or turn arbitrary output into an apparent
security claim. The caller supplies only `review` or `no-signal`; code derives the class-specific
signal and structural disposition from the exact B mapping and rule set.

### Read and interpret the result body during admission

Rejected because analyzer output is target-controlled and may be sensitive, malformed, large, or
semantically wrong. Digest-only external custody preserves lineage without making admission a
parser, detector, or data-exposure path.

### Call the CRYPTO-001B Success Oracle

Rejected because that registered role is intentionally `INCONCLUSIVE`, and B grants zero Oracle
invocations. CRYPTO-001C recomputes only metadata consistency in a separate workflow-owned policy;
it does not mutate the Capability authority set.

### Reuse the single-byte XOR host Oracle

Rejected because that Oracle searches a fixed key space and validates recovered plaintext for one
synthetic lab. Reuse would silently import key search, plaintext/key output, and scenario-specific
truth into general Cryptographic analysis.

### Treat structural consistency as semantic correctness

Rejected because matching Surface, rule, custody, and digest declarations cannot establish that
the external analyzer parsed bytes correctly or that a cryptographic weakness exists. Independent
semantic reproduction belongs to CRYPTO-001D and later Finding policy.

### Treat `no-signal` as a negative conclusion

Rejected because the structural Oracle does not inspect result-body semantics, verify coverage,
or measure false negatives. `inconclusive-no-signal` deliberately remains inconclusive.

### Add a Cryptography-specific Graph writer

Rejected because the existing writer already enforces registered producer identity, trusted
lineage, stale-head checks, append-only events, and exact retry semantics.

## Compatibility and rollback

CRYPTO-001C is additive and explicitly imported. Existing CRYPTO-001A/B, the fixed CTF XOR
Capability and runtime, Campaign, Scope, Capability, ToolRequest, approval, ActionPermit,
DOMAIN-002/004, Worker, Graph, Replay, Finding, and benchmark wires retain their versions. No
artifact, result-body, key-service, analyzer, sandbox-runtime, or data migration is introduced.

Rollback removes the specialized workflow, tests, graph contract, and this ADR. Deployment-owned
evidence and already admitted immutable Graph events require no migration. A future semantic
Oracle, new disposition, signal mapping, key access, cryptographic operation, analyzer runtime, or
independent replay requires a new versioned contract rather than silent expansion.

## Related documents

- [CRYPTO-001C contract](../graph/CRYPTO-001C-oracle-recomputed-cryptographic-analysis-knowledge-admission.md)
- [CRYPTO-001B](../capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md)
- [CRYPTO-001A](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0018](0018-bounded-ctf-crypto-artifacts.md)
- [ADR-0240](0240-type-cryptographic-analysis-surfaces-without-key-use-authority.md)
- [ADR-0241](0241-bind-offline-cryptographic-misuse-analysis-without-key-use-or-artifact-access-authority.md)
