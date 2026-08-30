# CRYPTO-001B: Offline Cryptographic Misuse-analysis Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.cryptography.offline-misuse-analysis@1.0.0`
- Tool: `cryptography.offline-misuse-analysis@1.0.0`
- Binding API: `pajin.dev/cryptographic-misuse-analysis-binding/v1alpha1`
- Activation API: `pajin.dev/cryptographic-misuse-analysis-capability-activation-set/v1alpha1`
- Preparation API: `pajin.dev/cryptographic-misuse-analysis-preparation/v1alpha1`
- Custody API: `pajin.dev/cryptographic-analysis-artifact-custody-binding/v1alpha1`
- Sandbox API: `pajin.dev/cryptographic-misuse-analysis-sandbox-binding/v1alpha1`
- Request API: `pajin.dev/cryptographic-misuse-analysis-request/v1alpha1`
- Rule-set API: `pajin.dev/cryptographic-misuse-rule-set/v1alpha1`
- Output schema: `pajin.cryptography.offline-misuse-analysis-result.v1`
- Authority: `src/pajin/capabilities/cryptographic_misuse_analysis.py`
- Decision: [ADR-0241](../adr/0241-bind-offline-cryptographic-misuse-analysis-without-key-use-or-artifact-access-authority.md)

## Purpose

CRYPTO-001B binds one complete CRYPTO-001A typed Surface to a complete signed read-only CAP-002
Capability, the current Campaign Scope, a code-classified content-addressed input-custody record
and externally supplied authorization-document digest, one class-owned logical analyzer, an exact
code-owned rule vocabulary, the existing minimum Cryptography Worker profile, bounded resources,
and a configuration-only offline sandbox requirement. It stops at `PreparedCapabilityAction`.

The adapter produces a secret-free request description only. It does not resolve, read, mount, or
parse artifact bytes; verify declaration sanitization, authorization, custody, digest, or byte
count; select or attest a sandbox or Worker; materialize a Worker job; execute an analyzer;
access or use a key or credential; perform encryption, decryption, signing, verification, key
search, protocol negotiation, or Oracle invocation; normalize a result; or produce an
Observation, Evidence, Graph admission, Hypothesis, or Finding.

## Capability and signed activation

The Capability is experimental, T2, `READ_ONLY`, network-disabled, approval-required, and costs
one request unit. Its complete CAP-002 authority set contains materializer, action compiler,
executor adapter, result normalizer, success Oracle, Replay strategy, and cleanup handler roles.
Activation accepts only an externally signed current Range release resolved through the existing
Capability lifecycle registry.

Materialization validates the exact request schema. Worker materialization and result
normalization fail closed because CRYPTO-001B contains no analyzer runtime. The success Oracle
returns `INCONCLUSIVE`, and Replay and cleanup return no plan. These registered roles complete the
authority contract without claiming that execution support exists.

The static binding pins:

- all four CRYPTO-001A locator classes and their exact registry identity;
- the complete code-backed CAP-001/CAP-002 identity;
- a local exact Cryptography Domain classification;
- the existing exact DOMAIN-004 Cryptography Worker profile;
- the code-owned rule-set identity, operation set, analyzer set, input-kind set, and output schema;
  and
- requirements for current activation, exact Scope, approval, one-use ActionPermit, Gateway
  policy re-entry, externally verified custody, an offline sandbox, and zero live channels.

The local classification deliberately leaves the established global DOMAIN-003 inventory
unchanged. Adding this Capability to that fixed inventory requires its own explicit versioned
registry update; the local binding is not an implicit inventory migration.

## Surface-owned operation and input mapping

The caller supplies an exact complete typed Surface and the requested operation. The operation,
input kind, artifact digest meaning, and analyzer are then derived from the Surface class and
cannot be selected independently.

| Surface class | Input kind | Operation | Logical analyzer | Bound digest |
| --- | --- | --- | --- | --- |
| `protocol` | `sanitized-protocol-declaration` | `protocol-declaration-read` | `protocol-declaration-analyzer` | protocol declaration SHA-256 |
| `key-usage` | `sanitized-key-usage-declaration` | `key-usage-declaration-read` | `key-usage-declaration-analyzer` | key-usage declaration SHA-256 |
| `ciphertext` | `ciphertext-artifact` | `ciphertext-structure-read` | `ciphertext-structure-analyzer` | ciphertext artifact SHA-256 |
| `configuration` | `sanitized-configuration-declaration` | `configuration-declaration-read` | `configuration-declaration-analyzer` | configuration declaration SHA-256 |

An analyzer name is a logical request contract, not an executable implementation or detection
claim. A key-usage Surface remains a declaration without key identity or material. In particular,
the `decryption` usage kind does not authorize a decryption operation. A ciphertext operation is
limited to future opaque structure inspection and does not authorize plaintext recovery, key
search, or an Oracle.

The declaration input kinds retain CRYPTO-001A's caller-supplied digest limitation. The word
`sanitized` describes the externally retained input expected by a future deployment; preparation
does not inspect the digest preimage and fixes declaration-sanitization verification to false.

## Code-owned rule and signal vocabulary

`pajin.cryptography.misuse-rules.baseline@1.0.0` is an exact content-addressed rule-set identity.
It binds the sorted Surface class, locator kind, input kind, digest source, operation, and analyzer
mapping and exactly four future neutral signal kinds:

- `cryptography.protocol-policy`;
- `cryptography.key-usage-policy`;
- `cryptography.ciphertext-structure`; and
- `cryptography.configuration-policy`.

The caller cannot select or inject a rule, plugin, command, or alternate signal vocabulary.
Rule-set registration does not make an analyzer runtime available and does not confirm misuse or
grant Finding or execution authority. CRYPTO-001C must define any admitted result vocabulary and
its Evidence semantics separately.

## Artifact custody and authorization-reference boundary

`CryptographicAnalysisArtifactCustodyBinding` is content-addressed configuration. The caller
supplies only the exact Surface, authorization-document digest, and declared byte count. The
builder binds:

- the complete exact typed Surface and class-derived input kind;
- the code-owned `pajin.cryptography.immutable-analysis-artifact-custody` authority class;
- an artifact-object identifier derived exactly from the class-derived artifact digest;
- an authorization-reference identifier derived exactly from the supplied lowercase SHA-256
  authorization-document digest;
- the class-derived declaration or artifact SHA-256; and
- a declared byte count from 1 through 536,870,912 bytes.

The derived identifiers cannot carry independent caller text and therefore cannot smuggle a key
alias, KMS/HSM/PKCS#11 coordinate, credential, JWT, path, or URL. The binding contains no raw
declaration, configuration, ciphertext, plaintext, key, key handle, key reference, certificate,
JWK, password, PIN, seed, cryptographic parameter, endpoint, command, or plugin.

The authorization reference is not proof. Preparation does not verify its issuer, signature,
freshness, Scope, object existence, digest, byte count, or declaration sanitization. The supplied
authorization SHA-256 is an identity coordinate, not secret redaction or proof of safe content.
Preparation does not
resolve or read the object or materialize a mount. Those checks remain deployment-owned future
runtime and admission requirements.

The public custody reference carries every variable claim needed to recompute the originating
binding digest. Mutating the Surface, input kind, derived coordinate, authorization digest,
artifact digest, or byte count cannot retain the same identity. A newly recomputed configuration
is still not authorization.

## Configuration-only offline sandbox boundary

`CryptographicMisuseAnalysisSandboxBinding` pins the code-owned deployment coordinate
`deployment:cryptographic-misuse-analysis`, the complete Surface, class-derived operation and
analyzer, exact rule-set reference, exact analyzer-executable and sandbox-image SHA-256 digests,
the code-owned non-root service identity `svc:pajin-crypto-analyzer`, the fixed read-only no-exec
`/pajin/input/artifact` mount target, `bounded-json-stdout`, the fixed output schema, and artifact,
output, runtime, memory, and process ceilings. Neither deployment nor runtime identity accepts
caller text, so those fields cannot carry a secret, key reference, credential, path, endpoint, or
privileged identity.

It also pins the exact existing DOMAIN-004 Cryptography profile:

- Domain: `cryptography`;
- network: `disabled-by-default`;
- filesystem: `read-only-artifact`;
- credentials: `none`;
- runtime: `offline-sandbox`;
- identity dimensions: `analyzer`, `artifact-digest`; and
- budget dimensions: `artifact-bytes`, `runtime`.

The binding requires network and DNS disabled, a read-only root filesystem, a read-only no-exec
artifact mount, no-new-privileges, non-root execution, disabled core dumps, and exact executable,
image, and rule-set digests. Host filesystem access, credentials, key injection, inherited
environment, symlink traversal, devices, plugins, shell commands, raw result echo, key or
credential use, cryptographic operations, key search, protocol negotiation, and Oracle invocation
are forbidden.

This is deployment configuration, not attestation or selection. Runtime availability,
conformance, sandbox selection, Worker selection, artifact read authority, mount materialization,
and execution authority remain false. The public reference binds the exact code-owned deployment
and runtime identities plus every profile, Surface, rule-set, analyzer, digest, output, and
resource claim into its content identity.

## Request and zero-live-channel budget

`BoundedCryptographicMisuseAnalyzerAdapter.prepare_request` requires exact agreement among the
complete Surface, custody binding, sandbox binding, input kind, operation, analyzer, artifact
digest, rule set, and ceilings. The output is one `CryptographicMisuseAnalysisRequest` with an
exact non-routable Surface target, `GET`, the fixed output schema, and complete secret-free
references.

The budget binds one request, the declared artifact bytes, and the sandbox's output, runtime,
memory, and process ceilings. The following dimensions are fixed to zero:

- network requests and DNS queries;
- host-filesystem reads and artifact writes;
- credential reads, key-material reads, and key-store sessions;
- cryptographic operations, key-search attempts, protocol negotiations, and Oracle invocations;
- plaintext and key-material outputs; and
- target-process executions and shell commands.

The budget is attenuation-only and unreserved. Unknown fields, boolean-to-integer coercion, and
attempts to raise a zero dimension fail closed. The request cannot embed raw content, a path,
credential, key reference, cryptographic parameter, rule, plugin, CTF challenge, recovered key,
plaintext, runtime admission, or execution marker.

## Campaign Scope and preparation

Preparation requires the exact non-routable token
`https://cryptography-scope.pajin.invalid/surfaces/<surface-id>` in the current Campaign allow
rules. Wildcard coverage is insufficient, any matching deny rule rejects preparation, and `GET`
must be present in Rules of Engagement. The Campaign private-network flag is retained in the
projection but cannot raise the request's zero network or DNS budget.

`prepare_cryptographic_misuse_analysis` revalidates the signed activation, release, registered
binding, Campaign, exact Surface, exact Scope token, custody and sandbox identities, operation,
analyzer, rule set, request, and ceilings. It emits a content-addressed
`CryptographicMisuseAnalysisPreparation` whose normalized parameters contain only the bounded
request description and whose state is `prepared-not-authorized`.

Preparation does not satisfy approval, issue a Permit, authorize Gateway dispatch, select a
Worker, reserve a budget, resolve or read an artifact, verify authorization or sanitization,
select or attest a sandbox, access a key or credential, perform a cryptographic operation, invoke
an Oracle, make a network request, run analysis, mutate an artifact, or produce Observation,
Evidence, Graph knowledge, Hypothesis, or Finding.

Actual execution would still require current Policy and Approval, a one-use ActionPermit,
Gateway policy re-entry, deployment verification of custody authorization, immutable byte
resolution and digest/size checks, exact image and executable admission, live non-root offline
sandbox attestation, read-only mount materialization, bounded output custody, and a separately
reviewed result-admission contract. None is implemented by CRYPTO-001B.

## Fail-closed behavior

Definitions, references, local Domain classification, static binding, activation, rule set,
custody, sandbox, Campaign projection, request, and preparation are exact or content-addressed
values. Public boundaries serialize and revalidate exact nested model instances and recursively
reject unmodeled state before trusting content identity.

Public accessors return deep copies of private cached canonical registrations. Even in-process
mutation using Python mechanisms that bypass frozen-model setters cannot poison the next rule-set,
Capability Definition, local classification, or static-binding lookup.

Resolution and preparation reject Surface class or lineage substitution, operation/analyzer/input
substitution, rule-set or Worker-profile substitution, artifact/authorization/image/executable
digest drift, deployment or runtime-identity substitution, ceiling drift, missing exact Scope, a
matching deny rule, absent GET, stale release, target/method/Tool drift, sensitive or operational
field injection, true authority markers, and boolean or integer coercion.

## Existing CTF asset boundary

The existing `pajin.ctf.crypto-single-byte-xor@1.0.0` Capability remains independent. CRYPTO-001B
does not import its inline ciphertext contract, logical artifact URL, fixed key-search loop,
Worker command, recovered key/plaintext output, challenge vocabulary, or host recomputation
Oracle. Its Tool ID, request schema, runtime, output, and authority set are not aliases for this
Capability. The lab remains evidence that one bounded CTF scenario works, not evidence of general
cryptographic misuse-analysis support.

## Observation, Replay, and benchmark boundary

A prepared request proves neither that the input exists nor that analysis occurred. CRYPTO-001C
must separately verify one authorized sealed offline result and its independent Oracle or
recomputation provenance before admitting neutral resource/policy/structure Observation and
Evidence or a bounded Hypothesis. It must not treat a signal as a confirmed vulnerability or
Finding.

CRYPTO-001D owns independent implementation replay, seeded vector Ground Truth, disposable
offline fixtures, metrics, and validation floors. CRYPTO-001B creates no execution, result,
Oracle, recomputation, Ground Truth, Control, benchmark Result, or measurement.

## Compatibility, migration, and rollback

The implementation is additive. CRYPTO-001A, the fixed CTF XOR Capability, existing Capability
and Tool registries, the global DOMAIN-003 inventory, the DOMAIN-004 profile registry, discovery,
Artifact readers, Scope, Worker, Graph, and runtime wire formats remain unchanged. No artifact
reader, cryptographic parser, analyzer, key store, KMS/HSM/PKCS#11 client, credential broker,
sandbox deployment, Worker runtime, network route, or data migration is added.

Rollback removes the additive module, tests, contract, ADR, and documentation links. Existing
typed Surfaces and the CTF lab retain their original validity. New operations, analyzers, input
kinds, rule signals, output fields, runtime behavior, or authority require a versioned contract
rather than silent expansion.

## Verification

`tests/test_cryptographic_misuse_analysis.py` covers all seven CAP-002 roles, current signed Range
activation, four exact Surface/input/operation/analyzer mappings, exact Cryptography Worker
profile selection, code-classified digest-derived custody authorization metadata, non-root
network-disabled read-only/no-exec sandbox configuration with code-owned deployment and runtime
identity, zero live/key/crypto/Oracle budgets, exact Scope and deny behavior, preparation
non-authority markers, unavailable runtime behavior, inconclusive Oracle, CTF isolation,
Surface/custody/sandbox/profile/rule/release/target/method/digest substitution, caller-controlled
identity smuggling, resource ceilings, sensitive and operational field injection, authority
escalation, forged model-instance rejection, and boolean/integer coercion.
