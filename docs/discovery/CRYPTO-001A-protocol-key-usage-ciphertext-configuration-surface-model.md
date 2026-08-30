# CRYPTO-001A: Protocol, Key-usage, Ciphertext, and Configuration Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/cryptography-protocol-key-artifact-locator/v1alpha1`
  - `pajin.dev/cryptography-protocol-key-artifact-locator-registry/v1alpha1`
  - `pajin.dev/cryptography-protocol-key-artifact-surface/v1alpha1`
- Authority: `src/pajin/discovery/cryptography_surfaces.py`
- Decision: [ADR-0240](../adr/0240-type-cryptographic-analysis-surfaces-without-key-use-authority.md)

## Purpose

CRYPTO-001A implements the locator schema reserved by DOMAIN-002 for
`cryptography.protocol-key-artifact`. It binds the exact DOMAIN-001 Cryptography classification
and DOMAIN-002 Cryptography type-set to four code-owned, content-free locator classes. It also
provides a content-addressed typed Surface whose initial state is
`registered-not-authorized`.

This contract represents caller-supplied protocol identity, sanitized declaration coordinates,
and one ciphertext content digest only. It does not resolve or read an artifact, verify a digest
against bytes, parse or validate a protocol, identify a key, verify declared key use, associate a
key with ciphertext, inspect configuration, analyze cryptographic misuse, access or use key
material or credentials, negotiate a protocol, invoke an Oracle, recompute a result, select a Tool
or Worker, access a network, admit Graph knowledge, or authorize an operation.

## Locator classes and lineage

| Class | Locator kind | Exact fields | Required parent | Meaning |
| --- | --- | --- | --- | --- |
| `protocol` | `cryptography-protocol` | stable protocol namespace and ID, sanitized declaration SHA-256 | none | One caller-declared protocol/profile coordinate; syntax, implementation, support, and negotiation remain unverified |
| `key-usage` | `cryptography-key-usage` | bounded declared-use kind and sanitized declaration SHA-256 | exact protocol | One key-use declaration without a free-form usage coordinate, key identity, reference, fingerprint, or material |
| `ciphertext` | `cryptography-ciphertext` | lowercase ciphertext artifact SHA-256 | exact protocol | One caller-supplied content coordinate; bytes, custody, format, size, provenance, plaintext, and key association remain unverified |
| `configuration` | `cryptography-configuration` | stable namespace and ID, sanitized declaration SHA-256 | exact protocol | One logical configuration declaration without raw values, parameters, path, endpoint, or Secret reference |

The protocol locator is the only root. Key-usage, ciphertext, and configuration locators embed the
complete protocol parent as sibling declarations. Changing the protocol namespace, ID, or
declaration digest therefore changes every child Surface identity.

Ciphertext is deliberately not a child of key usage. CRYPTO-001A has no Evidence that a particular
key protected a particular artifact. Making key usage the parent would turn an unverified
association into identity. A later CRYPTO-001C Observation may establish such a relation under
sealed Evidence without rewriting the A-slice coordinates.

## Canonical, immutable, and private coordinates

Protocol namespaces and IDs and configuration namespaces and IDs are bounded ASCII coordinates.
They are case-folded and require non-empty alphanumeric segments separated by one `.`, `_`, `+`,
or `-`. They reject non-ASCII inputs, empty or repeated separator segments, paths, URLs,
authorities, queries, fragments, percent encoding, wildcards, surrounding whitespace, control
characters, and mutable tokens such as `latest`, `current`, `default`, `auto`, `stable`,
`unknown`, `any`, `local`, and `x`.

The code-owned key-use vocabulary contains encryption, decryption, signature generation and
verification, key agreement and derivation, MAC generation and verification, and key wrapping and
unwrapping. Key usage has no free-form ID in v1, preventing a key alias or handle from being
smuggled through an otherwise allowed coordinate. The enum values classify a declaration only.
They do not assert that the operation is valid, supported, permitted, or performed.

Declaration SHA-256 values are coordinates over an externally retained, canonical, sanitized
declaration. CRYPTO-001A does not receive the declaration and cannot verify its sanitization or
preimage. SHA-256 is not redaction: producers must not derive `declarationSha256` from a private
key, password, PIN, seed, plaintext, low-entropy key alias, secret configuration value, or other
sensitive input. A digest supplied contrary to that rule remains unverified caller data, not proof
that the original was safe or that the declaration was parsed.

Each registered locator and typed Surface therefore fixes
`declarationSanitizationVerified=false`. The structurally content-free schema and
`secretFree=true` registry marker mean that no dedicated raw secret field exists; they do not
inspect arbitrary coordinate semantics or verify a digest preimage.

The ciphertext artifact SHA-256 is also caller-supplied. It binds a content coordinate but proves
neither byte custody nor ciphertext format. There is no inline hex or base64 payload, byte count,
path, URI, nonce, IV, salt, tag, additional authenticated data, transcript, plaintext, plaintext
digest, key association, public key, certificate, JWK, key fingerprint, key alias, KMS ARN,
PKCS#11 URI, credential lease, or Secret reference.

Every locator carries literal-false `rawKeyMaterialEmbedded`, `keyReferenceEmbedded`,
`rawCiphertextEmbedded`, `rawPlaintextEmbedded`, `rawConfigurationEmbedded`,
`rawParameterMaterialEmbedded`, `secretMaterialEmbedded`, `credentialReferenceEmbedded`,
`mutablePathEmbedded`, and `oracleResultEmbedded` markers and forbids extra fields.

## Typed Surface identity

`CryptographyProtocolKeyArtifactSurface` binds:

- the exact Cryptography classification reference;
- the exact `cryptography.protocol-key-artifact` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one revalidated discriminated protocol, key-usage, ciphertext, or configuration locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

Public builders, typed-Surface and `reference()` boundaries dump nested Pydantic model instances to
alias JSON and validate them again. References independently bind ID to digest, locator kind to
class, and the exact registry identity. Unmodeled instance state is rejected recursively. These
checks prevent unchecked instance-copy updates from bypassing parent, coordinate, digest,
registry, reference, or class validation before content identity is derived.

A Surface reference is only an inert content-addressed pointer. Its shape does not resolve or
prove that the complete Surface exists. A later Capability boundary must receive and revalidate
the complete typed Surface, derive its reference, and compare the two exactly instead of granting
authority from a standalone reference.

The typed value is pre-Observation knowledge and is not the established evidence-bound
`AttackSurface`. CRYPTO-001A does not extend the existing discovery `SurfaceLocator` union,
`SurfaceObservation`, or `AttackSurface` wire.

## Threat model and fail-closed behavior

The primary threats are treating a key ID or storage handle as safe metadata, hashing sensitive
low-entropy content and calling it redacted, embedding raw ciphertext or plaintext, converting a
path or endpoint into artifact or network Scope, treating a declared key operation as permission
to use credentials, claiming a key-to-ciphertext relationship without Evidence, substituting a
protocol parent below an otherwise identical child, deriving general support from the fixed CTF
XOR lab, and bypassing nested validation with a forged model instance.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class, order, source model, Domain, graph type-set, parent, digest, or
Surface identity substitution. Models reject malformed or uppercase digests, mutable or
operational coordinates, sensitive or authority fields, true authority markers, and boolean
coercion.

## Trust boundary and non-authority guarantees

CRYPTO-001A adds in-process typed values and exact registry resolution only. It creates no
artifact resolver, file reader, protocol parser, cryptographic analyzer, key store, KMS or HSM
client, credential lease, protocol client, Oracle, sandbox, Tool, Worker, network request, durable
store, publisher, audit event, Graph writer, or execution boundary. In particular, all of these
remain false:

- protocol, key-use, configuration, algorithm, key identity, artifact byte, or misuse
  verification; ciphertext resolution; Evidence sealing; and Graph admission;
- artifact resolution or read, offline analysis, key-material or credential access, key use,
  cryptographic operations, protocol negotiation, Oracle invocation, independent recomputation,
  Tool or Worker selection, network access, artifact mutation, Finding authority, runtime-support
  assertion, and execution;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance.

CRYPTO-001B may separately bind an exact typed Surface to a reviewed offline read-only analysis
Capability and the existing minimum Cryptography Worker boundary. Key material access or use,
decryption, signing, protocol negotiation, network access, and Oracle invocation remain separate
future authority and are not implied by that preparation.

## Existing CTF asset boundary

The existing `pajin.ctf.crypto-single-byte-xor@1.0.0` Capability accepts one bounded synthetic
inline ciphertext and performs a fixed 256-key search in an offline Worker. It is a reusable
classification and regression asset only. CRYPTO-001A does not reuse its inline artifact schema,
`artifact.invalid` policy target, Tool input, recovered key or plaintext result, Worker command,
or host recomputation Oracle. Their existence proves neither this registry's inputs nor general
Cryptography analysis support.

## Audit and benchmark impact

Registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but CRYPTO-001A emits no audit Artifact or Event. It registers no analysis,
Observation, Evidence, independent recomputation, seeded vector Ground Truth, metric,
validation-floor evidence, benchmark Result, Hypothesis, or Finding. CRYPTO-001D owns those later
recomputation and benchmark contracts.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, CTF manifests and Tools, Artifact
readers, Scope, Capability, Worker, Graph, and runtime behavior remain unchanged. There is no data
migration.

Rollback removes the additive module, public exports, contract, ADR, tests, and consumers. New
locator classes, parent relationships, key-use kinds, raw parameter fields, identity fields, or
digest algorithms require a versioned registry/schema change rather than silent membership
expansion.

## Verification

`tests/test_cryptography_protocol_key_artifact_surfaces.py` covers exact Cryptography
Domain/type-set binding, four-class code-owned membership and ordering, content-addressed
resolution, complete protocol parent lineage, canonical stable coordinates, key-use declarations
without key identity, ciphertext digest-only identity, configuration identity without raw values,
all four inert typed Surfaces, legacy discovery-wire compatibility, CTF runtime non-reuse,
registry/Domain/model/digest drift, sensitive-field injection, authority escalation, boolean
coercion, forged reference rejection, and revalidation of forged Pydantic child, parent, registry,
and Surface instances.
