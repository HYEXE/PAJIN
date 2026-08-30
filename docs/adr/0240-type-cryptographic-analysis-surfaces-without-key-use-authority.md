# ADR-0240: Type Cryptographic Analysis Surfaces without Key-use Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `cryptography.protocol-key-artifact` and
`pajin.locator.cryptography.protocol-key-artifact.v1` as Cryptography semantic identifiers, but it
does not implement their locator schema. PAJIN also has one fixed CTF single-byte XOR Capability,
an offline Worker pattern, and a host recomputation Oracle. Those assets are intentionally bounded
to one synthetic lab and are not a general identity model or authority for cryptographic analysis.

CRYPTO-001A must represent protocol, key-usage, ciphertext, and configuration knowledge before an
artifact has been resolved, a declaration has been parsed, or an offline analysis Capability has
been authorized. Key material, key handles, plaintext, raw ciphertext, cryptographic parameters,
configuration values, paths, endpoints, credentials, and Tool inputs are private, operational, or
Evidence-owned data. Treating any of them as Surface identity would import artifact access,
credential use, network, analysis, or execution semantics into the representation layer.

The parent model also matters. Making ciphertext a child of key usage would claim that a
particular declared key use produced or protects the artifact before Evidence exists. Allowing
multiple possible parent classes would create more than one canonical lineage for the same
declaration. Nested Pydantic instances require an explicit trust boundary because unchecked
instance-copy updates can otherwise bypass field validation before a digest is computed.

## Decision

Add a content-addressed Cryptography protocol/key/artifact locator registry with four code-owned
classes:

- `cryptography-protocol`: stable protocol namespace and ID plus one sanitized declaration digest;
- `cryptography-key-usage`: one exact protocol parent, bounded declared-use kind, and sanitized
  declaration digest, with no free-form usage coordinate;
- `cryptography-ciphertext`: one exact protocol parent and lowercase artifact SHA-256; and
- `cryptography-configuration`: one exact protocol parent, stable namespace and ID, and sanitized
  declaration digest.

Use protocol as the only root. Embed its complete locator in every child so protocol substitution
changes content identity. Keep key usage, ciphertext, and configuration as siblings. A later
sealed Observation may establish a key-to-ciphertext or configuration-to-operation relation, but
CRYPTO-001A does not encode or infer one.

Do not store any key ID, alias, handle, fingerprint, KMS ARN, PKCS#11 URI, public or private key,
certificate, JWK, wrapped key, password, PIN, seed, credential reference, raw ciphertext, plaintext
or its digest, transcript, nonce, IV, salt, tag, additional authenticated data, configuration
value, environment value, path, URI, endpoint, parser, analyzer, command, Tool, Capability,
Worker, or Scope input.

Treat declaration digests as caller-supplied coordinates over externally retained sanitized
declarations, not as redaction or verification. SHA-256 of low-entropy sensitive data may remain
guessable and correlatable. CRYPTO-001A cannot inspect the preimage and therefore makes no claim
that a supplied declaration digest was safely produced.

Fix `declarationSanitizationVerified=false` on every registered locator and typed Surface. Keep
`secretFree=true` only as a structural statement that the schema has no dedicated raw secret
field, not as proof about arbitrary coordinate semantics or a digest preimage.

Reject mutable aliases, path and URL syntax, wildcards, percent encoding, surrounding whitespace,
control characters, malformed or uppercase digests, unknown fields, true authority markers, and
boolean coercion. At every public parent/child builder and typed-Surface boundary, serialize nested
model instances to alias JSON and validate them again through the exact model or discriminated
union. Reject unmodeled instance state recursively before calculating content identity.

Add an inert `CryptographyProtocolKeyArtifactSurface` that binds one locator to the exact
Cryptography Domain, DOMAIN-002 type-set, and complete registry and starts as
`registered-not-authorized`. Do not add Cryptography locators to the established evidence-bound
discovery `SurfaceLocator` union. Do not change `SurfaceObservation`, `AttackSurface`, CTF,
Artifact, Scope, Graph, Capability, Worker, or runtime wires.

The registry and typed Surface explicitly deny artifact resolution or read, offline analysis,
key-material or credential access, key use, cryptographic operations, protocol negotiation,
Oracle invocation, recomputation, Tool or Worker selection, network access, Scope expansion,
Capability activation, approval satisfaction, Permit issuance, Graph admission, artifact
mutation, Finding authority, runtime-support assertion, and execution authority.

## Consequences

- CRYPTO-001B can bind one exact protocol/key-use/ciphertext/configuration identity to a separately
  reviewed offline read-only analysis Capability without deriving authority from metadata.
- A protocol locator is a caller declaration, not a protocol parser result, supported-version
  statement, connection target, or negotiation transcript.
- A key-usage locator classifies intended use but contains no key identity and permits no
  cryptographic operation.
- A ciphertext locator identifies supplied content by digest but proves no custody, bytes, format,
  size, plaintext, algorithm, or key association.
- A configuration locator carries no values or parameters. Later analysis must bind externally
  retained sanitized input and results through its own Evidence contract.
- The fixed CTF XOR path remains available under its existing contract and gains no broader input,
  Tool, Worker, or runtime claim from this registry.
- Public-boundary revalidation makes malformed nested instances fail closed even when the instance
  originated outside ordinary Pydantic parsing.
- A standalone Surface reference remains an inert pointer. Future Capability boundaries must
  revalidate the complete typed Surface and derive the reference rather than treating reference
  shape as proof or authority.

## Rejected alternatives

### Reuse the CTF inline artifact and Tool contract

Rejected because that contract intentionally permits one small synthetic inline ciphertext and a
fixed finite search. Generalizing its logical URL, recovered key/plaintext output, or Worker
command would expand a lab-specific execution boundary rather than define neutral identities.

### Use key identity, fingerprint, or storage handle in key-usage identity

Rejected because public-key data and fingerprints can be sensitive, aliases and handles are
mutable or resolvable, and KMS or PKCS#11 references resemble credential-use authority. Version 1
stores only the bounded declared-use kind and sanitized declaration digest, with no free-form
usage coordinate.

### Make ciphertext a child of key usage

Rejected because the relationship is a claim that requires Evidence. Protocol-sibling children
preserve exact lineage without turning an unverified key association into identity.

### Include raw ciphertext, plaintext digest, or cryptographic parameters

Rejected because raw values can be sensitive and because a plaintext digest is not reliable
redaction for low-entropy content. A later authorized Artifact/Evidence boundary may retain and
seal required inputs outside the Surface locator.

### Use paths, URIs, endpoints, or Worker identity as a Surface

Rejected because they are mutable storage, network, or deployment coordinates and could be
misread as Scope or execution authority. Artifact custody, egress, and Worker selection remain
separate reviewed boundaries.

### Trust already constructed Pydantic instances

Rejected because unchecked instance copying can bypass normal field validation. Public
Cryptography boundaries establish canonical validation before deriving identity.

## Compatibility and rollback

CRYPTO-001A is additive and requires no migration. Existing discovery locators, `AttackSurface`,
DOMAIN-002 semantics, CTF manifests, Tools and results, Artifact readers, canonical digests, Scope,
Graph, Capability, Worker, and runtime behavior remain unchanged. Rollback removes the new module,
exports, tests, contract, ADR, and consumers. New locator classes, parent relations, key-use kinds,
identity fields, or digest algorithms require an explicit versioned change rather than silent
registry expansion.

## Related documents

- [CRYPTO-001A contract](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0018](0018-bounded-ctf-crypto-artifacts.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
