# ADR-0244: Type Forensic Evidence Surfaces without Source-access or Evidence-mutation Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `forensics.immutable-artifact` and
`pajin.locator.forensics.immutable-artifact.v1` as Digital Forensics semantic identifiers, but it
does not implement their locator schema. DOMAIN-004 requires future Forensics Workers to receive
immutable evidence through a provenance-preserving, network-disabled parser boundary, while
DOMAIN-006 reserves independent parser comparison and Forensics metrics. Neither registry grants
source access, implements a parser, or verifies provenance.

FORENSICS-001A must represent disk, memory, log, and generic artifact knowledge before a source
has been resolved, a seal has been verified, bytes have been read, a format has been classified,
or a parser has been authorized. Paths, URIs, object keys, host and device names, case and operator
identities, timestamps, raw evidence, acquisition records, parser outputs, credentials, and
secrets are private or operational data. Including them in Surface identity would also risk
turning a locator into repository, host, device, credential, or execution authority.

The trust root is deliberately unresolved. ADR-0016 makes a PAJIN Run tamper-evident but explicitly
does not authenticate its author or prove external anchoring. `PLAN.md` therefore keeps the first
production immutable evidence source and chain-of-custody trust root as an open decision. The A
slice cannot describe a caller digest as verified immutable evidence or legal custody proof.

The same artifact bytes may appear in more than one sealed Run or provenance record. Treating the
artifact digest alone as identity would erase that distinction. Conversely, a caller class label
does not prove that bytes are a disk image, memory image, log, or any recognized artifact format.
The class and the complete provenance coordinate must both affect identity while remaining
unverified declarations.

## Decision

Add a content-addressed Forensic immutable-artifact locator registry with four code-owned sibling
classes:

- `forensics-disk` for caller-declared disk evidence;
- `forensics-memory` for caller-declared memory evidence;
- `forensics-log` for caller-declared log evidence; and
- `forensics-artifact` for an opaque generic forensic artifact.

Do not encode parent-child extraction relations in v1. Every locator embeds one complete
`ForensicSourceProvenanceCoordinate` containing:

- the code-owned `pajin.dev/run-integrity/v1` source-root kind;
- the caller-supplied source-root SHA-256;
- the caller-supplied source artifact-record SHA-256;
- the caller-supplied provenance-record SHA-256;
- the caller-supplied artifact SHA-256; and
- the caller-supplied artifact byte count in the inclusive range `0..2^63-1`.

The single v1 root kind reuses an existing versioned coordinate vocabulary without claiming that
the referenced Run exists or is trusted. Generic external roots, local files, object stores, and
new trust anchors require an explicit versioned registry/schema change. A later Capability may
resolve an exact retained source through a separate custody contract, but the locator cannot.

All digests are lowercase 64-hex SHA-256 values. They are identity coordinates over external
records, not proofs that the records exist, are canonical, are safe, or have the claimed
preimages. Hashing private or low-entropy content is not redaction. Producers must not derive these
coordinates from a credential, token, key, password, private case identifier, operator name, or
other sensitive low-entropy value.

Fix `immutableSourceRequired=true` and `provenancePreservationRequired=true` on registered locator
definitions. They are requirements for a future runtime, not observations. Keep all of these
state claims false on every typed Surface:

- source seal, authenticity, immutability, and artifact membership verification;
- chain-of-custody verification;
- artifact digest and byte-count verification;
- evidence-class and provenance-sanitization verification;
- source resolution, format verification, parser result availability, provenance preservation,
  Hypothesis creation, Evidence sealing, and Graph admission.

Every locator's provenance coordinate explicitly excludes raw source, disk, memory, log, artifact,
and provenance-record content; mutable paths and source URIs; secret and credential material or
references; and parser output. Models forbid all unknown fields and reject boolean coercion.

At every public provenance, locator, typed-Surface, complete-Surface reference-binding, and
resolver boundary, serialize nested Pydantic instances to alias JSON, validate through the exact
model or discriminated union, compare the canonical value with the input, and reject recursively
unmodeled instance state. This prevents unchecked instance-copy updates or hidden attributes from
influencing a content digest.

Add an inert `ForensicImmutableArtifactSurface` that binds one revalidated locator to the exact
Forensics Domain, DOMAIN-002 type-set, and complete code-owned registry. It starts as
`registered-not-authorized`. Do not add Forensic locators to the established evidence-bound
discovery `SurfaceLocator` union and do not change `SurfaceObservation`, `AttackSurface`,
DOMAIN-002, or existing Run-integrity wires.

The registry and typed Surface explicitly deny source resolution, acquisition, read, mount, and
copy; parser and analyzer selection; credential access or use; lateral movement; evidence
mutation; Tool and Worker selection; network access; Scope expansion; Capability activation;
approval satisfaction; Permit issuance; Graph admission; Finding authority; and execution.

## Consequences

- The same content under a different source root, source artifact record, provenance record, or
  byte-count declaration receives a different Surface identity.
- The same provenance coordinate under a different disk, memory, log, or artifact class receives
  a different Surface identity.
- A class is a caller declaration, not a filename, extension, MIME, parser, filesystem, operating
  system, process, timeline, encoding, format, or corruption result.
- A PAJIN Run root is only a coordinate in this slice. Source existence, current integrity,
  authenticity, external anchoring, artifact membership, custody continuity, acquisition
  completeness, and legal analysis authority remain unverified.
- A standalone Surface reference is an inert opaque digest pointer and carries no class or
  locator-kind claim. Its schema validation proves only pointer shape and the code-owned registry
  identity. `bind_forensic_immutable_artifact_surface_reference` revalidates a supplied complete
  Surface and provenance, derives its reference, and rejects any mismatch. A future Capability
  must use that complete-Surface binding instead of treating reference shape as proof or authority.
- FORENSICS-001B can bind an exact Surface to a separate, reviewed read-only parser preparation
  and DOMAIN-004 minimum Worker profile. It must not turn a discovered credential into use
  authority.
- FORENSICS-001C owns immutable-member resolution, signed execution provenance, no-mutation proof,
  and provenance-preserving Observation/Evidence admission.
- FORENSICS-001D owns deterministic re-parse or independent-parser comparison and DOMAIN-006
  measurements.

## Rejected alternatives

### Use a local path, URI, object key, filename, host, device, or case ID

Rejected because those values are mutable, private, operational, or repository-specific and could
be mistaken for Scope or source-access authority.

### Treat a Run root as authenticity or external anchoring proof

Rejected because ADR-0016 provides local tamper evidence, not author authentication, external
anchoring, or a production chain-of-custody trust root.

### Identify evidence only by artifact digest

Rejected because it discards the enclosing source root, artifact record, and provenance record
that distinguish acquisitions and retained copies.

### Infer disk, memory, or log class from filename, MIME, or extension

Rejected because format classification requires parser evidence. The A-slice class is an
unverified bounded declaration.

### Embed acquisition or custody records

Rejected because raw records may contain identities, timestamps, storage locations, private case
data, or credentials. Only their caller-supplied digests are identity coordinates, and digest
preimages remain unverified and potentially sensitive.

### Hash a credential or secret into Forensic identity

Rejected because hashing is not redaction for low-entropy material and because discovered
credential knowledge cannot become credential-use or lateral-movement authority.

### Reinterpret `ArtifactRef`, `SealedArtifact`, or `AttackSurface`

Rejected because those contracts already carry repository, producer-Run, Evidence, or admitted
discovery semantics. FORENSICS-001A is an additive pre-Observation representation layer.

### Trust already constructed Pydantic instances

Rejected because unchecked model copies and hidden attributes can bypass ordinary validation.
Public Forensic boundaries establish canonical validation before deriving identity.

## Compatibility and rollback

The change is additive and requires no migration. Existing discovery locators,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, `RunIntegritySeal`, `SealedArtifact`,
`ArtifactRef`, Artifact repositories and readers, canonical digests, Scope, Graph, Capability,
Permit, Gateway, Worker, and runtime behavior remain unchanged.

Rollback removes the additive module, exports, tests, contract, ADR, and consumers. It does not
modify or delete a source Run or evidence artifact. New source-root kinds, locator classes,
provenance fields, class semantics, or digest algorithms require a new registry/schema version
rather than silent membership expansion. Future trust-anchor verification must use a separate
attestation boundary; it must not mutate serialized v1 false-state claims.

## Related documents

- [FORENSICS-001A contract](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0016](0016-tamper-evident-run-integrity.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
- [ADR-0211](0211-register-domain-metrics-without-measurement-authority.md)
